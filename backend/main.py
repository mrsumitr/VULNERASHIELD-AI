import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

import detector
import patch_engine
import anomaly_detector
import dataset

app = FastAPI(title="VulneraShield-AI", version="2.0.0")

_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# Load anomaly detector — trained on safe logs only
_safe_logs = [log for log, lbl in zip(*dataset.load()) if lbl == "safe"]
_anomaly_clf, _anomaly_vec = anomaly_detector.load_or_train(_safe_logs)


class LogPayload(BaseModel):
    log_line: str

    @field_validator("log_line")
    @classmethod
    def validate_log_line(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("log_line cannot be empty")
        if len(v) > 5000:
            raise ValueError("log_line exceeds maximum length of 5000 characters")
        return v


def _confidence_level(conf: float) -> str:
    if conf >= 0.75:
        return "high"
    if conf >= 0.55:
        return "medium"
    return "low"


@app.get("/health")
async def health():
    return {"status": "ok", "model_classes": list(detector.classifier.classes_)}


@app.post("/analyze-log")
async def analyze_log(payload: LogPayload):
    label, conf = detector.analyze_payload(payload.log_line)

    # Run anomaly detection in parallel with classification
    flagged, anomaly_score = anomaly_detector.is_anomalous(
        payload.log_line, _anomaly_clf, _anomaly_vec
    )

    base = {
        "threat_confidence": f"{conf:.1%}",
        "confidence_level": _confidence_level(conf),
        "anomaly_flag": flagged,
        "anomaly_score": anomaly_score,
    }

    if label == detector.SAFE:
        # Safe by classifier but anomalous by Isolation Forest → possible zero-day
        if flagged:
            return {
                **base,
                "status": "SUSPICIOUS",
                "threat_label": "unknown",
                "remediation_brief": {
                    "identified_threat": "Anomalous Request (Possible Zero-Day)",
                    "mitigation_strategy": (
                        "This request was classified as safe by the supervised model "
                        "but flagged as statistically anomalous by the Isolation Forest detector. "
                        "It may represent a novel attack pattern not seen during training. "
                        "Review manually and consider adding it to the training set if malicious."
                    ),
                    "recommended_code_fix": (
                        "# Log for manual review\n"
                        "logger.warning('Anomalous request flagged: %s', log_line)\n"
                        "# Block if in high-security mode, else alert and monitor"
                    ),
                },
            }
        return {**base, "status": "SAFE", "threat_label": None, "remediation_brief": None}

    brief = patch_engine.get_remediation_brief(label, payload.log_line)
    return {
        **base,
        "status": "THREAT",
        "threat_label": label,
        "remediation_brief": {
            "identified_threat": brief["threat_type"],
            "mitigation_strategy": brief["solution"],
            "recommended_code_fix": brief["example_fix"],
        },
    }

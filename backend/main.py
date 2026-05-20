import os

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

import detector
import patch_engine

app = FastAPI(title="VulneraShield-AI", version="1.0.0")

_ORIGINS = os.getenv("ALLOWED_ORIGINS", "http://localhost:3000").split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_ORIGINS,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


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

    base = {
        "threat_confidence": f"{conf:.1%}",
        "confidence_level": _confidence_level(conf),
    }

    if label == detector.SAFE:
        return {**base, "status": "SAFE", "threat_label": None, "remediation_brief": None}

    brief = patch_engine.get_remediation_brief(label)
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

from pydantic import BaseModel, EmailStr, Field
from typing import List, Optional, Dict
from enum import Enum

class StatusEnum(str, Enum):
    VALID = "valid"
    INVALID = "invalid"
    RISKY = "risky"
    UNKNOWN = "unknown"

class SourceEnum(str, Enum):
    OMKAR = "omkar"
    PROBE_ENGINE = "probe_engine"
    SYSTEM = "system"
    CACHE = "cache"

class VerifyRequest(BaseModel):
    emails: List[EmailStr] = Field(..., min_items=1, max_items=1000)
    customer_id: str = Field(..., min_length=1, max_length=255)
    use_probe: bool = Field(default=True, description="Enable probe engine for catch-all detection")
    ip_index: Optional[int] = Field(default=None, description="IP pool index to use")

class SignalsModel(BaseModel):
    fake_rejected: Optional[bool] = None
    queue_id: Optional[bool] = None
    timing_ratio: Optional[float] = None
    spf_strict: Optional[bool] = None
    mta: Optional[str] = None

class VerifyResult(BaseModel):
    email: str
    status: StatusEnum
    deliverable: Optional[bool] = None
    confidence: int = Field(..., ge=0, le=100)
    catch_all: Optional[bool] = None
    retry_after: Optional[int] = None
    source: SourceEnum
    reason: Optional[str] = None
    signals: Optional[SignalsModel] = None
    processing_time_ms: Optional[float] = None

class VerifyResponse(BaseModel):
    results: List[VerifyResult]
    total_processed: int
    total_errors: int
    processing_time_ms: float
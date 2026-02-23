from pydantic import BaseModel, Field
from typing import List, Optional

class VerifyRequest(BaseModel):
    emails: List[str] = Field(min_length=1, max_length=500)

class VerifyResult(BaseModel):
    email: str
    mx: List[str] = []
    esp: str = "unknown"
    catch_all: Optional[bool] = None
    deliverable: bool = False
    status: str = "invalid"     # valid|invalid|risky
    role: bool = False
    free: bool = False
    disposable: bool = False
    source: str = "timing"      # omkar|timing
    reason: Optional[str] = None

class VerifyResponse(BaseModel):
    results: List[VerifyResult]

import time
import logging
from fastapi import FastAPI, HTTPException, BackgroundTasks
from fastapi.responses import JSONResponse

from .schemas import VerifyRequest, VerifyResponse, VerifyResult, StatusEnum, SourceEnum
from .core import omkar, probe_engine, scoring
from .protection.breaker import breaker
from .protection.domain_quota import quota_manager
from .protection.reputation import reputation
from .signals.provider import provider_caps

logger = logging.getLogger(__name__)

app = FastAPI(
    title="Bounso Email Verification API",
    version="1.0.0",
    description="Production-grade email verification with catch-all detection",
)

# ============ HEALTH CHECK ============
@app.get("/health")
async def health():
    return {"status": "ok", "version": "1.0.0"}

# ============ MAIN VERIFY ENDPOINT ============
@app.post("/verify", response_model=VerifyResponse)
async def verify_emails(req: VerifyRequest, background_tasks: BackgroundTasks):
    """
    Verify multiple emails with hybrid strategy:
    1. Try Omkar API (fast, cached)
    2. For catch-all results, run probe engine
    3. Apply quotas, reputation, and circuit breaker
    """
    
    start_time = time.time()
    results = []
    errors = 0

    for email in req.emails:
        domain = email.split("@")[1].lower()

        # ===== CIRCUIT BREAKER CHECK =====
        if breaker.is_open(domain):
            retry_after = breaker.get_time_until_retry(domain)
            results.append(
                VerifyResult(
                    email=email,
                    status=StatusEnum.RISKY,
                    confidence=0,
                    catch_all=None,
                    source=SourceEnum.SYSTEM,
                    reason="circuit_breaker_open",
                    retry_after=retry_after,
                )
            )
            errors += 1
            continue

        # ===== QUOTA CHECK =====
        try:
            quota_manager.check_quota(req.customer_id, domain)
        except HTTPException as e:
            results.append(
                VerifyResult(
                    email=email,
                    status=StatusEnum.RISKY,
                    confidence=0,
                    catch_all=None,
                    source=SourceEnum.SYSTEM,
                    reason="quota_exceeded",
                    retry_after=e.detail.get("reset_in"),
                )
            )
            errors += 1
            continue

        # ===== OMKAR FAST PATH =====
        try:
            omkar_result = await omkar.omkar_client.verify(email)
            
            # Not catch-all → return Omkar result
            if not omkar_result.get("catch_all"):
                status = StatusEnum.VALID if omkar_result.get("is_valid") else StatusEnum.INVALID
                confidence = 90 if omkar_result.get("is_valid") else 10
                
                results.append(
                    VerifyResult(
                        email=email,
                        status=status,
                        deliverable=omkar_result.get("is_valid"),
                        confidence=confidence,
                        catch_all=False,
                        source=SourceEnum.OMKAR,
                        reason=omkar_result.get("reason"),
                    )
                )
                breaker.record_success(domain)
                continue
            
        except Exception as e:
            logger.error(f"Omkar error for {email}: {e}")
            breaker.record_failure(domain)

        # ===== PROBE ENGINE FOR CATCH-ALL =====
        try:
            probe_result = await probe_engine.probe_engine.verify(email)
            
            confidence = probe_result["confidence"]
            # Apply provider cap
            confidence = provider_caps.apply_cap(confidence, domain)
            
            status = StatusEnum.VALID if confidence >= 80 else StatusEnum.RISKY
            
            # Build signal response
            signals_raw = probe_result.get("signals", {})
            signals_response = {
                "fake_rejected": signals_raw.get("fake_rejected"),
                "queue_id": signals_raw.get("queue_id", {}).get("detected"),
                "timing_ratio": signals_raw.get("timing_ratio", {}).get("ratio"),
                "spf_strict": signals_raw.get("spf_signal", {}).get("strict"),
                "mta": signals_raw.get("mta", {}).get("mta"),
            }
            
            results.append(
                VerifyResult(
                    email=email,
                    status=status,
                    confidence=confidence,
                    catch_all=True,
                    source=SourceEnum.PROBE_ENGINE,
                    reason="catch_all_probed",
                    signals=signals_response,
                )
            )
            breaker.record_success(domain)
        
        except Exception as e:
            logger.error(f"Probe engine error for {email}: {e}")
            breaker.record_failure(domain)
            
            results.append(
                VerifyResult(
                    email=email,
                    status=StatusEnum.UNKNOWN,
                    confidence=0,
                    catch_all=None,
                    source=SourceEnum.SYSTEM,
                    reason="probe_engine_error",
                )
            )
            errors += 1

    processing_time_ms = (time.time() - start_time) * 1000
    
    return VerifyResponse(
        results=results,
        total_processed=len(req.emails),
        total_errors=errors,
        processing_time_ms=processing_time_ms,
    )

# ============ QUOTA STATUS ============
@app.get("/quota/{customer_id}/{domain}")
async def get_quota(customer_id: str, domain: str):
    """Get current quota usage."""
    return quota_manager.get_usage(customer_id, domain)

# ============ DOMAIN REPUTATION ============
@app.get("/reputation/{domain}")
async def get_reputation(domain: str):
    """Get domain reputation stats."""
    return reputation.get_reputation(domain)

# ============ ERROR HANDLERS ============
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc):
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail},
    )
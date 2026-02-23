from fastapi import FastAPI
from concurrent.futures import ThreadPoolExecutor, as_completed

from .schemas import VerifyRequest, VerifyResponse, VerifyResult
from .classifiers import normalize_email, is_valid_syntax, split_email, is_free_domain, is_disposable_domain, is_role_email
from .dns_smtp import resolve_mx, detect_catch_all, timing_verify
from .esp import detect_esp_from_mx
from .omkar_client import omkar_verify
from .config import MAX_WORKERS

app = FastAPI(title="Bousno Verifier API", version="1.0.0")

def verify_one(email_raw: str) -> VerifyResult:
    email = normalize_email(email_raw)

    res = VerifyResult(email=email)

    if not is_valid_syntax(email):
        res.reason = "bad_syntax"
        res.status = "invalid"
        res.deliverable = False
        return res

    local, domain = split_email(email)
    res.role = is_role_email(local)
    res.free = is_free_domain(domain)
    res.disposable = is_disposable_domain(domain)

    # MX
    try:
        mxs = resolve_mx(domain)
    except:
        mxs = []
    res.mx = mxs

    if not mxs:
        res.reason = "no_mx"
        res.status = "invalid"
        res.deliverable = False
        return res

    res.esp = detect_esp_from_mx(mxs)
    mx_host = mxs[0]

    # Catch-all
    ca = detect_catch_all(domain, mx_host)
    # None = inconclusive; treat as catch-all? up to you; I recommend treat as None => go Omkar (cheaper)
    res.catch_all = bool(ca) if ca is not None else False

    # Route
    if ca is True:
        status, score, reason, deliverable = timing_verify(email, mx_host)
        res.source = "timing"
        res.status = status
        res.deliverable = deliverable
        res.reason = reason
        return res

    # Not catch-all (or inconclusive) => Omkar
    try:
        data = omkar_verify(email)
        # Omkar sample: {'email':..., 'is_valid': False, 'status': 'catch-all', 'is_free_email': False, ...}
        res.source = "omkar"
        # Map to unified
        is_valid = bool(data.get("is_valid"))
        omkar_status = (data.get("status") or "").lower()

        if is_valid:
            res.status = "valid"
            res.deliverable = True
            res.reason = "omkar_valid"
        else:
            # if Omkar says catch-all -> still mark catch_all true
            if "catch" in omkar_status:
                res.catch_all = True
                # If catch-all but Omkar didn't help, treat risky by default
                res.status = "risky"
                res.deliverable = False
                res.reason = "omkar_catchall"
            else:
                res.status = "invalid"
                res.deliverable = False
                res.reason = "omkar_invalid"

        # Optional override free based on Omkar
        if "is_free_email" in data:
            res.free = bool(data["is_free_email"])

    except Exception:
        # If Omkar fails, fall back to timing to avoid total failure
        status, score, reason, deliverable = timing_verify(email, mx_host)
        res.source = "timing"
        res.status = status
        res.deliverable = deliverable
        res.reason = f"omkar_failed_{reason}"

    return res

@app.post("/verify", response_model=VerifyResponse)
def verify(req: VerifyRequest):
    results = []
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as ex:
        futs = [ex.submit(verify_one, e) for e in req.emails]
        for f in as_completed(futs):
            results.append(f.result())
    # Preserve input order (optional): easiest is to map by email
    # But duplicates can exist; for now keep as completed.
    return VerifyResponse(results=results)

@app.get("/health")
def health():
    return {"ok": True}

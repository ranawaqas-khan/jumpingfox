import os
from typing import List

# ============ OMKAR API ============
OMKAR_API_KEY = os.getenv("OMKAR_API_KEY", "your-api-key-here")
OMKAR_URL = "https://email-verification-api.omkar.cloud/verify"
OMKAR_TIMEOUT = 10

# ============ REDIS ============
REDIS_HOST = os.getenv("REDIS_HOST", "localhost")
REDIS_PORT = int(os.getenv("REDIS_PORT", "6379"))
REDIS_DB = int(os.getenv("REDIS_DB", "0"))

# ============ RATE LIMITING ============
MAX_DOMAIN_CONCURRENCY = 2
DOMAIN_COOLDOWN = 300  # seconds
CIRCUIT_BREAKER_THRESHOLD = 3
CIRCUIT_BREAKER_COOLDOWN = 300

# ============ IP POOL ============
IP_POOL: List[str] = (
    os.getenv("IP_POOL", "").split(",") 
    if os.getenv("IP_POOL") 
    else []
)

# ============ SMTP ============
SMTP_TIMEOUT = 15
SMTP_PORT = 25
SMTP_SENDER = "check@bounso.com"
SMTP_EHLO_NAME = "bounso.com"

# ============ PROBE ENGINE ============
FAKE_EMAIL_LENGTH = 12
CONFIDENCE_THRESHOLD = 80
CATCH_ALL_CONFIDENCE_CAP = 85
PROVIDER_MAX_CONFIDENCE = {
    "default": 85,
    "gmail.com": 75,
    "outlook.com": 70,
}

# ============ QUOTAS ============
QUOTA_LIMITS = {
    "default": {
        "per_customer_hour": 500,
        "global_hour": 5000,
    },
    "high_tier": {
        "per_customer_hour": 5000,
        "global_hour": 50000,
    },
}
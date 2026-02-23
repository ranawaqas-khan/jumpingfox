import os

OMKAR_URL = os.getenv("OMKAR_URL", "https://email-verification-api.omkar.cloud/verify")
OMKAR_API_KEY = os.getenv("OMKAR_API_KEY", "ok_8b8b6ed9ed92abf6965966939cfee3d9")

DNS_TIMEOUT = float(os.getenv("DNS_TIMEOUT", "3"))
DNS_LIFETIME = float(os.getenv("DNS_LIFETIME", "5"))
SMTP_TIMEOUT = float(os.getenv("SMTP_TIMEOUT", "6"))

HELO_DOMAIN = os.getenv("HELO_DOMAIN", "leadstracker.xyz")
MAIL_FROM = os.getenv("MAIL_FROM", "verify@leadstracker.xyz")

MAX_WORKERS = int(os.getenv("MAX_WORKERS", "24"))
PROBE_PAUSE = float(os.getenv("PROBE_PAUSE", "0.08"))

MX_CACHE_TTL = int(os.getenv("MX_CACHE_TTL", "3600"))
DOMAIN_FLAG_TTL = int(os.getenv("DOMAIN_FLAG_TTL", "21600"))  # 6 hours

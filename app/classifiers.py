import re
from pathlib import Path

EMAIL_REGEX = re.compile(r"^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}$")

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

FREE_DOMAINS = set((DATA_DIR / "free_domains.txt").read_text().splitlines())
DISPOSABLE_DOMAINS = set((DATA_DIR / "disposable_domains.txt").read_text().splitlines())
ROLE_PREFIXES = set((DATA_DIR / "role_prefixes.txt").read_text().splitlines())

def normalize_email(e: str) -> str:
    return (e or "").strip().lower()

def is_valid_syntax(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email or ""))

def split_email(email: str):
    local, domain = email.split("@", 1)
    return local, domain

def is_free_domain(domain: str) -> bool:
    return domain.lower() in FREE_DOMAINS

def is_disposable_domain(domain: str) -> bool:
    return domain.lower() in DISPOSABLE_DOMAINS

def is_role_email(local: str) -> bool:
    # "sales", "info", "admin" etc
    pure = local.split("+", 1)[0].lower()
    return pure in ROLE_PREFIXES

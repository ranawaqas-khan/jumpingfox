import requests
from .config import OMKAR_URL, OMKAR_API_KEY

def omkar_verify(email: str) -> dict:
    headers = {"API-Key": OMKAR_API_KEY}
    r = requests.get(OMKAR_URL, headers=headers, params={"email": email}, timeout=12)
    r.raise_for_status()
    return r.json()

import httpx
import logging
from typing import Dict, Optional
from ..config import OMKAR_API_KEY, OMKAR_URL, OMKAR_TIMEOUT

logger = logging.getLogger(__name__)

class OmkarClient:
    """
    Omkar email verification API client.
    Handles fast-path verification before probe engine.
    """
    
    def __init__(self):
        self.api_key = OMKAR_API_KEY
        self.url = OMKAR_URL
        self.timeout = OMKAR_TIMEOUT
        self.session = None

    async def verify(self, email: str) -> Dict:
        """
        Verify email via Omkar API.
        Returns dict with status, is_valid, score, catch_all detection.
        """
        try:
            async with httpx.AsyncClient(timeout=self.timeout) as client:
                response = await client.get(
                    self.url,
                    headers={"API-Key": self.api_key},
                    params={"email": email}
                )
            
            if response.status_code != 200:
                logger.warning(f"Omkar API error for {email}: {response.status_code}")
                return {
                    "is_valid": None,
                    "status": "api_error",
                    "score": 0,
                }
            
            data = response.json()
            
            return {
                "is_valid": data.get("is_valid"),
                "status": data.get("status"),
                "score": data.get("score", 0),
                "catch_all": data.get("catch_all", False),
                "reason": data.get("reason"),
            }
        
        except Exception as e:
            logger.error(f"Omkar verification error: {e}")
            return {
                "is_valid": None,
                "status": "exception",
                "score": 0,
            }

omkar_client = OmkarClient()
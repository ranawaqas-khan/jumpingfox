import redis
from fastapi import HTTPException
from ..config import (
    REDIS_HOST, REDIS_PORT, REDIS_DB, QUOTA_LIMITS
)
from typing import Dict

class QuotaManager:
    """
    Redis-backed quota system for per-customer and global domain limits.
    """
    
    def __init__(self):
        self.r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True
        )

    def get_limits(self, tier: str = "default") -> Dict:
        """Get quota limits for tier."""
        return QUOTA_LIMITS.get(tier, QUOTA_LIMITS["default"])

    def check_quota(self, customer_id: str, domain: str, tier: str = "default") -> None:
        """
        Check customer and global quotas.
        Raises HTTPException 429 if exceeded.
        """
        limits = self.get_limits(tier)

        # ===== CUSTOMER QUOTA =====
        cust_key = f"quota:cust:{customer_id}:{domain}"
        cust_count = self.r.incr(cust_key)
        
        if cust_count == 1:
            self.r.expire(cust_key, 3600)
        
        if cust_count > limits["per_customer_hour"]:
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Customer domain quota exceeded",
                    "limit": limits["per_customer_hour"],
                    "used": cust_count,
                    "reset_in": self.r.ttl(cust_key)
                }
            )

        # ===== GLOBAL QUOTA =====
        glob_key = f"quota:global:{domain}"
        glob_count = self.r.incr(glob_key)
        
        if glob_count == 1:
            self.r.expire(glob_key, 3600)
        
        if glob_count > limits["global_hour"]:
            raise HTTPException(
                status_code=429,
                detail={
                    "error": "Global domain quota exceeded",
                    "limit": limits["global_hour"],
                    "used": glob_count,
                    "reset_in": self.r.ttl(glob_key)
                }
            )

    def get_usage(self, customer_id: str, domain: str) -> Dict:
        """Get current usage stats."""
        cust_key = f"quota:cust:{customer_id}:{domain}"
        glob_key = f"quota:global:{domain}"
        
        return {
            "customer_used": int(self.r.get(cust_key) or 0),
            "customer_limit": self.get_limits()["per_customer_hour"],
            "global_used": int(self.r.get(glob_key) or 0),
            "global_limit": self.get_limits()["global_hour"],
            "customer_reset_in": self.r.ttl(cust_key),
            "global_reset_in": self.r.ttl(glob_key),
        }

quota_manager = QuotaManager()
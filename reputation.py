import redis
from ..config import REDIS_HOST, REDIS_PORT, REDIS_DB
from typing import Dict

class ReputationMonitor:
    """
    Tracks domain reputation and degrades confidence for suspicious domains.
    """
    
    def __init__(self):
        self.r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True
        )

    def record_false_positive(self, domain: str) -> None:
        """Record a false positive (marked valid but bounced later)."""
        key = f"reputation:fp:{domain}"
        count = self.r.incr(key)
        self.r.expire(key, 86400 * 7)  # 7 days
        
        if count >= 10:
            self.degrade_domain(domain, "high_false_positive_rate")

    def record_bounce(self, domain: str) -> None:
        """Record a bounce."""
        key = f"reputation:bounces:{domain}"
        self.r.incr(key)
        self.r.expire(key, 3600)

    def degrade_domain(self, domain: str, reason: str) -> None:
        """Mark domain as degraded."""
        key = f"reputation:degraded:{domain}"
        self.r.setex(key, 3600, reason)

    def get_confidence_cap(self, domain: str) -> int:
        """
        Get max confidence for domain based on reputation.
        Returns 0-100.
        """
        if self.is_degraded(domain):
            return 50
        
        bounces = int(self.r.get(f"reputation:bounces:{domain}") or 0)
        
        if bounces > 20:
            return 70
        elif bounces > 10:
            return 80
        
        return 100

    def is_degraded(self, domain: str) -> bool:
        """Check if domain reputation is degraded."""
        key = f"reputation:degraded:{domain}"
        return self.r.exists(key) > 0

    def get_reputation(self, domain: str) -> Dict:
        """Get full reputation data."""
        return {
            "domain": domain,
            "degraded": self.is_degraded(domain),
            "bounces": int(self.r.get(f"reputation:bounces:{domain}") or 0),
            "false_positives": int(self.r.get(f"reputation:fp:{domain}") or 0),
            "confidence_cap": self.get_confidence_cap(domain),
        }

reputation = ReputationMonitor()
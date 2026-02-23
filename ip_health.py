import redis
from ..config import REDIS_HOST, REDIS_PORT, REDIS_DB
from typing import Dict, Optional

class IPHealthMonitor:
    """
    Tracks IP reputation and blocks based on bounce/blacklist status.
    """
    
    def __init__(self):
        self.r = redis.Redis(
            host=REDIS_HOST,
            port=REDIS_PORT,
            db=REDIS_DB,
            decode_responses=True
        )

    def mark_bounce(self, ip: str, domain: str) -> None:
        """Record a bounce from this IP to domain."""
        key = f"ip:bounces:{ip}:{domain}"
        count = self.r.incr(key)
        self.r.expire(key, 3600)
        
        if count >= 5:
            self.block_ip(ip, domain, "too_many_bounces")

    def mark_blacklist(self, ip: str, domain: str) -> None:
        """Record blacklist hit."""
        self.block_ip(ip, domain, "blacklist")

    def block_ip(self, ip: str, domain: str, reason: str) -> None:
        """Block IP from accessing domain."""
        key = f"ip:blocked:{ip}:{domain}"
        self.r.setex(key, 3600, reason)

    def is_blocked(self, ip: str, domain: str) -> bool:
        """Check if IP is blocked."""
        key = f"ip:blocked:{ip}:{domain}"
        return self.r.exists(key) > 0

    def get_health(self, ip: str, domain: str) -> Dict:
        """Get health status of IP."""
        bounces = int(self.r.get(f"ip:bounces:{ip}:{domain}") or 0)
        blocked = self.is_blocked(ip, domain)
        
        return {
            "ip": ip,
            "domain": domain,
            "bounces": bounces,
            "blocked": blocked,
            "health_score": max(0, 100 - (bounces * 15))
        }

ip_health = IPHealthMonitor()
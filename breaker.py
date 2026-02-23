from collections import defaultdict
import time
from threading import Lock
from typing import Dict, Set

class CircuitBreaker:
    """
    Per-domain circuit breaker with exponential backoff.
    Prevents cascade failures from repeated SMTP errors.
    """
    
    def __init__(self, threshold: int = 3, cooldown: int = 300):
        self.failures: Dict[str, int] = defaultdict(int)
        self.open_until: Dict[str, float] = {}
        self.lock = Lock()
        self.threshold = threshold
        self.cooldown = cooldown
        self.failure_timestamps: Dict[str, list] = defaultdict(list)

    def is_open(self, domain: str) -> bool:
        """Check if circuit is open for domain."""
        with self.lock:
            if domain in self.open_until:
                if time.time() < self.open_until[domain]:
                    return True
                # Reset circuit after cooldown expires
                del self.open_until[domain]
                self.failures[domain] = 0
                self.failure_timestamps[domain] = []
        return False

    def record_failure(self, domain: str) -> None:
        """Record a failure and potentially open circuit."""
        with self.lock:
            self.failures[domain] += 1
            self.failure_timestamps[domain].append(time.time())
            
            # Keep only last 60 seconds of failures for rolling window
            cutoff = time.time() - 60
            self.failure_timestamps[domain] = [
                ts for ts in self.failure_timestamps[domain] 
                if ts > cutoff
            ]
            
            if self.failures[domain] >= self.threshold:
                self.open_until[domain] = time.time() + self.cooldown

    def record_success(self, domain: str) -> None:
        """Reset failure counter on success."""
        with self.lock:
            self.failures[domain] = 0
            self.failure_timestamps[domain] = []

    def get_time_until_retry(self, domain: str) -> int:
        """Get seconds until domain is available."""
        with self.lock:
            if domain in self.open_until:
                remaining = self.open_until[domain] - time.time()
                return max(0, int(remaining) + 1)
        return 0

breaker = CircuitBreaker()
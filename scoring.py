from typing import Dict
from ..signals.provider import provider_caps
from ..protection.reputation import reputation

class ScoringEngine:
    """
    Computes final confidence score from all signals.
    Weighs timing, queue ID, DNS, and provider characteristics.
    """
    
    def score(self, signals: Dict, domain: str) -> int:
        """
        Compute confidence (0-100) from signals.
        
        Scoring logic:
        - Start at 50
        - Fake address rejected? +45 (95 total) — strong indicator
        - Queue ID detected? +20 — indicates legitimate server
        - Timing ratio > 1.4? +15 — real takes longer to verify
        - SPF strict (-all)? +5 — domain controls email
        - Cap by provider (Gmail max 70, etc.)
        - Cap by domain reputation (false positive rate, bounces)
        """
        score = 50
        
        # ===== CATCH-ALL DETECTION (Fake rejected) =====
        if signals.get("fake_rejected"):
            score = 95
            return self._apply_caps(score, domain)
        
        # ===== QUEUE ID =====
        if signals.get("queue_id", {}).get("detected"):
            score += 20
        
        # ===== TIMING RATIO =====
        ratio = signals.get("timing_ratio", {}).get("ratio", 1.0)
        if ratio > 1.4:
            score += 15
        elif ratio < 0.8:
            score -= 10  # Penalize catch-all-like timing
        
        # ===== SPF SIGNAL =====
        if signals.get("spf_signal", {}).get("strict"):
            score += 5
        
        # ===== APPLY CAPS =====
        return self._apply_caps(score, domain)

    def _apply_caps(self, score: int, domain: str) -> int:
        """Apply provider and reputation caps."""
        # Provider cap
        score = provider_caps.apply_cap(score, domain)
        
        # Reputation cap
        rep = reputation.get_reputation(domain)
        score = min(score, rep["confidence_cap"])
        
        return max(0, min(100, score))

scorer = ScoringEngine()
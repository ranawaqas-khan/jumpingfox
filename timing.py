from typing import List, Optional
from statistics import mean, stdev

class TimingAnalyzer:
    """
    Analyzes SMTP response timing to detect catch-all vs bounced email.
    Catch-all servers respond consistently; bounce servers respond to valid faster.
    """
    
    def __init__(self, variance_threshold: float = 0.4):
        self.variance_threshold = variance_threshold

    def compute_ratio(self, real_ms: float, fake_times: List[float]) -> float:
        """
        Compute timing ratio: real_response_time / avg_fake_response_time.
        Ratio > 1.4 suggests real address (takes longer to verify).
        """
        if not fake_times or all(t == 0 for t in fake_times):
            return 1.0
        
        fake_avg = mean([t for t in fake_times if t > 0])
        
        if fake_avg == 0:
            return 1.0
        
        return real_ms / fake_avg

    def analyze_pattern(self, real_ms: float, fake_times: List[float]) -> dict:
        """
        Analyze timing pattern:
        - If ratio > 1.4: real address (valid) — server spends more time checking
        - If ratio < 0.8: likely catch-all — fake rejected same as real
        - Else: ambiguous
        """
        if not fake_times:
            return {"status": "insufficient_data", "ratio": 1.0, "confidence": 0}
        
        ratio = self.compute_ratio(real_ms, fake_times)
        
        if len(fake_times) > 1:
            std = stdev(fake_times)
            variance = std / mean(fake_times) if mean(fake_times) > 0 else 0
        else:
            variance = 0

        if ratio > 1.4:
            return {
                "status": "valid",
                "ratio": ratio,
                "confidence": min(90, 60 + (ratio - 1.4) * 50),
                "variance": variance,
            }
        elif ratio < 0.8:
            return {
                "status": "catch_all",
                "ratio": ratio,
                "confidence": min(80, 50 + (0.8 - ratio) * 50),
                "variance": variance,
            }
        else:
            return {
                "status": "ambiguous",
                "ratio": ratio,
                "confidence": 40,
                "variance": variance,
            }

timing_analyzer = TimingAnalyzer()
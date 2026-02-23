from typing import Dict

class ProviderConfidenceCaps:
    """
    Provider-specific confidence caps.
    Free tier emails (Gmail, etc.) are harder to verify accurately.
    """
    
    CAPS = {
        # Catch-all heavy, difficult to verify
        "gmail.com": 70,
        "googlemail.com": 70,
        "yahoo.com": 65,
        "aol.com": 65,
        "outlook.com": 75,
        "hotmail.com": 75,
        "live.com": 75,
        
        # Corporate - more verifiable
        "microsoft.com": 85,
        "apple.com": 85,
        
        # Default for unknown
        "default": 85,
    }

    def get_cap(self, domain: str) -> int:
        """Get confidence cap for domain."""
        domain_lower = domain.lower()
        return self.CAPS.get(domain_lower, self.CAPS["default"])

    def apply_cap(self, confidence: int, domain: str) -> int:
        """Apply provider cap to confidence score."""
        cap = self.get_cap(domain)
        return min(confidence, cap)

provider_caps = ProviderConfidenceCaps()
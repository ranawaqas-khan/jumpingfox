from typing import Dict, Optional

class BannerFingerprinter:
    """
    Parses SMTP banner to detect MTA type and capabilities.
    Different MTAs have different timing and queue ID characteristics.
    """
    
    MTA_PATTERNS = {
        "postfix": {
            "keywords": ["postfix"],
            "supports_timing": True,
            "supports_queue_id": True,
            "timing_variance": 0.3,
        },
        "exchange": {
            "keywords": ["exchange", "microsoft"],
            "supports_timing": False,
            "supports_queue_id": True,
            "timing_variance": 0.1,
        },
        "mimecast": {
            "keywords": ["mimecast"],
            "supports_timing": False,
            "supports_queue_id": False,
            "timing_variance": 0.0,
        },
        "sendgrid": {
            "keywords": ["sendgrid"],
            "supports_timing": False,
            "supports_queue_id": True,
            "timing_variance": 0.0,
        },
        "google": {
            "keywords": ["google", "aspmx"],
            "supports_timing": True,
            "supports_queue_id": False,
            "timing_variance": 0.2,
        },
    }

    def parse(self, banner: str) -> Dict:
        """Parse SMTP banner and return MTA characteristics."""
        if not banner:
            return self._unknown_mta()
        
        banner_lower = banner.lower()
        
        for mta, config in self.MTA_PATTERNS.items():
            if any(kw in banner_lower for kw in config["keywords"]):
                return {
                    "mta": mta,
                    "supports_timing": config["supports_timing"],
                    "supports_queue_id": config["supports_queue_id"],
                    "timing_variance": config["timing_variance"],
                    "banner": banner,
                }
        
        return self._unknown_mta()

    def _unknown_mta(self) -> Dict:
        """Default for unknown MTA."""
        return {
            "mta": "unknown",
            "supports_timing": True,
            "supports_queue_id": True,
            "timing_variance": 0.4,
            "banner": None,
        }

fingerprinter = BannerFingerprinter()
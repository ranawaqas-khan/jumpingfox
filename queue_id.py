import re
from typing import Optional, Dict

class QueueIDDetector:
    """
    Detects queue IDs in SMTP responses.
    Queue IDs indicate legitimate server queuing, suggesting valid address.
    """
    
    PATTERNS = [
        # Postfix: 10-14 hex chars
        (r'[0-9A-F]{10,14}', "postfix_hex"),
        # Sendmail/Generic: 14+ alphanumeric
        (r'[A-Za-z0-9]{14,}', "generic_id"),
        # With slashes (some servers)
        (r'[A-Za-z0-9]{8,}/[A-Za-z0-9]{8,}', "path_id"),
        # UUID format
        (r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', "uuid"),
    ]

    def detect(self, message: str) -> Dict[str, bool]:
        """
        Detect queue ID in message.
        Returns {detected: bool, pattern: str}.
        """
        if not message:
            return {"detected": False, "pattern": None, "value": None}
        
        message_str = str(message).strip()
        
        for pattern, pattern_name in self.PATTERNS:
            match = re.search(pattern, message_str)
            if match:
                return {
                    "detected": True,
                    "pattern": pattern_name,
                    "value": match.group(0),
                }
        
        return {"detected": False, "pattern": None, "value": None}

detector = QueueIDDetector()
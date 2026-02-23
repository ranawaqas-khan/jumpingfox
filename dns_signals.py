import dns.resolver
import logging
from typing import Dict, Optional

logger = logging.getLogger(__name__)

class DNSSignalAnalyzer:
    """
    Analyzes DNS signals (SPF, DMARC, MX) for domain reputation.
    """

    def get_spf(self, domain: str) -> Dict:
        """
        Check SPF record for strictness.
        -all (fail all) vs ~all (softfail) indicates domain controls email.
        """
        try:
            records = dns.resolver.resolve(domain, "TXT")
            for record in records:
                text = record.to_text()
                if "v=spf1" in text:
                    return {
                        "present": True,
                        "strict": "-all" in text,
                        "text": text.strip('"'),
                    }
        except Exception as e:
            logger.debug(f"SPF lookup failed for {domain}: {e}")
        
        return {"present": False, "strict": False, "text": None}

    def get_dmarc(self, domain: str) -> Dict:
        """Check DMARC record."""
        try:
            records = dns.resolver.resolve(f"_dmarc.{domain}", "TXT")
            for record in records:
                text = record.to_text()
                return {
                    "present": True,
                    "text": text.strip('"'),
                }
        except Exception:
            pass
        
        return {"present": False, "text": None}

    def get_mx(self, domain: str) -> Dict:
        """Get MX record info."""
        try:
            records = dns.resolver.resolve(domain, "MX")
            mx_hosts = [
                {
                    "priority": int(r.preference),
                    "host": r.exchange.to_text().rstrip("."),
                }
                for r in records
            ]
            return {
                "present": True,
                "count": len(mx_hosts),
                "hosts": mx_hosts,
            }
        except Exception as e:
            logger.debug(f"MX lookup failed for {domain}: {e}")
        
        return {"present": False, "count": 0, "hosts": []}

    def analyze(self, domain: str) -> Dict:
        """Full DNS signal analysis."""
        spf = self.get_spf(domain)
        dmarc = self.get_dmarc(domain)
        mx = self.get_mx(domain)
        
        return {
            "domain": domain,
            "spf": spf,
            "dmarc": dmarc,
            "mx": mx,
            "reputation_score": self._score(spf, dmarc, mx),
        }

    def _score(self, spf: Dict, dmarc: Dict, mx: Dict) -> int:
        """Score domain based on DNS records."""
        score = 50
        
        if spf.get("present"):
            score += 15
        if spf.get("strict"):
            score += 10
        if dmarc.get("present"):
            score += 15
        if mx.get("present") and mx.get("count") > 1:
            score += 10
        
        return min(score, 100)

dns_analyzer = DNSSignalAnalyzer()
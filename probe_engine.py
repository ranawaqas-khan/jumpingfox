import asyncio
import random
import string
import aiosmtplib
import dns.resolver
import logging
from typing import Dict, List, Optional
from ..config import (
    SMTP_TIMEOUT, SMTP_PORT, SMTP_SENDER, SMTP_EHLO_NAME, FAKE_EMAIL_LENGTH
)
from ..signals.timing import timing_analyzer
from ..signals.queue_id import detector
from ..signals.dns_signals import dns_analyzer
from ..signals.banner import fingerprinter
from ..core.scoring import scorer

logger = logging.getLogger(__name__)

class ProbeEngine:
    """
    Async SMTP probe engine for catch-all detection.
    Tests real email against fake addresses to detect catch-all patterns.
    """

    async def verify(self, email: str, ip: Optional[str] = None) -> Dict:
        """
        Full probe verification for catch-all detection.
        Returns status, confidence, and detailed signals.
        """
        domain = email.split("@")[1]
        
        try:
            # Get MX records
            mx_host = await self._get_mx_host(domain)
            if not mx_host:
                return {
                    "status": "invalid",
                    "confidence": 0,
                    "reason": "no_mx_record",
                    "signals": None,
                }
            
            # Connect and test
            signals = await self._test_address(email, mx_host, domain)
            
            if signals is None:
                return {
                    "status": "risky",
                    "confidence": 20,
                    "reason": "smtp_connection_failed",
                    "signals": None,
                }
            
            # Score results
            confidence = scorer.score(signals, domain)
            status = "valid" if confidence >= 80 else "risky"
            
            return {
                "status": status,
                "confidence": confidence,
                "reason": "probe_analysis",
                "signals": signals,
            }
        
        except Exception as e:
            logger.error(f"Probe engine error for {email}: {e}")
            return {
                "status": "unknown",
                "confidence": 0,
                "reason": str(e),
                "signals": None,
            }

    async def _get_mx_host(self, domain: str) -> Optional[str]:
        """Resolve domain to primary MX host."""
        try:
            mx = dns.resolver.resolve(domain, "MX")
            primary = sorted(mx, key=lambda x: x.preference)[0]
            return primary.exchange.to_text().rstrip(".")
        except Exception as e:
            logger.warning(f"MX lookup failed for {domain}: {e}")
            return None

    async def _test_address(self, email: str, mx_host: str, domain: str) -> Optional[Dict]:
        """
        Core SMTP testing:
        1. Send RCPT TO for real email
        2. Send RCPT TO for fake emails
        3. Compare timing and responses
        4. Detect catch-all vs valid
        """
        try:
            async with aiosmtplib.SMTP(
                hostname=mx_host,
                port=SMTP_PORT,
                timeout=SMTP_TIMEOUT,
            ) as smtp:
                # Connect
                await smtp.connect()
                banner = smtp.server_name or ""
                mta_info = fingerprinter.parse(banner)
                
                await smtp.ehlo(SMTP_EHLO_NAME)
                await smtp.mail(SMTP_SENDER)
                
                # ===== TEST REAL ADDRESS =====
                start_real = asyncio.get_event_loop().time()
                real_code, real_msg = await smtp.rcpt(email)
                real_time_ms = (asyncio.get_event_loop().time() - start_real) * 1000
                
                await smtp.rset()
                await smtp.mail(SMTP_SENDER)
                
                # ===== TEST FAKE ADDRESSES =====
                fake_times = []
                fake_rejected = None
                
                for i in range(2):
                    fake_email = self._generate_fake(domain)
                    
                    start_fake = asyncio.get_event_loop().time()
                    fake_code, fake_msg = await smtp.rcpt(fake_email)
                    fake_time_ms = (asyncio.get_event_loop().time() - start_fake) * 1000
                    
                    fake_times.append(fake_time_ms)
                    
                    if i == 0 and fake_code != 250:
                        fake_rejected = True
                    
                    if i < 1:
                        await smtp.rset()
                        await smtp.mail(SMTP_SENDER)
                
                # ===== BUILD SIGNALS =====
                signals = {
                    "mta": mta_info,
                    "fake_rejected": fake_rejected,
                    "queue_id": detector.detect(str(real_msg)),
                    "timing_ratio": timing_analyzer.analyze_pattern(real_time_ms, fake_times),
                    "spf_signal": dns_analyzer.get_spf(domain),
                    "real_code": real_code,
                    "fake_codes": [250 if fake_rejected else 550],  # Simplified
                    "real_time_ms": real_time_ms,
                    "fake_times_ms": fake_times,
                }
                
                return signals
        
        except asyncio.TimeoutError:
            logger.warning(f"SMTP timeout for {mx_host}")
            return None
        except Exception as e:
            logger.error(f"SMTP test error: {e}")
            return None

    def _generate_fake(self, domain: str) -> str:
        """Generate random fake email for testing."""
        random_part = ''.join(
            random.choices(string.ascii_lowercase + string.digits, k=FAKE_EMAIL_LENGTH)
        )
        return f"{random_part}@{domain}"

probe_engine = ProbeEngine()
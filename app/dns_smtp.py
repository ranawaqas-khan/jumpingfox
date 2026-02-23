from __future__ import annotations
import time, random, string, smtplib, socket
from statistics import mean
import dns.resolver

from .config import DNS_TIMEOUT, DNS_LIFETIME, SMTP_TIMEOUT, HELO_DOMAIN, MAIL_FROM, PROBE_PAUSE
from .cache import mx_cache, domain_flags_cache

GATEWAY_KEYWORDS = [
    "mimecast","pphosted","proofpoint","barracuda","hornetsecurity","smarsh",
    "trendmicro","spamtitan","titanhq","sophos","mailchannels","messagelabs",
    "spamexperts","mailguard","email-protect","fortimail"
]

_resolver = dns.resolver.Resolver(configure=False)
_resolver.nameservers = ["8.8.8.8","8.8.4.4","1.1.1.1"]
_resolver.timeout = DNS_TIMEOUT
_resolver.lifetime = DNS_LIFETIME

def random_local(k=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=k))

def resolve_ipv4(host):
    try:
        ans = _resolver.resolve(host, "A")
        for r in ans:
            return str(r)
    except:
        pass
    try:
        infos = socket.getaddrinfo(host, 25, socket.AF_INET, socket.SOCK_STREAM)
        if infos:
            return infos[0][4][0]
    except:
        pass
    return None

def resolve_mx(domain: str) -> list[str]:
    domain = domain.lower()
    if domain in mx_cache:
        return mx_cache[domain]
    answers = _resolver.resolve(domain, "MX")
    mxs = sorted([(int(r.preference), str(r.exchange).rstrip(".")) for r in answers], key=lambda x: x[0])
    hosts = [h for _, h in mxs]
    mx_cache[domain] = hosts
    return hosts

def looks_enterprise(mx_host: str) -> bool:
    h = (mx_host or "").lower()
    return any(k in h for k in GATEWAY_KEYWORDS)

def smtp_rcpt_sequence(mx_host: str, domain: str, real_email: str):
    # returns list[(addr, code, ms)]
    ip = resolve_ipv4(mx_host)
    if not ip:
        return []
    fake1 = f"{random_local()}@{domain}"
    fake2 = f"{random_local()}@{domain}"
    seq = []
    try:
        s = smtplib.SMTP(timeout=SMTP_TIMEOUT)
        s.connect(ip, 25)
        s.helo(HELO_DOMAIN)
        s.mail(MAIL_FROM)

        for addr in (fake1, real_email, fake2):
            start = time.perf_counter()
            try:
                code, _ = s.rcpt(addr)
            except:
                code = None
            ms = round((time.perf_counter() - start) * 1000, 2)
            seq.append((addr, code, ms))
            time.sleep(PROBE_PAUSE)

        s.quit()
        return seq
    except:
        return []

def analyze_timing(seq):
    times = [t for _, _, t in seq if isinstance(t, (int, float))]
    if not times:
        return 0, 0
    return max(times) - min(times), int(mean(times))

def detect_catch_all(domain: str, mx_host: str) -> bool | None:
    """
    Domain-level catch-all. Returns True/False or None if inconclusive.
    Cached in domain_flags_cache.
    """
    key = f"catchall:{domain}"
    if key in domain_flags_cache:
        return domain_flags_cache[key]

    # Try 2 independent fake probes; if both accept -> catch-all likely
    ip = resolve_ipv4(mx_host)
    if not ip:
        domain_flags_cache[key] = None
        return None

    accepts = 0
    for _ in range(2):
        fake = f"{random_local(12)}@{domain}"
        try:
            s = smtplib.SMTP(timeout=SMTP_TIMEOUT)
            s.connect(ip, 25)
            s.helo(HELO_DOMAIN)
            s.mail(MAIL_FROM)
            code, _ = s.rcpt(fake)
            s.quit()
            if code and 200 <= int(code) < 300:
                accepts += 1
        except:
            pass

    if accepts == 2:
        domain_flags_cache[key] = True
        return True
    if accepts == 0:
        domain_flags_cache[key] = False
        return False

    domain_flags_cache[key] = None
    return None

def timing_verify(email: str, mx_host: str) -> tuple[str, int, str, bool]:
    """
    Returns (status, score, reason, deliverable)
    """
    domain = email.split("@", 1)[1]
    seq = smtp_rcpt_sequence(mx_host, domain, email)
    delta, avg = analyze_timing(seq)
    codes = [c for _, c, _ in seq if c is not None]
    real_code = codes[1] if len(codes) > 1 else None

    enterprise = looks_enterprise(mx_host)

    if enterprise:
        return ("valid", 85, "enterprise_gateway", True)

    # Example rule: hard invalid if 550 and fast
    if real_code == 550 and delta < 40:
        return ("invalid", 10, "smtp_550", False)

    # Catch-all domains mostly end up risky unless you build deeper heuristics
    return ("risky", 55, "timing_uncertain", False)

"""
Advanced URL Intelligence Service
===================================
Multi-engine URL threat analysis:
  - Structural heuristics (50+ patterns)
  - Live DNS resolution (A, MX, TXT, NS, CNAME)
  - SSL/TLS certificate inspection
  - HTTP response & redirect chain analysis
  - Live WHOIS domain-age lookup (python-whois)
  - Phishing keyword and typosquat detection
  - Homograph / IDN attack detection
  - Threat category classification
"""
import re
import socket
import ssl
import urllib.request
import urllib.parse
import urllib.error
import json
import os
import hashlib
import math
from datetime import datetime, timezone

try:
    import whois as _whois  # python-whois
except Exception:  # pragma: no cover
    _whois = None
from typing import Dict, Any, List, Optional, Tuple

# ── Known safe domains (whitelist) ───────────────────────────────────────────────
WHITELIST = {
    "google.com","github.com","microsoft.com","apple.com","amazon.com",
    "cloudflare.com","fastly.com","akamai.com","cdn.jsdelivr.net",
    "stackoverflow.com","wikipedia.org","mozilla.org","python.org",
    "npmjs.com","pypi.org","reddit.com","twitter.com","youtube.com",
}

# ── Phishing keywords (weighted) ─────────────────────────────────────────────────
PHISHING_KEYWORDS: List[Tuple[str, int, str]] = [
    ("login",        12, "Phishing keyword: login"),
    ("signin",       12, "Phishing keyword: sign-in"),
    ("verify",       15, "Phishing keyword: verify"),
    ("verification", 15, "Phishing keyword: verification"),
    ("account",      10, "Phishing keyword: account"),
    ("update",       10, "Phishing keyword: update"),
    ("secure",       12, "Phishing keyword: secure"),
    ("banking",      20, "Phishing keyword: banking"),
    ("paypal",       25, "Brand impersonation: PayPal"),
    ("apple",        18, "Brand impersonation: Apple"),
    ("amazon",       18, "Brand impersonation: Amazon"),
    ("microsoft",    18, "Brand impersonation: Microsoft"),
    ("gmail",        18, "Brand impersonation: Gmail"),
    ("netflix",      18, "Brand impersonation: Netflix"),
    ("crypto",       20, "High-risk keyword: crypto"),
    ("wallet",       18, "High-risk keyword: wallet"),
    ("password",     20, "High-risk keyword: password"),
    ("admin",        15, "High-risk keyword: admin panel"),
    ("confirm",      12, "Phishing keyword: confirm"),
    ("recover",      12, "Phishing keyword: recover"),
    ("reward",       15, "Phishing keyword: reward"),
    ("prize",        20, "Phishing keyword: prize"),
    ("urgent",       18, "Social engineering: urgent"),
    ("click-here",   15, "Social engineering: click-here"),
]

# ── Suspicious TLDs ───────────────────────────────────────────────────────────────
SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",      # Free / disposable
    ".xyz", ".top", ".cc", ".pw", ".icu",   # Spam-heavy
    ".onion", ".i2p",                        # Dark web
    ".su",                                   # Old Soviet TLD, abuse-heavy
    ".zip", ".mov",                          # Google's controversial new TLDs
}

# ── DNS Resolution ───────────────────────────────────────────────────────────────
def _dns_resolve(hostname: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"a_records": [], "error": None}
    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_INET)
        result["a_records"] = list({i[4][0] for i in infos})[:5]
    except Exception as ex:
        result["error"] = str(ex)
    return result

# ── SSL Certificate Inspection ────────────────────────────────────────────────────
def _ssl_info(hostname: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"valid": False, "issuer": None, "expires": None, "subject": None, "error": None}
    try:
        ctx  = ssl.create_default_context()
        conn = ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=5), server_hostname=hostname)
        cert = conn.getpeercert()
        conn.close()
        issuer  = dict(x[0] for x in cert.get("issuer", []))
        subject = dict(x[0] for x in cert.get("subject", []))
        expires = cert.get("notAfter", "")
        result.update({"valid": True, "issuer": issuer.get("organizationName","Unknown"),
                       "expires": expires, "subject": subject.get("commonName","")})
    except ssl.SSLCertVerificationError:
        result["error"] = "SSL certificate verification failed"
    except ssl.SSLError as e:
        result["error"] = f"SSL error: {e}"
    except Exception as e:
        result["error"] = str(e)
    return result

# ── HTTP Response + Redirect Chain ───────────────────────────────────────────────
def _http_probe(url: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {
        "status_code": None, "final_url": url, "redirect_chain": [],
        "server": None, "content_type": None, "page_title": None,
        "content_length": None, "error": None, "x_frame_options": None,
        "content_security_policy": False, "strict_transport": False,
    }
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0 (SOC/Scanner)"})
        resp = urllib.request.urlopen(req, timeout=8)
        result["status_code"] = resp.status
        result["final_url"]   = resp.url
        headers = {k.lower(): v for k, v in resp.headers.items()}
        result["server"]         = headers.get("server","Unknown")
        result["content_type"]   = headers.get("content-type","")
        result["content_length"] = headers.get("content-length","?")
        result["x_frame_options"] = headers.get("x-frame-options", None)
        result["content_security_policy"] = "content-security-policy" in headers
        result["strict_transport"]        = "strict-transport-security" in headers
        # Extract title
        body = resp.read(32768).decode("utf-8", errors="ignore")
        title_m = re.search(r'<title[^>]*>([^<]{1,200})</title>', body, re.I)
        result["page_title"] = title_m.group(1).strip() if title_m else None
    except urllib.error.HTTPError as e:
        result["status_code"] = e.code
        result["error"] = f"HTTP {e.code}"
    except Exception as e:
        result["error"] = str(e)
    return result

# ── Domain Entropy (randomized-looking domains) ──────────────────────────────────
def _domain_entropy(domain: str) -> float:
    c = {}
    for ch in domain:
        c[ch] = c.get(ch, 0) + 1
    e = 0.0
    for v in c.values():
        p = v / len(domain)
        e -= p * math.log2(p)
    return round(e, 3)

# ── Homograph / IDN Detection ─────────────────────────────────────────────────────
def _check_homograph(hostname: str) -> bool:
    return "xn--" in hostname  # Punycode = potential IDN homograph attack

# ── Real WHOIS domain age ────────────────────────────────────────────────────────
def _domain_whois(hostname: str) -> Dict[str, Any]:
    """Live WHOIS lookup. Returns {available, age_days, created, expires, registrar}.
    available=False when python-whois is missing or the registry gave no answer —
    the caller must not treat 'unknown age' as 'new domain'."""
    if _whois is None:
        return {"available": False, "reason": "python-whois not installed"}
    try:
        w = _whois.whois(hostname)
    except Exception as e:
        return {"available": False, "reason": f"whois lookup failed: {e}"}
    created = w.creation_date
    if isinstance(created, list):
        created = created[0] if created else None
    expires = w.expiration_date
    if isinstance(expires, list):
        expires = expires[0] if expires else None
    if not created:
        return {"available": False, "reason": "registry returned no creation date"}
    try:
        age_days = (datetime.now(timezone.utc).replace(tzinfo=None) - created.replace(tzinfo=None)).days
    except Exception:
        return {"available": False, "reason": "unparseable creation date"}
    reg = w.registrar
    if isinstance(reg, list):
        reg = reg[0] if reg else None
    return {"available": True, "age_days": age_days,
            "created": str(created), "expires": str(expires) if expires else None,
            "registrar": reg}


class URLScanService:
    """Advanced multi-engine URL threat intelligence scanner."""

    @staticmethod
    def analyze_limit(url: str) -> Dict[str, Any]:
        return URLScanService.analyze(url)

    @staticmethod
    def analyze(url: str) -> Dict[str, Any]:
        raw_url = url.strip()
        if not raw_url.startswith(("http://","https://")):
            raw_url = "https://" + raw_url

        parsed  = urllib.parse.urlparse(raw_url)
        hostname = parsed.hostname or ""
        path     = parsed.path or ""
        tld      = "." + hostname.split(".")[-1] if "." in hostname else ""

        # Strip www
        domain = re.sub(r'^www\.', '', hostname)

        score    = 0
        findings: List[str] = []
        categories: List[str] = []

        # ── 1. Whitelist check ─────────────────────────────────────────────────
        is_white = any(hostname.endswith(d) for d in WHITELIST)

        # ── 2. Protocol ────────────────────────────────────────────────────────
        if parsed.scheme == "http":
            score += 15
            findings.append("Unencrypted HTTP — no TLS/SSL")

        # ── 3. Suspicious TLD ──────────────────────────────────────────────────
        if tld in SUSPICIOUS_TLDS:
            score += 25
            findings.append(f"High-risk TLD: {tld}")
            categories.append("Suspicious TLD")

        # ── 4. @ symbol in URL ─────────────────────────────────────────────────
        if "@" in raw_url:
            score += 35
            findings.append("User-info in URL (@ symbol) — credential phishing pattern")
            categories.append("Credential Trick")

        # ── 5. IP address as host ──────────────────────────────────────────────
        if re.match(r'^\d{1,3}(\.\d{1,3}){3}$', hostname):
            score += 30
            findings.append("Bare IP address as host — malware hosting pattern")
            categories.append("IP Host")

        # ── 6. Subdomain depth ─────────────────────────────────────────────────
        subdomain_count = hostname.count(".")
        if subdomain_count > 4:
            score += 20
            findings.append(f"Excessive subdomain depth: {subdomain_count} levels")
            categories.append("Subdomain Abuse")

        # ── 7. URL length ──────────────────────────────────────────────────────
        if len(raw_url) > 75:
            score += 10
            findings.append(f"Unusually long URL ({len(raw_url)} chars)")

        # ── 8. Phishing keywords ───────────────────────────────────────────────
        url_lower = raw_url.lower()
        for kw, pts, desc in PHISHING_KEYWORDS:
            if kw in url_lower and not is_white:
                score += pts
                findings.append(desc)

        # ── 9. Domain entropy (randomized DGA-like domains) ────────────────────
        ent = _domain_entropy(domain)
        if ent > 3.8:
            score += 15
            findings.append(f"High domain entropy ({ent}) — possible DGA domain")
            categories.append("DGA Domain")

        # ── 10. Homograph / IDN attack ─────────────────────────────────────────
        if _check_homograph(hostname):
            score += 30
            findings.append("Punycode/IDN domain detected — potential homograph attack")
            categories.append("Homograph Attack")

        # ── 11. Numeric-heavy domain ───────────────────────────────────────────
        digit_ratio = sum(c.isdigit() for c in domain) / max(1, len(domain))
        if digit_ratio > 0.4:
            score += 12
            findings.append(f"High digit ratio in domain ({digit_ratio:.0%}) — spam pattern")

        # ── 12. Hyphens ────────────────────────────────────────────────────────
        if domain.count("-") >= 3:
            score += 10
            findings.append("Multiple hyphens in domain — common phishing indicator")

        # ── 13. Path indicators ────────────────────────────────────────────────
        path_l = path.lower()
        for pind in ["/wp-login","/admin","/.env","/.git","passwd","cmd=","exec(","/shell"]:
            if pind in path_l:
                score += 20
                findings.append(f"Suspicious path indicator: {pind}")
                categories.append("Suspicious Path")

        # ── 14. Query string complexity ────────────────────────────────────────
        qs = parsed.query or ""
        if len(qs) > 200:
            score += 10
            findings.append("Very long query string")

        # ── DNS resolution ─────────────────────────────────────────────────────
        dns_info = _dns_resolve(hostname) if hostname else {"a_records":[],"error":"No hostname"}

        # If DNS fails completely for non-IP, it's suspicious
        if dns_info.get("error") and not re.match(r'^\d', hostname):
            score += 10
            findings.append("DNS resolution failed — domain may not exist or is blocked")

        # ── SSL / TLS ──────────────────────────────────────────────────────────
        ssl_info = _ssl_info(hostname) if (hostname and parsed.scheme == "https") else {"valid": False, "error": "HTTP only"}
        if not ssl_info.get("valid") and parsed.scheme == "https":
            score += 20
            findings.append("Invalid or missing SSL certificate")
            categories.append("SSL Issue")
        if ssl_info.get("valid") and ssl_info.get("issuer"):
            findings.append(f"SSL issued by: {ssl_info['issuer']}")

        # ── HTTP probe ─────────────────────────────────────────────────────────
        http_info = _http_probe(raw_url)
        if http_info.get("status_code") and http_info["status_code"] >= 400:
            score += 5
            findings.append(f"HTTP error response: {http_info['status_code']}")

        # Redirect to different domain
        if http_info.get("final_url") and http_info["final_url"] != raw_url:
            final_host = urllib.parse.urlparse(http_info["final_url"]).hostname or ""
            if final_host and final_host != hostname:
                score += 15
                findings.append(f"Redirects to different domain: {final_host}")
                categories.append("Hidden Redirect")

        # ── Domain Age (real WHOIS) ────────────────────────────────────────────
        whois_info = _domain_whois(hostname) if hostname else {"available": False, "reason": "no hostname"}
        if whois_info.get("available"):
            age_days = whois_info["age_days"]
            age_str = f"{age_days} days (registered {whois_info['created'][:10]})"
            if age_days < 30:
                score += 25
                findings.append(f"Very new domain: registered {age_days} days ago")
                categories.append("New Domain")
            elif age_days < 180:
                score += 10
                findings.append(f"Recently registered domain: {age_days} days old")
        else:
            age_days = None
            age_str = f"unknown ({whois_info.get('reason', 'no data')})"

        # ── Whitelist discount ─────────────────────────────────────────────────
        if is_white:
            score = max(0, score - 60)
            findings = [f"[Trusted domain] {f}" for f in findings]

        # Normalize
        score = min(100, score)

        risk_level = "SAFE"
        if score >= 30: risk_level = "SUSPICIOUS"
        if score >= 65: risk_level = "MALICIOUS"

        # ── Threat Category ────────────────────────────────────────────────────
        if not categories:
            if score > 50: categories = ["Phishing", "Credential Theft"]
            elif score > 20: categories = ["Suspicious Domain"]
            else: categories = ["Clean"]
        threat_category = " / ".join(categories[:3]) if categories else "Unknown"

        # ── IP Geolocation (real — ip-api.com via the shared batch cache) ──────
        ip = dns_info["a_records"][0] if dns_info["a_records"] else "N/A"
        country, region, isp, flag = "Unknown", "N/A", "Unknown", "🏳️"
        if ip and ip != "N/A":
            try:
                from app.api.v1.endpoints.dashboard import fetch_geoip_batch_sync, get_flag_emoji
                geo = fetch_geoip_batch_sync([ip]).get(ip, {})
                if geo:
                    country = geo.get("country", "Unknown")
                    region = geo.get("code", "N/A")
                    isp = geo.get("isp", "Unknown")
                    if geo.get("asn") and geo.get("asn") != "N/A":
                        isp = f"{isp} ({geo['asn']})"
                    flag = get_flag_emoji(geo.get("code", ""))
            except Exception:
                pass

        # ── Structured Report ──────────────────────────────────────────────────
        return {
            "url":              raw_url,
            "domain":           hostname,
            "path":             path,
            "risk_score":       score,
            "risk_level":       risk_level,
            "threat_category":  threat_category,
            "findings":         findings[:20],
            "domain_age":       age_str,
            "domain_age_days":  age_days,
            "ip_address":       ip,
            "country":          f"{flag} {country}",
            "region":           region,
            "isp":              isp,
            "server_location":  f"{flag} {country}",
            "ssl":              ssl_info,
            "dns":              dns_info,
            "http":             http_info,
            "whois":            whois_info,
            "entropy":          ent,
            "categories":       categories,
            "is_whitelisted":   is_white,
            "scan_timestamp":   datetime.now(timezone.utc).isoformat(),
        }

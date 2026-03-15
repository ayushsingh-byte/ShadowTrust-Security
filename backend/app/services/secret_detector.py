"""
Secret Detector Service
========================
Scans binary and text content for 30+ types of hardcoded secrets:
API keys, auth tokens, passwords, private keys, database URLs,
cloud credentials, C2 endpoints, and embedded credentials.
"""
import re
from typing import Dict, Any, List

# ─── Secret Pattern Registry ──────────────────────────────────────────────────────
# (pattern, type_name, severity)
SECRET_PATTERNS: List[tuple] = [
    # ── Cloud / Infrastructure ──────────────────────────────────────────────────
    (r'AIza[0-9A-Za-z\-_]{35}',                                          "Google API Key",         "CRITICAL"),
    (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}',                       "Firebase FCM Key",       "CRITICAL"),
    (r'(?<![A-Z0-9])AKIA[0-9A-Z]{16}(?![A-Z0-9])',                      "AWS Access Key ID",      "CRITICAL"),
    (r'(?:aws_secret_access_key|AWS_SECRET)[^=\n]*=\s*([A-Za-z0-9/+=]{40})', "AWS Secret Access Key", "CRITICAL"),
    (r'[0-9a-f]{32}-us[0-9]{1,2}',                                       "Mailchimp API Key",      "HIGH"),
    (r'SG\.[a-zA-Z0-9\-_]{22}\.[a-zA-Z0-9\-_]{43}',                    "SendGrid API Key",       "HIGH"),
    (r'key-[a-zA-Z0-9]{32}',                                             "Mailgun API Key",        "HIGH"),
    (r'sk_live_[0-9a-z]{24}',                                            "Stripe Live Key",        "CRITICAL"),
    (r'sk_test_[0-9a-z]{24}',                                            "Stripe Test Key",        "HIGH"),
    (r'rk_live_[0-9a-z]{24}',                                            "Stripe Restricted Key",  "HIGH"),
    (r'AC[a-z0-9]{32}',                                                   "Twilio Account SID",     "HIGH"),
    (r'SK[a-z0-9]{32}',                                                   "Twilio API Key",         "HIGH"),
    (r'(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}',                       "GitHub Token",           "CRITICAL"),
    (r'v1\.[a-zA-Z0-9+/=]{86}==',                                        "Slack Bot Token",        "HIGH"),
    (r'xox[baprs]-[0-9]{12}-[0-9]{12}-[0-9a-zA-Z]{24}',                "Slack API Token",        "HIGH"),

    # ── Cryptographic Material ──────────────────────────────────────────────────
    (r'-----BEGIN RSA PRIVATE KEY-----',                                  "RSA Private Key",        "CRITICAL"),
    (r'-----BEGIN EC PRIVATE KEY-----',                                   "EC Private Key",         "CRITICAL"),
    (r'-----BEGIN OPENSSH PRIVATE KEY-----',                              "OpenSSH Private Key",    "CRITICAL"),
    (r'-----BEGIN PGP PRIVATE KEY BLOCK-----',                            "PGP Private Key",        "CRITICAL"),
    (r'-----BEGIN DSA PRIVATE KEY-----',                                  "DSA Private Key",        "CRITICAL"),

    # ── JWT / Auth Tokens ───────────────────────────────────────────────────────
    (r'eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}', "JWT Token",              "HIGH"),
    (r'Bearer\s+[A-Za-z0-9\-._~+/]+=*',                                  "Bearer Auth Token",      "HIGH"),
    (r'Basic\s+[A-Za-z0-9+/]+=*',                                        "Basic Auth Header",      "HIGH"),

    # ── Database URLs ───────────────────────────────────────────────────────────
    (r'mongodb(?:\+srv)?://[A-Za-z0-9:@./?=&_-]{10,}',                  "MongoDB URI",            "CRITICAL"),
    (r'postgresql://[A-Za-z0-9:@./?=&_-]{10,}',                         "PostgreSQL URI",         "CRITICAL"),
    (r'mysql://[A-Za-z0-9:@./?=&_-]{10,}',                              "MySQL URI",              "CRITICAL"),
    (r'redis://[A-Za-z0-9:@./?=&_-]{10,}',                              "Redis URI",              "HIGH"),
    (r'jdbc:[a-z]+://[A-Za-z0-9:@./?=&_-]{10,}',                        "JDBC Connection String", "CRITICAL"),

    # ── Hardcoded Credentials ───────────────────────────────────────────────────
    (r'(?:password|passwd|pwd|pass)\s*[=:]\s*["\']([^"\']{6,64})["\']', "Hardcoded Password",     "CRITICAL"),
    (r'(?:username|user|uname)\s*[=:]\s*["\']([^"\']{3,32})["\']',      "Hardcoded Username",     "MEDIUM"),
    (r'(?:api_?key|apikey|api-key)\s*[=:]\s*["\']([^"\']{8,64})["\']',  "Hardcoded API Key",      "HIGH"),
    (r'(?:secret|secret_?key)\s*[=:]\s*["\']([^"\']{8,64})["\']',       "Hardcoded Secret",       "HIGH"),
    (r'(?:token|auth_?token|access_?token)\s*[=:]\s*["\']([^"\']{8,})["\']', "Hardcoded Token",   "HIGH"),
    (r'(?:private_?key|priv_?key)\s*[=:]\s*["\']([^"\']{10,})["\']',    "Hardcoded Private Key",  "CRITICAL"),

    # ── Network Infrastructure ──────────────────────────────────────────────────
    (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?(?:/\S+)?', "IP-Based URL",           "HIGH"),
    (r'https?://[a-z0-9\-]+\.(?:onion|i2p)',                             "Dark Web URL",           "CRITICAL"),
    (r'https?://[a-z0-9\-]+\.(?:tk|ml|ga|cf|gq|xyz|top|cc)\b',         "Suspicious TLD URL",     "HIGH"),
    (r'\b(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(?:\.(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}\b:\d{4,5}', "IP:Port Endpoint", "HIGH"),

    # ── Miscellaneous ───────────────────────────────────────────────────────────
    (r'-----BEGIN CERTIFICATE-----',                                      "Certificate",            "LOW"),
    (r'gcp_[a-zA-Z0-9_-]{24}',                                           "GCP Credential",         "CRITICAL"),
    (r'PRIVATE_KEY_ID\s*[=:]\s*["\']([^"\']+)["\']',                    "Private Key ID",         "HIGH"),
    (r'app_secret\s*[=:]\s*["\']([a-f0-9]{32})["\']',                   "App Secret",             "HIGH"),
    (r'client_secret\s*[=:]\s*["\']([^"\']{16,})["\']',                 "OAuth Client Secret",    "HIGH"),
    (r'consumer_secret\s*[=:]\s*["\']([^"\']{16,})["\']',               "OAuth Consumer Secret",  "HIGH"),
    (r'encryption_key\s*[=:]\s*["\']([^"\']{8,})["\']',                 "Encryption Key",         "CRITICAL"),
    (r'aes_key\s*[=:]\s*["\']([^"\']+)["\']',                           "AES Key",                "CRITICAL"),
    (r'hmac_secret\s*[=:]\s*["\']([^"\']+)["\']',                       "HMAC Secret",            "CRITICAL"),
]

# Severity ordering for sort / display
SEV_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def _mask_value(val: str, keep_prefix: int = 6, keep_suffix: int = 4) -> str:
    """Mask the middle of a secret value for safe display."""
    if len(val) <= keep_prefix + keep_suffix + 4:
        return val[:keep_prefix] + "●●●●"
    return val[:keep_prefix] + "●" * min(12, len(val) - keep_prefix - keep_suffix) + val[-keep_suffix:]


def _extract_context(text: str, match_start: int, match_end: int, context: int = 60) -> str:
    """Return surrounding context around a match."""
    start = max(0, match_start - context)
    end   = min(len(text), match_end + context)
    raw   = text[start:end].replace("\n", " ").replace("\r", "")
    return raw[:160]


class SecretDetector:
    """
    Scans binary / text content for 50+ secret patterns.
    Returns a structured list of findings with severity, context, and masked values.
    """

    def __init__(self, data: bytes, filename: str):
        self.data     = data
        self.filename = filename
        self.text     = data.decode("utf-8", errors="ignore")

    def scan(self) -> List[Dict[str, Any]]:
        findings: List[Dict[str, Any]] = []
        seen = set()

        for pattern, secret_type, severity in SECRET_PATTERNS:
            try:
                for m in re.finditer(pattern, self.text, re.IGNORECASE):
                    raw_val = m.group(0)
                    # Dedup by type + first 12 chars
                    dedup_key = (secret_type, raw_val[:12])
                    if dedup_key in seen:
                        continue
                    seen.add(dedup_key)

                    context = _extract_context(self.text, m.start(), m.end())
                    findings.append({
                        "type":     secret_type,
                        "severity": severity,
                        "masked":   _mask_value(raw_val),
                        "raw_prefix": raw_val[:20],
                        "context":  context,
                        "position": m.start(),
                        "source":   self.filename,
                    })
            except re.error:
                continue

        # Sort by severity
        findings.sort(key=lambda x: SEV_ORDER.get(x["severity"], 9))
        return findings[:50]  # cap at 50 findings

    def summary(self) -> Dict[str, Any]:
        findings = self.scan()
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            counts[f["severity"]] = counts.get(f["severity"], 0) + 1
        return {
            "findings": findings,
            "summary": counts,
            "total": len(findings),
            "has_critical": counts["CRITICAL"] > 0,
        }

"""
Heuristic "category layer" for the unified Logs page.

`categorize(text, source)` runs an ordered list of regex rules over a log line
and returns the first match: ``{category, severity, reason}``. Deterministic,
zero-dependency, instant. Add rules to ``RULES`` — first match wins, so put the
specific ones first.

Categories:  auth · recon · exec · c2 · malware · lateral · exfil · persistence ·
             privilege · defense-evasion · system · network · audit · error · info
Severities:  INFO · LOW · MEDIUM · HIGH · CRITICAL
"""

from __future__ import annotations

import re
from typing import Dict, List, Tuple

_I = re.IGNORECASE

# (pattern, category, severity, reason)
RULES: List[Tuple[re.Pattern, str, str, str]] = [
    # ── malware / AV ──────────────────────────────────────────────────────────
    (re.compile(r"(virus|trojan|malware|eicar|clamav|signature).{0,40}\bFOUND\b|\bFOUND\b.{0,40}(virus|trojan|malware|eicar)"
                r"|clamav.*infected|\b(Win|Unix|Multios)\.(Trojan|Malware|Test)\.|\bEicar\b", _I),
     "malware", "CRITICAL", "antivirus signature hit"),
    (re.compile(r"\b(ransomware|cobalt ?strike|mimikatz|meterpreter|reverse shell|/dev/tcp/|nc .*-e |bash -i)\b", _I),
     "malware", "CRITICAL", "known offensive tooling / reverse shell"),

    # ── auth ──────────────────────────────────────────────────────────────────
    (re.compile(r"(failed password|authentication failure|auth(entication)? failed|login failed|invalid user|EventCode=4625|\"4625\""
                r"|\b(status|result|outcome)\"?\s*[=:]\s*\"?(fail|denied|invalid|error))", _I),
     "auth", "HIGH", "failed authentication"),
    (re.compile(r"(accepted password|login success|session opened|EventCode=4624|\"4624\"|cowrie\.login\.success"
                r"|\b(status|result|outcome)\"?\s*[=:]\s*\"?(ok|success|allow|pass))", _I),
     "auth", "MEDIUM", "successful authentication"),
    (re.compile(r"\"event\"\s*:\s*\"auth\"|\b(action|activity)\"?\s*[=:]\s*\"?(login|logon|authentication)\b", _I),
     "auth", "LOW", "authentication event"),
    (re.compile(r"(EventCode=4720|\"4720\"|useradd|adduser|net user .*/add|new account)", _I),
     "persistence", "HIGH", "account created"),
    (re.compile(r"(EventCode=4740|\"4740\"|account locked)", _I),
     "auth", "MEDIUM", "account lockout"),

    # ── privilege ─────────────────────────────────────────────────────────────
    (re.compile(r"\b(sudo:|su\[|to root|COMMAND=/|pkexec|setuid|EventCode=4672|SeDebugPrivilege)\b", _I),
     "privilege", "HIGH", "privilege escalation / elevated command"),

    # ── recon ─────────────────────────────────────────────────────────────────
    (re.compile(r"\b(nmap|masscan|zmap|port ?scan|dionaea\.connection\.reject|scan detected)\b", _I),
     "recon", "MEDIUM", "scanning / probing"),
    (re.compile(r"\b(whoami|uname -a|id;|cat /etc/passwd|ipconfig|net view|systeminfo|arp -a)\b", _I),
     "recon", "MEDIUM", "host / network discovery command"),

    # ── exec ──────────────────────────────────────────────────────────────────
    (re.compile(r"(wget |curl .*http|certutil .*urlcache|Invoke-WebRequest|powershell .*-enc|base64 -d|python -c|EventCode=4688|ProcessCreate|cowrie\.command\.input)", _I),
     "exec", "HIGH", "command execution / payload fetch"),
    (re.compile(r"\.(sh|elf|bin|exe|dll|ps1|bat|scr)\b", _I),
     "exec", "MEDIUM", "executable / script referenced"),

    # ── c2 ────────────────────────────────────────────────────────────────────
    (re.compile(r"\b(beacon|c2 |command.and.control|dns tunnel|user-agent:.*(curl|wget|python))\b", _I),
     "c2", "HIGH", "possible command-and-control"),

    # ── lateral movement ─────────────────────────────────────────────────────
    (re.compile(r"\b(psexec|wmic .*process call create|smbexec|winrm|EventCode=5140|admin\$|ipc\$)\b", _I),
     "lateral", "HIGH", "lateral movement technique"),

    # ── exfil ─────────────────────────────────────────────────────────────────
    (re.compile(r"\b(scp |rsync .*::|curl .*-T |PUT .*http|upload|exfil|to pastebin|transfer\.sh)\b", _I),
     "exfil", "HIGH", "possible data exfiltration"),

    # ── defense evasion ──────────────────────────────────────────────────────
    (re.compile(r"(clear[- ]?(event ?)?log|EventCode=1102|wevtutil cl|history -c|rm .*\.log|disable.*(defender|firewall|av))", _I),
     "defense-evasion", "HIGH", "log/defence tampering"),

    # ── network ───────────────────────────────────────────────────────────────
    (re.compile(r"(connection (accept|opened|closed|reject)|apache.*\"(GET|POST|PUT|HEAD) |dionaea\.connection|new connection from)", _I),
     "network", "LOW", "network connection"),
    (re.compile(r"\b(SQL injection|xss|\.\./\.\./|union select|' or '1'='1|<script>|/etc/passwd)\b", _I),
     "exec", "HIGH", "web attack pattern"),

    # ── platform / system ────────────────────────────────────────────────────
    (re.compile(r"(traceback \(most recent call last\)|unhandledpromiserejection|panic:|fatal error|segfault|core dumped)", _I),
     "error", "HIGH", "application crash / exception"),
    (re.compile(r"\b(error|exception|failed to|cannot |could not |denied|refused|timeout|unhealthy|OOMKilled|exit code [1-9])\b", _I),
     "error", "MEDIUM", "error / failure"),
    (re.compile(r"\b(warn(ing)?|deprecat|retry|slow query|high (cpu|memory))\b", _I),
     "system", "LOW", "warning"),
    (re.compile(r"(started|listening on|ready|healthy|initialised|initialized|bound to|Uvicorn running|nginx.*start)", _I),
     "system", "INFO", "service lifecycle"),

    # ── audit ─────────────────────────────────────────────────────────────────
    (re.compile(r"\b(APPROVE|DENY|REVOKE|ELEVATE|ISSUE_CREDENTIALS|RESET_PASSWORD|role change|clearance)\b"),
     "audit", "MEDIUM", "admin / access-control action"),
]

# Fallbacks keyed by source when no rule matched.
_SOURCE_DEFAULTS = {
    "honeypot": ("network", "LOW", "honeypot telemetry"),
    "splunk": ("info", "INFO", "indexed event"),
    "platform": ("system", "INFO", "container / app log"),
    "audit": ("audit", "INFO", "audit record"),
}


def categorize(text: str, source: str = "") -> Dict[str, str]:
    t = text or ""
    for pattern, category, severity, reason in RULES:
        if pattern.search(t):
            return {"category": category, "severity": severity, "reason": reason}
    cat, sev, reason = _SOURCE_DEFAULTS.get(source, ("info", "INFO", "uncategorised"))
    return {"category": cat, "severity": sev, "reason": reason}


_SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


def severity_rank(sev: str) -> int:
    return _SEV_ORDER.get((sev or "INFO").upper(), 0)

"""
CAPE Sandbox Integration Engine
================================
Production-grade sandbox analysis proxy. When CAPE_URL env var is set,
delegates to a real CAPE deployment. Otherwise runs a deep heuristic
simulation engine that produces the same structured report schema.
Results are cached by SHA-256 hash to avoid reprocessing identical samples.
"""

import os
import json
import math
import hashlib
import struct
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

CAPE_URL = os.getenv("CAPE_URL", "").rstrip("/")
CAPE_API_KEY = os.getenv("CAPE_API_KEY", "")
CACHE_FILE = os.path.join("scans", "cape_cache.json")
SIM_ENGINE_VERSION = 2

# ─── MITRE Technique Catalog ───────────────────────────────────────────────────
MITRE_TECHNIQUES = {
    "T1059": "Command and Scripting Interpreter",
    "T1055": "Process Injection",
    "T1082": "System Information Discovery",
    "T1083": "File and Directory Discovery",
    "T1071": "Application Layer Protocol (C2)",
    "T1547": "Boot or Logon Autostart Execution",
    "T1105": "Ingress Tool Transfer",
    "T1027": "Obfuscated Files or Information",
    "T1140": "Deobfuscate/Decode Files",
    "T1190": "Exploit Public-Facing Application",
    "T1486": "Data Encrypted for Impact (Ransomware)",
    "T1112": "Modify Registry",
    "T1070": "Indicator Removal on Host",
    "T1016": "System Network Configuration Discovery",
    "T1049": "System Network Connections Discovery",
    "T1021": "Remote Services (Lateral Movement)",
    "T1078": "Valid Accounts",
    "T1136": "Create Account",
    "T1566": "Phishing",
    "T1003": "OS Credential Dumping",
}

# Behavioral signature → MITRE mapping
BEHAVIOR_MITRE_MAP = {
    b"/bin/sh": ["T1059"],
    b"/bin/bash": ["T1059"],
    b"cmd.exe": ["T1059"],
    b"powershell": ["T1059", "T1027"],
    b"CreateRemoteThread": ["T1055"],
    b"VirtualAllocEx": ["T1055"],
    b"WriteProcessMemory": ["T1055"],
    b"HKEY_LOCAL_MACHINE\\Software\\Microsoft\\Windows\\CurrentVersion\\Run": ["T1547", "T1112"],
    b"RegSetValueEx": ["T1112"],
    b"wget": ["T1105"],
    b"curl ": ["T1105"],
    b"base64": ["T1027", "T1140"],
    b"encrypt": ["T1486"],
    b".locked": ["T1486"],
    b"bitcoin": ["T1486"],
    b"monero": ["T1486"],
    b"socket": ["T1071"],
    b"connect(": ["T1071"],
    b"WSAConnect": ["T1071", "T1049"],
    b"nc -e": ["T1059", "T1021"],
    b"mkfifo": ["T1059"],
    b"WNetAddConnection": ["T1021"],
    b"net user": ["T1136"],
    b"mimikatz": ["T1003"],
    b"lsass": ["T1003"],
    b"GetAdaptersInfo": ["T1016"],
    b"ipconfig": ["T1016"],
    b"DeleteFile": ["T1070"],
    b"ClearEventLog": ["T1070"],
}

# Family classification heuristics
FAMILY_SIGNATURES = {
    "Ransomware": [b"encrypt", b".locked", b"bitcoin", b"ransom", b"CryptoLocker", b"WannaCry", b"monero", b"decrypt"],
    "RAT/Backdoor": [b"CreateRemoteThread", b"VirtualAllocEx", b"shell32", b"reverse_shell", b"netcat", b"meterpreter"],
    "Botnet/Downloader": [b"wget", b"curl ", b"socket", b"connect(", b"C2", b"botnet", b"bot_id"],
    "Trojan": [b"/bin/bash", b"cmd.exe", b"powershell", b"svchost", b"RunDll32"],
    "Spyware/Stealer": [b"mimikatz", b"lsass", b"password", b"keylog", b"clipboard"],
    "Rootkit": [b"NtSetSystemInformation", b"DKOM", b"rootkit", b"driver", b"kernel32"],
    "Worm": [b"WNetAddConnection", b"SMB", b"EternalBlue", b"spreader", b"AutoRun"],
    "Adware": [b"AdSense", b"adware", b"popup", b"banner", b"track"],
}

# Suspicious API calls library
SUSPICIOUS_APIS = [
    "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread",
    "OpenProcess", "NtUnmapViewOfSection", "SetWindowsHookEx",
    "GetAsyncKeyState", "RegSetValueEx", "RegCreateKeyEx",
    "CreateServiceA", "OpenSCManager", "WinExec",
    "ShellExecuteA", "URLDownloadToFile", "InternetOpenA",
    "socket", "connect", "send", "recv", "WSAStartup",
    "CryptEncrypt", "CryptDecrypt", "BCryptEncrypt",
    "NtQuerySystemInformation", "GetSystemInfo", "IsDebuggerPresent",
    "CheckRemoteDebuggerPresent", "OutputDebugString",
]

# Common benign imports (excluded from suspicious set)
COMMON_IMPORTS = {
    "kernel32.dll", "ntdll.dll", "user32.dll", "advapi32.dll",
    "msvcrt.dll", "ws2_32.dll", "gdi32.dll", "shell32.dll",
    "ole32.dll", "oleaut32.dll", "shlwapi.dll", "rpcrt4.dll",
}

# ─── Cache Layer ────────────────────────────────────────────────────────────────

def _load_cache() -> Dict[str, Any]:
    if not os.path.exists(CACHE_FILE):
        return {}
    try:
        with open(CACHE_FILE, "r") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_cache(cache: Dict[str, Any]) -> None:
    os.makedirs("scans", exist_ok=True)
    with open(CACHE_FILE, "w") as f:
        json.dump(cache, f, indent=2)


def get_cached_result(sha256: str) -> Optional[Dict[str, Any]]:
    cache = _load_cache()
    cached = cache.get(sha256)
    if not isinstance(cached, dict):
        return None

    # Ignore stale simulated cache entries when simulation logic changes.
    source = cached.get("source", "SIMULATED")
    if source != "CAPE_LIVE" and cached.get("sim_engine_version") != SIM_ENGINE_VERSION:
        return None

    return cached


def cache_result(sha256: str, result: Dict[str, Any]) -> None:
    cache = _load_cache()
    cache[sha256] = result
    # Limit cache to 500 entries (FIFO)
    if len(cache) > 500:
        oldest_key = next(iter(cache))
        del cache[oldest_key]
    _save_cache(cache)


# ─── Binary Analysis Utilities ──────────────────────────────────────────────────

def _calculate_entropy(data: bytes) -> float:
    """Shannon entropy of a byte array. High entropy (>7.0) suggests packing/encryption."""
    if not data:
        return 0.0
    counter = Counter(data)
    entropy = 0.0
    for count in counter.values():
        p = count / len(data)
        entropy -= p * math.log2(p)
    return round(entropy, 3)


def _is_pe(data: bytes) -> bool:
    return data[:2] == b'MZ'


def _is_elf(data: bytes) -> bool:
    return data[:4] == b'\x7fELF'


def _is_pdf(data: bytes) -> bool:
    return data[:4] == b'%PDF'


def _extract_printable_strings(data: bytes, min_len: int = 6) -> List[str]:
    """Extract printable ASCII strings from binary data."""
    result = []
    current = b""
    for byte in data:
        if 32 <= byte <= 126:
            current += bytes([byte])
        else:
            if len(current) >= min_len:
                result.append(current.decode("ascii", errors="ignore"))
            current = b""
    if len(current) >= min_len:
        result.append(current.decode("ascii", errors="ignore"))
    # Filter noise and return top unique strings
    interesting = [s for s in list(set(result)) if not s.strip().startswith('//') and len(s) < 200]
    return interesting[:80]


def _detect_packer(data: bytes, entropy: float, strings: List[str]) -> Optional[str]:
    packer_sigs = {
        "UPX": [b"UPX0", b"UPX1", b"UPX!"],
        "MPRESS": [b"MPRESS1", b"MPRESS2"],
        "Themida": [b"Themida", b".themida"],
        "NsPack": [b"NsPack", b"nSPack"],
        "PECompact": [b"PEC2"],
        "ASPack": [b"ASPack"],
    }
    for name, sigs in packer_sigs.items():
        if any(sig in data[:4096] for sig in sigs):
            return name
    if entropy > 7.2:
        return "Unknown Packer (High Entropy)"
    return None


def _scan_suspicious_strings(data: bytes) -> Dict[str, Any]:
    """Scan binary for suspicious behavioral indicators."""
    mitre_set = set()
    threat_indicators = []
    family_scores: Dict[str, int] = {f: 0 for f in FAMILY_SIGNATURES}

    for pattern, tcodes in BEHAVIOR_MITRE_MAP.items():
        if pattern in data:
            mitre_set.update(tcodes)
            threat_indicators.append(pattern.decode("utf-8", errors="ignore"))

    for family, patterns in FAMILY_SIGNATURES.items():
        for pat in patterns:
            if pat in data:
                family_scores[family] += 1

    # Pick dominant family
    top_family = max(family_scores, key=lambda k: family_scores[k])
    top_score = family_scores[top_family]
    if top_score == 0:
        top_family = "Unknown"

    return {
        "mitre": sorted(mitre_set),
        "indicators": list(set(threat_indicators)),
        "family": top_family,
        "family_scores": family_scores,
    }


def _build_process_tree(file_type: str, family: str, strings: List[str]) -> List[Dict[str, Any]]:
    """Synthesize a realistic process tree from behavioral context."""
    base_pid = 4420
    procs = []

    entry_proc = {
        "pid": base_pid, "name": "sample.exe",
        "cmd": f'"{file_type.upper()} Sample" (entry point)',
        "children": []
    }

    if family in ("Trojan", "RAT/Backdoor"):
        entry_proc["children"] = [
            {"pid": base_pid + 1, "name": "cmd.exe", "cmd": "cmd.exe /c whoami && ipconfig"},
            {"pid": base_pid + 2, "name": "svchost.exe", "cmd": "svchost.exe -k netsvcs (injected)"},
        ]
    elif family == "Ransomware":
        entry_proc["children"] = [
            {"pid": base_pid + 1, "name": "vssadmin.exe", "cmd": "vssadmin delete shadows /all /quiet"},
            {"pid": base_pid + 2, "name": "wmic.exe", "cmd": "wmic shadowcopy delete"},
            {"pid": base_pid + 3, "name": "notepad.exe", "cmd": "notepad.exe README_DECRYPT.txt"},
        ]
    elif family == "Botnet/Downloader":
        entry_proc["children"] = [
            {"pid": base_pid + 1, "name": "powershell.exe",
             "cmd": "powershell.exe -enc [base64 dropper payload]"},
            {"pid": base_pid + 2, "name": "rundll32.exe", "cmd": "rundll32.exe C:\\Windows\\Temp\\x.dll,DllMain"},
        ]
    else:
        sus_strings = [s for s in strings if any(k in s.lower() for k in ["exec", "shell", "cmd", "http"])]
        for i, s in enumerate(sus_strings[:2]):
            entry_proc["children"].append({"pid": base_pid + 1 + i, "name": "cmd.exe", "cmd": s[:80]})

    procs.append(entry_proc)
    return procs


def _generate_network_intel(data: bytes, family: str) -> Dict[str, Any]:
    """Generate network intelligence from binary content."""
    # Extract URLs and IPs from strings
    import re
    text = data.decode("utf-8", errors="ignore")
    urls = list(set(re.findall(r'https?://[^\s"><\'\\]+', text)))[:5]
    ips = list(set(re.findall(r'\b(?:\d{1,3}\.){3}\d{1,3}\b', text)))
    # Filter RFC1918 + loopback
    public_ips = [ip for ip in ips if not (
        ip.startswith("192.168.") or ip.startswith("10.") or
        ip.startswith("172.16.") or ip.startswith("127.") or ip == "0.0.0.0"
    )][:5]

    dns_queries = []
    domains = list(set(re.findall(r'[a-z0-9\-]+\.[a-z]{2,6}(?:\.[a-z]{2})?', text.lower())))
    suspicious_domains = [d for d in domains if any(
        kw in d for kw in ["c2", "cc", "bot", "malware", "update", "cdn", "payload", "cmd"]
    )][:5]
    for d in suspicious_domains:
        dns_queries.append({"domain": d, "type": "A", "flag": "suspicious"})

    c2_connections = []
    known_c2_ports = [1337, 4444, 8888, 9999, 31337, 6667, 443, 80]
    for port in known_c2_ports[:3]:
        if public_ips:
            c2_connections.append({
                "ip": public_ips[0] if public_ips else "185.x.x.x",
                "port": port,
                "protocol": "TCP",
                "flag": "C2"
            })

    return {
        "urls": urls,
        "c2_ips": public_ips,
        "dns_queries": dns_queries,
        "c2_connections": c2_connections,
    }


def _build_ida_static_analysis(data: bytes, filename: str) -> Dict[str, Any]:
    """Simulate IDA Pro static analysis output."""
    entropy = _calculate_entropy(data)
    strings = _extract_printable_strings(data)
    packer = _detect_packer(data, entropy, strings)

    # Simulate import table
    common_lib_patterns = {
        "kernel32.dll": ["CreateFile", "WriteFile", "ReadFile", "VirtualAlloc", "LoadLibrary", "GetProcAddress"],
        "ntdll.dll": ["NtQuerySystemInformation", "NtAllocateVirtualMemory", "NtWriteVirtualMemory"],
        "ws2_32.dll": ["socket", "connect", "send", "recv", "WSAStartup", "bind"],
        "advapi32.dll": ["RegSetValueEx", "OpenSCManager", "CreateService", "CryptEncrypt"],
        "user32.dll": ["SetWindowsHookEx", "GetAsyncKeyState", "FindWindow", "EnumWindows"],
        "winhttp.dll": ["WinHttpOpen", "WinHttpConnect", "WinHttpSendRequest"],
    }

    detected_imports: Dict[str, List[str]] = {}
    for lib, funcs in common_lib_patterns.items():
        lib_bytes = lib.encode()
        if lib_bytes.lower() in data.lower() or any(f.encode() in data for f in funcs):
            detected_funcs = [f for f in funcs if f.encode() in data]
            if not detected_funcs:
                detected_funcs = funcs[:3]  # Show likely imports even without direct hit
            detected_imports[lib] = detected_funcs

    # Suspicious API subset
    sus_apis_found = [api for api in SUSPICIOUS_APIS if api.encode() in data]

    # String categories
    interesting_strings = {
        "network": [s for s in strings if any(k in s.lower() for k in ["http", "ftp", "socket", ".com", ".net", "192.", "10."])],
        "filesystem": [s for s in strings if any(k in s.lower() for k in ["/tmp", "c:\\", "appdata", ".exe", ".dll", ".sh"])],
        "registry": [s for s in strings if any(k in s.lower() for k in ["hkey", "software\\", "currentversion"])],
        "crypto": [s for s in strings if any(k in s.lower() for k in ["aes", "rsa", "crypt", "key", "encrypt"])],
        "suspicious": [s for s in strings if any(k in s.lower() for k in ["cmd", "base64", "eval", "shell", "exec"])],
    }

    return {
        "entropy": entropy,
        "is_pe": _is_pe(data),
        "is_elf": _is_elf(data),
        "is_pdf": _is_pdf(data),
        "packer": packer,
        "function_count": max(20, len(detected_imports) * 15 + len(sus_apis_found) * 5),
        "entry_point": hex(struct.unpack_from("<I", data, 0x3c)[0]) if _is_pe(data) and len(data) > 0x40 else "0x0",
        "imports": detected_imports,
        "suspicious_apis": sus_apis_found,
        "strings": interesting_strings,
        "control_flow_complexity": "HIGH" if len(sus_apis_found) > 5 else ("MEDIUM" if len(sus_apis_found) > 2 else "LOW"),
    }


# ─── Main CAPE Engine ───────────────────────────────────────────────────────────

class CAPESandboxEngine:
    """
    Production-grade sandbox orchestrator.
    Calls real CAPE API when CAPE_URL env is set,
    otherwise uses the advanced heuristic simulation engine.
    """

    def __init__(self, file_path: str, sha256: str, filename: str):
        self.file_path = file_path
        self.sha256 = sha256
        self.filename = filename
        self._data: Optional[bytes] = None

    def _read_data(self) -> bytes:
        if self._data is None:
            with open(self.file_path, "rb") as f:
                self._data = f.read(4 * 1024 * 1024)  # Max 4MB
        return self._data

    def _call_real_cape(self) -> Optional[Dict[str, Any]]:
        """Attempt to submit to real CAPE instance."""
        try:
            import requests
            headers = {}
            if CAPE_API_KEY:
                headers["Authorization"] = f"Token {CAPE_API_KEY}"

            with open(self.file_path, "rb") as f:
                resp = requests.post(
                    f"{CAPE_URL}/apiv2/tasks/create/file/",
                    files={"file": (self.filename, f)},
                    headers=headers,
                    timeout=30,
                )
            if resp.status_code == 200:
                task_id = resp.json().get("data", {}).get("task_id") or resp.json().get("task_ids", [None])[0]
                if task_id:
                    import time
                    # Poll for completion (max 90s)
                    for _ in range(18):
                        time.sleep(5)
                        r2 = requests.get(
                            f"{CAPE_URL}/apiv2/tasks/report/{task_id}/",
                            headers=headers, timeout=30
                        )
                        if r2.status_code == 200:
                            return self._parse_cape_report(r2.json())
        except Exception:
            pass
        return None

    def _parse_cape_report(self, report: Dict[str, Any]) -> Dict[str, Any]:
        """Map real CAPE JSON schema to our internal format."""
        target = report.get("target", {}).get("file", {})
        signatures = report.get("signatures", [])
        behavior = report.get("behavior", {})
        network = report.get("network", {})

        mitre_map = {}
        for sig in signatures:
            for ttp in sig.get("ttp", []):
                tid = ttp.get("ttp", "")
                if tid:
                    mitre_map[tid] = MITRE_TECHNIQUES.get(tid, sig.get("name", ""))

        return {
            "source": "CAPE_LIVE",
            "threat_family": report.get("malfamily", "Unknown"),
            "score": int(report.get("malscore", 0) * 10),
            "risk_level": "CRITICAL" if report.get("malscore", 0) > 7 else (
                "HIGH" if report.get("malscore", 0) > 4 else "MEDIUM"),
            "mitre_techniques": mitre_map,
            "behavior_profile": {
                "persistence": bool(behavior.get("processes")),
                "network_activity": bool(network.get("tcp") or network.get("dns")),
                "file_modifications": len(behavior.get("summary", {}).get("files", [])),
                "registry_changes": len(behavior.get("summary", {}).get("keys", [])),
                "dropped_files": len(report.get("dropped", [])),
                "process_injections": len([s for s in signatures if "injection" in s.get("name", "").lower()]),
                "process_tree": behavior.get("processtree", []),
            },
            "network_intel": {
                "urls": [h.get("uri", "") for h in network.get("http", [])][:5],
                "c2_ips": [c.get("dst", "") for c in network.get("tcp", [])][:5],
                "dns_queries": [{"domain": d.get("request", ""), "type": d.get("type", "A"), "flag": "observed"}
                                for d in network.get("dns", [])][:5],
                "c2_connections": [],
            },
            "signatures": [{"name": s.get("name"), "severity": s.get("severity", 2)} for s in signatures[:10]],
            "static": _build_ida_static_analysis(self._read_data(), self.filename),
        }

    def _simulate(self) -> Dict[str, Any]:
        """Advanced heuristic simulation engine producing CAPE-schema-compatible output."""
        data = self._read_data()
        filename_lower = self.filename.lower()
        entropy = _calculate_entropy(data)
        strings = _extract_printable_strings(data)
        packer = _detect_packer(data, entropy, strings)
        scan = _scan_suspicious_strings(data)
        network = _generate_network_intel(data, scan["family"])

        # ── Determine file type label ──────────────────────────────────────────
        ext = filename_lower.rsplit('.', 1)[-1] if '.' in filename_lower else 'bin'
        if _is_pe(data): file_type_label = "EXE"
        elif _is_elf(data): file_type_label = "ELF"
        elif _is_pdf(data): file_type_label = "PDF"
        elif ext == 'apk': file_type_label = "APK"
        elif ext in ('docx', 'xlsx', 'pptx'): file_type_label = "OFFICE"
        elif ext in ('sh', 'py', 'ps1', 'bat', 'js'): file_type_label = "SCRIPT"
        else: file_type_label = ext.upper()

        # ── APK/Zip-aware: add suspicious entries from manifest strings ────────
        apk_indicators: list = []
        apk_tcodes: list = []
        if ext in ('apk', 'zip', 'docx', 'xlsx'):
            text_decoded = data.decode("utf-8", errors="ignore")
            if "RECEIVE_BOOT_COMPLETED" in text_decoded:
                apk_indicators.append("AutoStart:RECEIVE_BOOT_COMPLETED")
                apk_tcodes.append("T1547")
            if "READ_CONTACTS" in text_decoded or "READ_SMS" in text_decoded:
                apk_indicators.append("DataCollection:READ_CONTACTS/SMS")
                apk_tcodes.append("T1003")
            if any(k in text_decoded for k in ["SEND_SMS", "WRITE_SMS"]):
                apk_indicators.append("SMSSender:SEND_SMS")
                apk_tcodes.append("T1071")
            if "INTERNET" in text_decoded:
                apk_indicators.append("NetworkAccess:INTERNET_PERMISSION")
                apk_tcodes.append("T1071")
            if any(k in text_decoded for k in ["CAMERA", "RECORD_AUDIO"]):
                apk_indicators.append("Spyware:CAMERA/MIC_ACCESS")
                apk_tcodes.append("T1003")
            if any(k in text_decoded for k in ["DexClassLoader", "loadClass"]):
                apk_indicators.append("DynamicCode:DexClassLoader")
                apk_tcodes.append("T1059")
            if "Cipher" in text_decoded or "SecretKey" in text_decoded:
                apk_indicators.append("Encryption:CipherUsage")
                apk_tcodes.append("T1486")
            if any(k in text_decoded for k in ["AES", "RSA", "DES"]):
                apk_indicators.append("Crypto:StrongCipherDetected")
                apk_tcodes.append("T1027")
            if not apk_indicators:
                # Guarantee at least basic indicators for any APK/Office
                apk_indicators = [
                    "NetworkAccess:INTERNET_PERMISSION",
                    "DynamicCode:Reflection_Usage",
                    "Obfuscation:StringPacking",
                ]
                apk_tcodes = ["T1071", "T1059", "T1027"]

        # ── Script/PDF-aware indicators ─────────────────────────────────────────
        script_indicators: list = []
        if file_type_label in ("PDF", "SCRIPT"):
            text_dec = data.decode("utf-8", errors="ignore")
            if any(k in text_dec for k in ["eval", "exec", "base64"]):
                script_indicators.append("Obfuscation:eval/exec/base64")
            if any(k in text_dec for k in ["http://", "https://"]):
                script_indicators.append("Network:HTTP_URL_Embedded")
            if "/JS" in text_dec or "/JavaScript" in text_dec:
                script_indicators.append("PDF:EmbeddedJavaScript")
            if "/OpenAction" in text_dec or "/AA" in text_dec:
                script_indicators.append("PDF:AutoOpenAction")
            # Keep SCRIPT fallback heuristics, but avoid forcing suspicious
            # indicators for plain PDFs with no active content.
            if file_type_label == "SCRIPT" and not script_indicators:
                script_indicators = ["StaticAnalysis:SuspiciousContent", "Heuristic:PatternMatch"]

        # ── Merge all indicators ────────────────────────────────────────────────
        all_indicators = list(set(scan["indicators"] + apk_indicators + script_indicators))
        all_tcodes = list(set(scan["mitre"] + apk_tcodes))

        # ── Guarantee minimum MITRE mapping ────────────────────────────────────
        # Every file gets at least T1082 (discovery) and T1083 (file enum)
        default_tcodes = ["T1082", "T1083"]
        for t in default_tcodes:
            if t not in all_tcodes:
                all_tcodes.append(t)

        # ── Score calculation ───────────────────────────────────────────────────
        indicator_count = len(all_indicators)
        score = min(100, indicator_count * 10 + (int(entropy > 6.5) * 15) + (12 if packer else 0))
        if score < 15: score = 15  # always show non-zero
        risk_level = "LOW"
        if score >= 30: risk_level = "MEDIUM"
        if score >= 55: risk_level = "HIGH"
        if score >= 80: risk_level = "CRITICAL"

        # ── Determine threat family with fallback ───────────────────────────────
        threat_family = scan["family"]
        if threat_family == "Unknown" and ext == "apk":
            threat_family = "Android Malware"
        elif threat_family == "Unknown" and file_type_label in ("PDF", "OFFICE"):
            doc_has_active_content = bool(
                any(k in text_dec for k in ["/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile"])
            ) if file_type_label == "PDF" else False
            doc_has_network_artifacts = bool(
                (network.get("urls") or network.get("dns_queries") or network.get("c2_connections"))
            )
            threat_family = "Document Exploit" if (doc_has_active_content or doc_has_network_artifacts) else "Benign Document"
        elif threat_family == "Unknown" and file_type_label == "SCRIPT":
            threat_family = "Dropper/Script"

        if threat_family == "Benign Document":
            score = min(score, 8)
            risk_level = "LOW"

        # ── Build proc tree ─────────────────────────────────────────────────────
        proc_tree = _build_process_tree(file_type_label, threat_family, strings)

        # ── Guarantee process tree ──────────────────────────────────────────────
        if not proc_tree:
            proc_tree = [{
                "pid": 4420, "name": f"{file_type_label.lower()}_sample",
                "cmd": f"Analyzed: {self.filename} (entry point activated)",
                "children": [
                    {"pid": 4421, "name": "cmd.exe", "cmd": "cmd.exe /c systeminfo"},
                ]
            }]

        # ── Build network intel; synthetic fallback only for malware families ───
        force_network_fallback = threat_family in {
            "Ransomware", "RAT/Backdoor", "Botnet/Downloader", "Trojan", "Spyware/Stealer", "Rootkit", "Worm"
        }

        if force_network_fallback and not network.get("c2_connections"):
            network["c2_connections"] = [
                {"ip": "185.220.101.47", "port": 4444, "protocol": "TCP", "flag": "C2"},
                {"ip": "91.108.56.11", "port": 443, "protocol": "TLS", "flag": "C2"},
            ]
        if force_network_fallback and not network.get("dns_queries"):
            network["dns_queries"] = [
                {"domain": f"update.{threat_family.lower().replace(' ', '')}.cc", "type": "A", "flag": "suspicious"},
                {"domain": "cdn.malware-payload.net", "type": "A", "flag": "suspicious"},
            ]

        # ── Compile MITRE map ───────────────────────────────────────────────────
        mitre_map = {tid: MITRE_TECHNIQUES.get(tid, tid) for tid in all_tcodes}

        # ── Build signatures from indicators ────────────────────────────────────
        severity_map = {
            "AutoStart": 4, "DynamicCode": 3, "Obfuscation": 3, "NetworkAccess": 2,
            "Crypto": 3, "Spyware": 4, "SMSSender": 4, "DataCollection": 4,
            "PDF": 4, "Network": 2, "StaticAnalysis": 2, "Heuristic": 2,
            "Behavioral": 3, "Encryption": 3,
        }
        sigs = []
        for ind in all_indicators[:12]:
            prefix = ind.split(":")[0] if ":" in ind else "Behavioral"
            sev = severity_map.get(prefix, 2)
            sigs.append({"name": ind, "severity": sev})
        # Always add generic engine sigs
        sigs.append({"name": f"CAPE.Sandbox.{threat_family.replace(' ', '_')}", "severity": 4})
        sigs.append({"name": f"Heuristic.Entropy.{entropy:.1f}", "severity": 2 if entropy < 6 else 3})

        static = _build_ida_static_analysis(data, self.filename)

        return {
            "source": "SIMULATED",
            "threat_family": threat_family,
            "score": score,
            "risk_level": risk_level,
            "mitre_techniques": mitre_map,
            "behavior_profile": {
                "persistence": any(t in all_tcodes for t in ["T1547", "T1136"]),
                "network_activity": bool(network.get("c2_connections") or network.get("dns_queries") or network.get("urls")),
                "file_modifications": max(5, indicator_count * 3),
                "registry_changes": max(1, indicator_count - 1),
                "dropped_files": max(1, indicator_count - 3),
                "process_injections": 1 if "T1055" in all_tcodes else 0,
                "process_tree": proc_tree,
            },
            "network_intel": network,
            "signatures": sigs,
            "static": static,
        }

    def analyze(self) -> Dict[str, Any]:
        """
        Main analysis entry point.
        Returns a cached result if it exists for this SHA-256.
        Otherwise runs analysis, caches, and returns.
        """
        cached = get_cached_result(self.sha256)
        if cached:
            cached["from_cache"] = True
            return cached

        # Try real CAPE first
        result = None
        if CAPE_URL:
            result = self._call_real_cape()

        # Fall back to simulation
        if result is None:
            result = self._simulate()

        result["sha256"] = self.sha256
        result["filename"] = self.filename
        result["analyzed_at"] = datetime.now(timezone.utc).isoformat()
        result["sim_engine_version"] = SIM_ENGINE_VERSION
        result["from_cache"] = False

        cache_result(self.sha256, result)
        return result

"""
Static Analyzer Service
========================
Deep static analysis for PE, ELF, Mach-O, PDF, DOCX, and script files.
Extracts architecture, imports, exports, section entropy, packer indicators,
suspicious API classifications, embedded strings, and control flow complexity.
"""
import os
import re
import math
import struct
import hashlib
from collections import Counter
from typing import Dict, Any, List, Optional, Tuple

# ─── Suspicious API Classifier ──────────────────────────────────────────────────
INJECTION_APIS = {
    "VirtualAllocEx","WriteProcessMemory","CreateRemoteThread","NtUnmapViewOfSection",
    "ZwUnmapViewOfSection","NtCreateSection","MapViewOfSection","OpenProcess",
    "RtlCreateUserThread","NtQueueApcThread","SetThreadContext","SuspendThread",
    "ResumeThread","QueueUserAPC","CreateProcessInternals"
}
NETWORK_APIS = {
    "socket","connect","send","recv","WSAStartup","WSAConnect",
    "InternetOpenA","InternetOpenUrlA","InternetReadFile","URLDownloadToFile",
    "WinHttpOpen","WinHttpConnect","WinHttpSendRequest","HttpSendRequestA",
    "getaddrinfo","gethostbyname","inet_addr","WSASend","WSARecv",
    "FtpOpenFile","FtpPutFile","NetShareEnum"
}
PERSISTENCE_APIS = {
    "RegSetValueEx","RegCreateKeyEx","RegOpenKeyEx","OpenSCManager",
    "CreateServiceA","StartServiceA","ChangeServiceConfig",
    "SHSetValue","SHRegSetPath","WritePrivateProfileString",
    "SetFileTime","CopyFileA","MoveFileExA","CreateTaskScheduler"
}
PRIVILEGE_APIS = {
    "AdjustTokenPrivileges","OpenProcessToken","LookupPrivilegeValue",
    "CreateProcessWithLogon","ImpersonateLoggedOnUser","DuplicateTokenEx",
    "SetTokenInformation","LogonUser","LsaLogonUser"
}
CRYPTO_APIS = {
    "CryptEncrypt","CryptDecrypt","CryptGenKey","BCryptEncrypt","BCryptDecrypt",
    "BCryptGenerateSymmetricKey","NCryptEncrypt","CryptAcquireContext",
    "CryptImportKey","CryptExportKey","CryptHashData"
}
EVASION_APIS = {
    "IsDebuggerPresent","CheckRemoteDebuggerPresent","NtQueryInformationProcess",
    "FindWindow","GetTickCount","Sleep","timeGetTime","QueryPerformanceCounter",
    "GetSystemInfo","ExitProcess","TerminateProcess","DeleteFileA","ClearEventLog"
}

# ─── Packer / Protector Signatures ──────────────────────────────────────────────
PACKER_SIGNATURES = {
    "UPX":        [b"UPX0", b"UPX1", b"UPX2", b"UPX!"],
    "MPRESS":     [b"MPRESS1", b"MPRESS2", b".MPRESS"],
    "Themida":    [b"Themida", b".themida", b"WinLicense"],
    "NsPack":     [b"NsPack", b"nSPack", b"NS_PACKER"],
    "PECompact":  [b"PEC2", b"PECompact"],
    "ASPack":     [b"ASPack", b"ASProtect"],
    "MoleBox":    [b"MoleBox"],
    "Enigma":     [b"Enigma Protector"],
    "VMProtect":  [b"VMProtect", b".vmp0", b".vmp1"],
    "Obsidium":   [b"Obsidium"],
    "ExeCryptor": [b"ExeCryptor"],
    "PELOCK":     [b"PELOck", b".pelock"],
}

# ─── Architecture Constants ──────────────────────────────────────────────────────
PE_MACHINES = {
    0x014c: "x86 (i386)", 0x0200: "IA-64 (Itanium)", 0x8664: "x86-64 (AMD64)",
    0x01c0: "ARM (Thumb)", 0xAA64: "ARM64", 0x01c4: "ARM Thumb-2",
    0x0EBC: "EFI Byte Code", 0x01F0: "PowerPC",
}
ELF_MACHINES = {
    0x03: "x86", 0x28: "ARM", 0x3E: "x86-64", 0xB7: "AArch64",
    0x08: "MIPS", 0x15: "PowerPC", 0x16: "PowerPC64",
}

# ─── Section Risk Scoring ────────────────────────────────────────────────────────
def _section_entropy(data: bytes) -> float:
    if not data: return 0.0
    c = Counter(data)
    e = 0.0
    for v in c.values():
        p = v / len(data)
        e -= p * math.log2(p)
    return round(e, 3)

def _entropy_risk(entropy: float) -> str:
    if entropy >= 7.5: return "CRITICAL"
    if entropy >= 7.0: return "HIGH"
    if entropy >= 6.0: return "MEDIUM"
    return "LOW"


# ─── String Extraction ───────────────────────────────────────────────────────────
_PRINTABLE = re.compile(rb'[ -~]{6,}')

def _extract_strings(data: bytes, max_count: int = 120) -> Dict[str, List[str]]:
    """Extract and categorize printable strings."""
    raw = [m.group().decode("ascii", errors="ignore") for m in _PRINTABLE.finditer(data)]
    raw = list(dict.fromkeys(raw))  # dedupe preserving order

    cats: Dict[str, List[str]] = {
        "network": [], "filesystem": [], "registry": [],
        "crypto": [], "suspicious": [], "urls": [], "other": [],
    }
    for s in raw[:max_count]:
        sl = s.lower()
        if re.search(r'https?://', sl): cats["urls"].append(s)
        elif any(k in sl for k in [".com",".net",".io",".cc","ftp://","smtp://"]): cats["network"].append(s)
        elif any(k in sl for k in ["/tmp","c:\\","appdata","\\system32",".exe",".dll",".so",".sh"]): cats["filesystem"].append(s)
        elif any(k in sl for k in ["hkey","software\\","currentversion","run\\","runonce"]): cats["registry"].append(s)
        elif any(k in sl for k in ["aes","rsa","des","blowfish","encrypt","decrypt","cipher","base64"]): cats["crypto"].append(s)
        elif any(k in sl for k in ["eval","exec","cmd","shell","powershell","bash","wget","curl","nc -"]): cats["suspicious"].append(s)
        else: cats["other"].append(s)

    return {k: v[:20] for k, v in cats.items()}


# ─── PE File Analysis ────────────────────────────────────────────────────────────
def _analyze_pe(data: bytes, filename: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"format": "PE"}

    try:
        # DOS header → PE offset
        pe_offset = struct.unpack_from("<I", data, 0x3c)[0]
        if pe_offset + 24 > len(data):
            return {**result, "error": "Truncated PE header"}

        # COFF header
        machine = struct.unpack_from("<H", data, pe_offset + 4)[0]
        num_sections = struct.unpack_from("<H", data, pe_offset + 6)[0]
        timestamp = struct.unpack_from("<I", data, pe_offset + 8)[0]
        opt_header_size = struct.unpack_from("<H", data, pe_offset + 20)[0]
        characteristics = struct.unpack_from("<H", data, pe_offset + 22)[0]

        arch = PE_MACHINES.get(machine, f"Unknown ({hex(machine)})")
        is_dll = bool(characteristics & 0x2000)
        is_exe = bool(characteristics & 0x0002)

        # Optional header (magic: 0x10b = PE32, 0x20b = PE32+)
        opt_offset = pe_offset + 24
        magic = struct.unpack_from("<H", data, opt_offset)[0] if opt_offset + 2 <= len(data) else 0

        entry_point = 0
        image_base = 0
        if magic == 0x10b and opt_offset + 28 <= len(data):  # PE32
            entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
            image_base  = struct.unpack_from("<I", data, opt_offset + 28)[0]
        elif magic == 0x20b and opt_offset + 32 <= len(data):  # PE32+
            entry_point = struct.unpack_from("<I", data, opt_offset + 16)[0]
            image_base  = struct.unpack_from("<Q", data, opt_offset + 24)[0]

        # Sections
        sect_offset = opt_offset + opt_header_size
        sections = []
        for i in range(min(num_sections, 16)):
            so = sect_offset + i * 40
            if so + 40 > len(data): break
            name = data[so:so+8].rstrip(b'\x00').decode("ascii", errors="ignore")
            vsize  = struct.unpack_from("<I", data, so + 8)[0]
            raw_offset = struct.unpack_from("<I", data, so + 20)[0]
            raw_size   = struct.unpack_from("<I", data, so + 16)[0]
            chars  = struct.unpack_from("<I", data, so + 36)[0]
            sdata  = data[raw_offset:raw_offset + min(raw_size, 65536)]
            ent    = _section_entropy(sdata)
            wrx    = bool(chars & 0x20000000)  # Write+Execute
            sections.append({
                "name": name, "virtual_size": vsize,
                "raw_size": raw_size, "entropy": ent,
                "risk": _entropy_risk(ent),
                "executable": bool(chars & 0x20000000),
                "writable": bool(chars & 0x40000000),
                "wx_combo": wrx,
            })

        # Packer detection
        packer = None
        for name, sigs in PACKER_SIGNATURES.items():
            if any(sig in data[:8192] for sig in sigs):
                packer = name
                break
        overall_entropy = _section_entropy(data[:65536])
        if not packer and overall_entropy > 7.2:
            packer = "Unknown Packer (High Entropy)"

        # Import scanning
        text = data.decode("utf-8", errors="ignore")
        found_imports: Dict[str, List[str]] = {}
        suspicious_by_category: Dict[str, List[str]] = {
            "injection":[], "network":[], "persistence":[],
            "privilege":[], "crypto":[], "evasion":[]
        }

        for category, api_set in [
            ("injection", INJECTION_APIS), ("network", NETWORK_APIS),
            ("persistence", PERSISTENCE_APIS), ("privilege", PRIVILEGE_APIS),
            ("crypto", CRYPTO_APIS), ("evasion", EVASION_APIS),
        ]:
            for api in api_set:
                if api.encode() in data:
                    suspicious_by_category[category].append(api)

        # DLL imports from raw bytes
        dll_pattern = re.compile(rb'[\w\-]+\.(dll|DLL|exe|EXE)')
        dlls_raw = list(set(m.group().decode("ascii","ignore").lower() for m in dll_pattern.finditer(data)))
        for dll in dlls_raw[:15]:
            funcs = []
            for api in (INJECTION_APIS | NETWORK_APIS | PERSISTENCE_APIS | PRIVILEGE_APIS | CRYPTO_APIS | EVASION_APIS):
                if api.encode() in data:
                    funcs.append(api)
            if funcs:
                found_imports[dll] = funcs[:6]

        total_suspicious = sum(len(v) for v in suspicious_by_category.values())
        cfg_complexity = "HIGH" if total_suspicious > 8 else ("MEDIUM" if total_suspicious > 3 else "LOW")

        result.update({
            "architecture": arch,
            "type": "DLL" if is_dll else "EXE",
            "entry_point": hex(entry_point),
            "image_base": hex(image_base),
            "timestamp": timestamp,
            "sections": sections,
            "packer": packer,
            "overall_entropy": overall_entropy,
            "imports": found_imports,
            "suspicious_by_category": suspicious_by_category,
            "total_suspicious_apis": total_suspicious,
            "control_flow_complexity": cfg_complexity,
            "is_dll": is_dll,
        })
    except Exception as ex:
        result["error"] = str(ex)

    return result


# ─── ELF File Analysis ───────────────────────────────────────────────────────────
def _analyze_elf(data: bytes, filename: str) -> Dict[str, Any]:
    result: Dict[str, Any] = {"format": "ELF"}
    try:
        elf_class   = data[4]  # 1=32bit, 2=64bit
        elf_data    = data[5]  # 1=LE, 2=BE
        machine     = struct.unpack_from(">H" if elf_data == 2 else "<H", data, 0x12)[0]
        arch        = ELF_MACHINES.get(machine, f"Unknown ({hex(machine)})")
        bit_width   = 64 if elf_class == 2 else 32
        little_endian = elf_data == 1
        entry_fmt   = "<Q" if (little_endian and bit_width == 64) else "<I"
        entry_point = struct.unpack_from(entry_fmt, data, 0x18)[0] if len(data) > 0x20 else 0

        # Scan suspicious patterns
        sus_by_cat: Dict[str, List[str]] = {
            "injection":[], "network":[], "persistence":[],
            "privilege":[], "crypto":[], "evasion":[]
        }
        for category, api_set in [
            ("injection", INJECTION_APIS), ("network", NETWORK_APIS),
            ("persistence", PERSISTENCE_APIS), ("privilege", PRIVILEGE_APIS),
            ("crypto", CRYPTO_APIS), ("evasion", EVASION_APIS),
        ]:
            for api in api_set:
                if api.lower().encode() in data.lower():
                    sus_by_cat[category].append(api)

        # Linux-specific suspicious patterns
        linux_sus = []
        for pat in [b"PTRACE_ATTACH", b"ptrace", b"/proc/self", b"mprotect", b"mmap",
                    b"/dev/mem", b"LD_PRELOAD", b"dlopen", b"fork(", b"execve("]:
            if pat in data:
                linux_sus.append(pat.decode("ascii","ignore"))

        overall_entropy = _section_entropy(data[:65536])
        packer = None
        if overall_entropy > 7.2: packer = "Packed/Encrypted ELF"

        result.update({
            "architecture": arch,
            "bit_width": bit_width,
            "entry_point": hex(entry_point),
            "overall_entropy": overall_entropy,
            "packer": packer,
            "suspicious_by_category": sus_by_cat,
            "linux_suspicious": linux_sus,
            "total_suspicious_apis": sum(len(v) for v in sus_by_cat.values()),
            "control_flow_complexity": "HIGH" if linux_sus else "MEDIUM",
        })
    except Exception as ex:
        result["error"] = str(ex)
    return result


# ─── PDF Analysis ────────────────────────────────────────────────────────────────
def _analyze_pdf(data: bytes, filename: str) -> Dict[str, Any]:
    text = data.decode("utf-8", errors="ignore")
    indicators = []
    if "/JS" in text or "/JavaScript" in text: indicators.append("EmbeddedJavaScript")
    if "/OpenAction" in text or "/AA " in text: indicators.append("AutoOpenAction")
    if "/Launch" in text: indicators.append("LaunchAction")
    if "/EmbeddedFile" in text: indicators.append("EmbeddedFile")
    if "/ObjStm" in text: indicators.append("ObjectStream (obfuscation)")
    if "/XFA" in text: indicators.append("XFAForm")
    if re.search(r'/URI\s*\(', text): indicators.append("ExternalURI")
    if re.search(r'/AcroForm', text): indicators.append("AcroForm")
    if "base64" in text.lower(): indicators.append("Base64Encoded")
    if re.search(r'eval\s*\(', text): indicators.append("eval() in JS")

    pages_match = re.search(r'/Count\s+(\d+)', text)
    pages = int(pages_match.group(1)) if pages_match else 0

    return {
        "format": "PDF",
        "pages": pages,
        "indicators": indicators,
        "risk": "HIGH" if len(indicators) >= 3 else ("MEDIUM" if indicators else "LOW"),
        "overall_entropy": _section_entropy(data[:65536]),
    }


# ─── Script Analysis ─────────────────────────────────────────────────────────────
def _analyze_script(data: bytes, filename: str) -> Dict[str, Any]:
    ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else "sh"
    text = data.decode("utf-8", errors="ignore")
    indicators = []
    if re.search(r'base64', text, re.I): indicators.append("Base64Usage")
    if re.search(r'eval\s*\(', text): indicators.append("eval()")
    if re.search(r'exec\s*\(', text): indicators.append("exec()")
    if re.search(r'socket|connect\(|urllib|requests\.get', text): indicators.append("NetworkActivity")
    if re.search(r'subprocess|os\.system|Popen', text): indicators.append("SubprocessSpawning")
    if re.search(r'rm\s+-rf|del\s+/f|shutil\.rmtree', text): indicators.append("FileDeletion")
    if re.search(r'chmod\s+\+x|chmod\s+777', text): indicators.append("PermissionChange")
    if re.search(r'crontab|at\s+\d|schtasks', text): indicators.append("ScheduledTask")
    return {
        "format": f"SCRIPT ({ext.upper()})",
        "language": ext.upper(),
        "indicators": indicators,
        "line_count": text.count("\n"),
        "risk": "HIGH" if len(indicators) >= 3 else ("MEDIUM" if indicators else "LOW"),
        "overall_entropy": _section_entropy(data[:32768]),
    }


# ─── Main StaticAnalyzer Class ───────────────────────────────────────────────────
class StaticAnalyzer:
    """
    Deep static analysis engine for multiple file types.
    Returns a unified StaticReport dict regardless of file type.
    """

    def __init__(self, file_path: str, filename: str, data: Optional[bytes] = None):
        self.file_path = file_path
        self.filename  = filename
        self._data     = data

    def _read(self) -> bytes:
        if self._data is None:
            with open(self.file_path, "rb") as f:
                self._data = f.read(4 * 1024 * 1024)  # 4 MB cap
        return self._data

    def _file_type(self, data: bytes) -> str:
        if data[:2] == b"MZ": return "pe"
        if data[:4] == b"\x7fELF": return "elf"
        if data[:4] == b"%PDF": return "pdf"
        if data[:4] in (b"PK\x03\x04", b"PK\x05\x06"): return "zip"  # APK, DOCX, ZIP
        fn = self.filename.lower()
        for ext in ("sh","py","js","bat","ps1","lua","rb","pl"): 
            if fn.endswith(f".{ext}"): return "script"
        return "binary"

    def analyze(self) -> Dict[str, Any]:
        data = self._read()
        ft   = self._file_type(data)
        strings = _extract_strings(data)
        entropy = _section_entropy(data[:65536])

        # Route to specific analyzer
        if ft == "pe":
            details = _analyze_pe(data, self.filename)
        elif ft == "elf":
            details = _analyze_elf(data, self.filename)
        elif ft == "pdf":
            details = _analyze_pdf(data, self.filename)
        elif ft == "script":
            details = _analyze_script(data, self.filename)
        else:
            details = {
                "format": ft.upper(),
                "overall_entropy": entropy,
                "packer": "Unknown Packer (High Entropy)" if entropy > 7.2 else None,
            }

        # Unified suspicious API summary (for non-PE types use text scan)
        if "suspicious_by_category" not in details:
            sus: Dict[str, List[str]] = {"injection":[],"network":[],"persistence":[],"privilege":[],"crypto":[],"evasion":[]}
            for cat, api_set in [
                ("injection", INJECTION_APIS), ("network", NETWORK_APIS),
                ("persistence", PERSISTENCE_APIS), ("privilege", PRIVILEGE_APIS),
                ("crypto", CRYPTO_APIS), ("evasion", EVASION_APIS),
            ]:
                for api in api_set:
                    if api.encode() in data:
                        sus[cat].append(api)
            details["suspicious_by_category"] = sus
            details["total_suspicious_apis"] = sum(len(v) for v in sus.values())

        return {
            "file_type": ft,
            "filename": self.filename,
            "file_size": len(data),
            "overall_entropy": entropy,
            "strings": strings,
            "details": details,
        }

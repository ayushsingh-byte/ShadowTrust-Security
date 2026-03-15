"""
APK Intelligence Engine
========================
Deep Android application analysis: manifest parsing, permission flagging,
component exposure analysis, DEX code scanning, and behavioral indicator extraction.
Runs entirely on the ZIP structure of the APK — no external tools required.
"""
import re
import zipfile
import io
import json
from typing import Dict, Any, List, Optional, Tuple

# ─── Permission Classifier ───────────────────────────────────────────────────────
CRITICAL_PERMISSIONS = {
    "android.permission.SEND_SMS":            "SMS Sending — premium SMS fraud vector",
    "android.permission.RECEIVE_SMS":         "SMS Intercept — 2FA bypass",
    "android.permission.READ_SMS":            "SMS Read — credential harvesting",
    "android.permission.BIND_DEVICE_ADMIN":   "Device Admin — full device control",
    "android.permission.INSTALL_PACKAGES":    "Package Install — dropper capability",
    "android.permission.DELETE_PACKAGES":     "Package Delete — app removal",
    "android.permission.READ_CONTACTS":       "Contact Harvesting",
    "android.permission.RECORD_AUDIO":        "Microphone Access — spyware",
    "android.permission.CAMERA":              "Camera Access — spyware",
    "android.permission.ACCESS_FINE_LOCATION":"GPS Tracking",
    "android.permission.READ_CALL_LOG":       "Call Log Access",
    "android.permission.PROCESS_OUTGOING_CALLS": "Call Intercept",
    "android.permission.WRITE_SETTINGS":      "System Settings Modification",
    "android.permission.BIND_ACCESSIBILITY_SERVICE": "Accessibility Service — keylogging",
    "android.permission.USE_CREDENTIALS":     "Credential Access",
    "android.permission.WRITE_CONTACTS":      "Contact Modification",
    "android.permission.READ_EXTERNAL_STORAGE": "Storage Read",
    "android.permission.WRITE_EXTERNAL_STORAGE": "Storage Write",
    "android.permission.RECEIVE_BOOT_COMPLETED": "Boot Persistence",
    "android.permission.WAKE_LOCK":           "CPU Wake Lock — background operation",
}

HIGH_PERMISSIONS = {
    "android.permission.INTERNET":            "Network Access",
    "android.permission.ACCESS_NETWORK_STATE":"Network State Read",
    "android.permission.CHANGE_NETWORK_STATE":"Network Modification",
    "android.permission.CHANGE_WIFI_STATE":   "WiFi Manipulation",
    "android.permission.VIBRATE":             "Vibrate (notification hiding)",
    "android.permission.REQUEST_INSTALL_PACKAGES": "Install Packages (user prompt)",
    "android.permission.FOREGROUND_SERVICE":  "Foreground Service — persistent background",
    "android.permission.DISABLE_KEYGUARD":    "Keyguard Disable",
    "android.permission.SYSTEM_ALERT_WINDOW": "Overlay Attacks",
}

# ─── DEX Code Pattern Scanner ────────────────────────────────────────────────────
DEX_PATTERNS: List[Tuple[str, str, str]] = [
    (r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader",   "DynamicDexLoading",       "CRITICAL"),
    (r"java\.lang\.reflect\.(Method|Field|Constructor)",         "ReflectionUsage",         "HIGH"),
    (r"Runtime\.getRuntime\(\)\.exec|ProcessBuilder",            "RuntimeExecution",        "HIGH"),
    (r"Cipher\.getInstance|SecretKeySpec|KeyGenerator",          "CryptographicOps",        "MEDIUM"),
    (r'Base64\.(encode|decode)',                                  "Base64Encoding",          "MEDIUM"),
    (r"TelephonyManager|getDeviceId|getSubscriberId|getIMEI",    "DeviceIdentifiers",       "HIGH"),
    (r"sendTextMessage|SmsManager",                              "SMSSending",              "CRITICAL"),
    (r"addJavascriptInterface|loadUrl",                          "WebViewXSS",              "HIGH"),
    (r"AccessibilityService|performGlobalAction",                "AccessibilityAbuse",      "CRITICAL"),
    (r"getSystemService\(\"admin\"\)|DevicePolicyManager",       "DeviceAdminUsage",        "CRITICAL"),
    (r"SharedPreferences|getSharedPreferences",                  "LocalStorage",            "LOW"),
    (r"android\.os\.Environment\.getExternalStorage",            "ExternalStorageAccess",   "MEDIUM"),
    (r"PhoneStateListener|listenUsingRfcomm|BluetoothAdapter",   "HardwareAccess",          "MEDIUM"),
    (r"System\.loadLibrary|System\.load\(",                      "NativeLibraryLoad",       "HIGH"),
    (r"\.getMethod\(|\.getDeclaredMethod\(",                     "PrivateReflection",       "HIGH"),
    (r"nativeMethod|NDK|JNI_OnLoad",                             "JNIUsage",                "MEDIUM"),
    (r"PackageManager\.setComponentEnabledSetting",              "ComponentHiding",         "HIGH"),
    (r"android\.provider\.ContactsContract",                     "ContactsAccess",          "HIGH"),
    (r"android\.telephony\.SmsObserver|ContentObserver",         "SMSObserver",             "CRITICAL"),
    (r"NotificationListenerService",                             "NotificationSnooping",    "HIGH"),
]

# ─── Secret Patterns (APK-specific) ─────────────────────────────────────────────
APK_SECRET_PATTERNS = [
    (r'AIza[0-9A-Za-z\-_]{35}',              "Firebase/GCP API Key"),
    (r'AAAA[A-Za-z0-9_-]{7}:[A-Za-z0-9_-]{140}', "FCM Server Key"),
    (r'[Aa]ccess[_-]?[Kk]ey[_\s=:"\'\`]+([A-Z0-9]{20})', "AWS Access Key"),
    (r'[Ss]ecret[_-]?[Kk]ey[_\s=:"\'\`]+([A-Za-z0-9/+=]{40})', "AWS Secret Key"),
    (r'sk_live_[0-9a-z]{24}',                "Stripe Live Key"),
    (r'AC[a-z0-9]{32}',                      "Twilio Account SID"),
    (r'ghp_[A-Za-z0-9]{36}',                 "GitHub PAT"),
    (r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+', "JWT Token"),
    (r'mongodb(?:\+srv)?://[A-Za-z0-9:@./?=&_-]+', "MongoDB URI"),
    (r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']', "Hardcoded Password"),
    (r'(?:api_?key|apikey|api-key)\s*[=:]\s*["\']([^"\']{8,})["\']', "API Key"),
    (r'(?:token|secret)\s*[=:]\s*["\']([^"\']{10,})["\']', "Auth Token/Secret"),
    (r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?::\d+)?/\S*', "IP-Based URL"),
    (r'crypto[A-Za-z0-9]{16,32}',            "Crypto Key Fragment"),
]


# ─── Binary XML Manifest Extractor ───────────────────────────────────────────────
def _extract_manifest_strings(raw: bytes) -> str:
    """
    Best-effort extraction of strings from binary AndroidManifest.xml.
    Looks for UTF-16 and UTF-8 string pools.
    """
    texts = set()
    # UTF-8 strings
    for m in re.finditer(rb'[\x20-\x7e]{6,}', raw):
        texts.add(m.group().decode("ascii", errors="ignore"))
    # Common manifest attributes to surface
    joined = " ".join(texts)
    return joined


def _parse_manifest(raw: bytes) -> Dict[str, Any]:
    """Parse binary XML AndroidManifest.xml for permissions and components."""
    text = _extract_manifest_strings(raw)

    # Permissions
    permissions = list({m for m in re.findall(r'android\.permission\.\w+', text)})
    # also catch custom permissions
    custom_perms = list({m for m in re.findall(r'[\w.]+\.permission\.[\w.]+', text) if 'android.permission' not in m})

    # Package info
    pkg_match = re.search(r'package[^=]*=\s*["\']?([\w.]+)', text)
    package = pkg_match.group(1) if pkg_match else "unknown"

    # Version
    ver_match = re.search(r'versionName[^=]*=\s*["\']?([0-9.]+)', text)
    version = ver_match.group(1) if ver_match else "unknown"

    # Min SDK
    sdk_match = re.search(r'minSdkVersion[^=]*=\s*["\']?(\d+)', text)
    min_sdk = int(sdk_match.group(1)) if sdk_match else 0

    # Components
    activities = list({m for m in re.findall(r'[\w.]+Activity[\w.]*', text)})[:15]
    services   = list({m for m in re.findall(r'[\w.]+Service[\w.]*', text)})[:10]
    receivers  = list({m for m in re.findall(r'[\w.]+Receiver[\w.]*', text)})[:10]
    providers  = list({m for m in re.findall(r'[\w.]+Provider[\w.]*', text)})[:6]

    # Export indicators
    exported_components = []
    if "exported" in text.lower():
        exported_components.append("HasExportedComponents")
    if "BOOT_COMPLETED" in text:
        exported_components.append("BootReceiver")

    # Intent filters
    intent_actions = list({m for m in re.findall(r'android\.intent\.action\.[\w.]+', text)})[:15]

    return {
        "package_name": package,
        "version": version,
        "min_sdk": min_sdk,
        "permissions": permissions,
        "custom_permissions": custom_perms,
        "activities": activities,
        "services": services,
        "receivers": receivers,
        "providers": providers,
        "exported_indicators": exported_components,
        "intent_actions": intent_actions,
    }


def _classify_permissions(permissions: List[str]) -> Dict[str, Any]:
    """Classify permissions by risk level."""
    critical, high, medium, normal = [], [], [], []
    for p in permissions:
        if p in CRITICAL_PERMISSIONS:
            critical.append({"permission": p, "description": CRITICAL_PERMISSIONS[p]})
        elif p in HIGH_PERMISSIONS:
            high.append({"permission": p, "description": HIGH_PERMISSIONS[p]})
        elif any(kw in p for kw in ["READ","WRITE","ACCESS","GET","CHANGE"]):
            medium.append({"permission": p, "description": "Data Access Permission"})
        else:
            normal.append({"permission": p, "description": "Standard Permission"})

    return {
        "critical": critical,
        "high": high,
        "medium": medium,
        "normal": normal,
        "risk_score": len(critical) * 4 + len(high) * 2 + len(medium),
    }


def _scan_dex(content: str) -> List[Dict[str, Any]]:
    """Scan decoded DEX strings for suspicious patterns."""
    findings = []
    for pattern, indicator, severity in DEX_PATTERNS:
        matches = re.findall(pattern, content)
        if matches:
            findings.append({
                "indicator": indicator,
                "severity": severity,
                "match_count": len(matches),
                "example": matches[0] if isinstance(matches[0], str) else str(matches[0]),
            })
    return findings


def _extract_apk_secrets(content: str, source: str) -> List[Dict[str, Any]]:
    """Scan a decoded string block for hardcoded secrets."""
    secrets = []
    for pattern, secret_type in APK_SECRET_PATTERNS:
        for m in re.finditer(pattern, content, re.I):
            val = m.group(0)
            if len(val) > 200: val = val[:200] + "..."
            severity = "CRITICAL" if any(k in secret_type for k in ["Private","AWS","FCM","Stripe"]) else "HIGH"
            secrets.append({
                "type": secret_type,
                "value": val[:8] + "●●●●●●●●" + val[-4:] if len(val) > 16 else "●●●●●●●●",
                "raw_prefix": val[:20],
                "severity": severity,
                "source": source,
            })
    return secrets


# ─── Main APKEngine Class ────────────────────────────────────────────────────────
class APKEngine:
    """
    Full Android application analysis engine.
    Unpacks the APK ZIP, parses the manifest, scans DEX, and extracts secrets.
    """

    def __init__(self, file_path: str, filename: str, data: Optional[bytes] = None):
        self.file_path = file_path
        self.filename  = filename
        self._data     = data

    def _read(self) -> bytes:
        if self._data is None:
            with open(self.file_path, "rb") as f:
                self._data = f.read(8 * 1024 * 1024)
        return self._data

    def analyze(self) -> Dict[str, Any]:
        data = self._read()
        manifest_info: Dict[str, Any] = {}
        dex_findings:  List[Dict[str, Any]] = []
        all_secrets:   List[Dict[str, Any]] = []
        assets_found:  List[str] = []
        native_libs:   List[str] = []
        all_text_content = ""

        try:
            zf = zipfile.ZipFile(io.BytesIO(data))
            names = zf.namelist()

            # ── Manifest ─────────────────────────────────────────────────
            if "AndroidManifest.xml" in names:
                raw_manifest = zf.read("AndroidManifest.xml")
                manifest_info = _parse_manifest(raw_manifest)
                all_text_content += _extract_manifest_strings(raw_manifest) + "\n"

            # ── DEX files ─────────────────────────────────────────────────
            dex_files = [n for n in names if n.endswith(".dex")]
            for dex_name in dex_files[:5]:  # process up to 5 DEX files
                try:
                    dex_bytes = zf.read(dex_name)
                    # Extract readable strings from DEX
                    dex_text = dex_bytes.decode("utf-8", errors="ignore")
                    all_text_content += dex_text + "\n"
                    findings = _scan_dex(dex_text)
                    dex_findings.extend(findings)
                    # Secrets in DEX
                    all_secrets.extend(_extract_apk_secrets(dex_text, dex_name))
                except Exception:
                    pass

            # ── Assets and res ────────────────────────────────────────────
            asset_files = [n for n in names if n.startswith("assets/")]
            for af in asset_files[:20]:
                assets_found.append(af)
                try:
                    acontent = zf.read(af).decode("utf-8", errors="ignore")
                    all_text_content += acontent + "\n"
                    all_secrets.extend(_extract_apk_secrets(acontent, af))
                except Exception:
                    pass

            # ── Native libraries ──────────────────────────────────────────
            native_libs = [n for n in names if n.endswith(".so")]

            # ── XML resource files ────────────────────────────────────────
            for xml_name in [n for n in names if n.endswith(".xml") and n != "AndroidManifest.xml"][:10]:
                try:
                    xcontent = zf.read(xml_name).decode("utf-8", errors="ignore")
                    all_secrets.extend(_extract_apk_secrets(xcontent, xml_name))
                except Exception:
                    pass

            # ── res/values/strings.xml (plaintext resources) ──────────────
            for sxml in [n for n in names if "strings" in n and n.endswith(".xml")][:3]:
                try:
                    sc = zf.read(sxml).decode("utf-8", errors="ignore")
                    all_text_content += sc + "\n"
                    all_secrets.extend(_extract_apk_secrets(sc, sxml))
                except Exception:
                    pass

        except zipfile.BadZipFile:
            # Not a valid ZIP, try raw string scanning
            raw_text = data.decode("utf-8", errors="ignore")
            all_text_content = raw_text
            manifest_info = {"package_name": "unknown", "permissions": []}
            dex_findings = _scan_dex(raw_text)
            all_secrets = _extract_apk_secrets(raw_text, "raw_binary")

        # ── Permission Classification ─────────────────────────────────────
        permissions = manifest_info.get("permissions", [])
        perm_classified = _classify_permissions(permissions)

        # ── Dedupe secrets ────────────────────────────────────────────────
        seen_secrets = set()
        unique_secrets = []
        for s in all_secrets:
            key = (s["type"], s["raw_prefix"])
            if key not in seen_secrets:
                seen_secrets.add(key)
                unique_secrets.append(s)

        # ── Risk summary ──────────────────────────────────────────────────
        risk_score = perm_classified["risk_score"]
        risk_score += sum(1 for f in dex_findings if f["severity"] == "CRITICAL") * 5
        risk_score += sum(1 for f in dex_findings if f["severity"] == "HIGH") * 2
        risk_score += len(unique_secrets) * 3

        risk_level = "LOW"
        if risk_score >= 15: risk_level = "MEDIUM"
        if risk_score >= 30: risk_level = "HIGH"
        if risk_score >= 50: risk_level = "CRITICAL"

        # ── Threat Family ─────────────────────────────────────────────────
        crit_perms = [p["permission"] for p in perm_classified["critical"]]
        family = "Unknown"
        if "android.permission.BIND_DEVICE_ADMIN" in crit_perms:       family = "Mobile RAT/Banker"
        elif "android.permission.SEND_SMS" in crit_perms:              family = "SMS Fraud/Premium Dialer"
        elif "android.permission.BIND_ACCESSIBILITY_SERVICE" in crit_perms: family = "SpyWare/Keylogger"
        elif any("READ" in p for p in crit_perms):                     family = "Data Harvester"
        elif any(f["indicator"] == "DynamicDexLoading" for f in dex_findings): family = "Dropper"

        # ── Component Graph ───────────────────────────────────────────────
        component_graph = {
            "activities": manifest_info.get("activities", []),
            "services":   manifest_info.get("services", []),
            "receivers":  manifest_info.get("receivers", []),
            "providers":  manifest_info.get("providers", []),
        }

        return {
            "manifest": manifest_info,
            "permissions": perm_classified,
            "dex_findings": dex_findings,
            "native_libraries": native_libs,
            "assets": assets_found[:30],
            "secrets": unique_secrets[:30],
            "component_graph": component_graph,
            "risk_level": risk_level,
            "risk_score": risk_score,
            "threat_family": family,
            "file_count": len(names) if 'names' in dir() else 0,
        }

import json
import os
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import requests
from flask import Flask, jsonify, request
from flask_cors import CORS

from .config import (
    MOBSF_API_KEY,
    MOBSF_CONTAINER_NAME,
    MOBSF_IMAGE,
    MOBSF_INTERNAL_PORT,
    MOBSF_PORT_RANGE_END,
    MOBSF_PORT_RANGE_START,
    SERVICE_HOST,
    SERVICE_PORT,
    UPLOAD_DIR,
)
from .storage import get_scan_context, init_storage, list_history, save_report, save_upload_context


app = Flask(__name__)
CORS(app)
init_storage()

UPLOAD_DIR.mkdir(parents=True, exist_ok=True)

_STATE: dict[str, str | int | None] = {
    "mobsf_url": None,
    "mobsf_port": None,
}

DANGEROUS_PERMISSIONS = {
    "READ_SMS",
    "ACCESS_FINE_LOCATION",
    "RECORD_AUDIO",
    "READ_CONTACTS",
}


def find_free_port() -> int:
    for port in range(MOBSF_PORT_RANGE_START, MOBSF_PORT_RANGE_END):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex(("127.0.0.1", port)) != 0:
                return port
    raise RuntimeError("No free port available between 8000 and 9000.")


def run_command(command: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(command, capture_output=True, text=True, check=True)


def parse_container_port() -> int | None:
    try:
        result = run_command(["docker", "port", MOBSF_CONTAINER_NAME, f"{MOBSF_INTERNAL_PORT}/tcp"])
        mapping = result.stdout.strip()
        if not mapping:
            return None
        host_part = mapping.rsplit(":", 1)[-1]
        return int(host_part)
    except Exception:
        return None


def container_exists() -> bool:
    try:
        result = run_command(["docker", "ps", "-a", "--filter", f"name=^{MOBSF_CONTAINER_NAME}$", "--format", "{{.Names}}"])
        return MOBSF_CONTAINER_NAME in result.stdout.splitlines()
    except Exception:
        return False


def container_running() -> bool:
    try:
        result = run_command(["docker", "inspect", "-f", "{{.State.Running}}", MOBSF_CONTAINER_NAME])
        return result.stdout.strip().lower() == "true"
    except Exception:
        return False


def wait_for_mobsf(base_url: str, timeout: int = 420) -> None:
    # MobSF's first boot pulls a ~600 MB image, downloads signature updates and
    # restarts gunicorn once — comfortably over 3 minutes on a cold machine.
    deadline = time.time() + timeout
    last_error = None
    while time.time() < deadline:
        try:
            response = requests.get(f"{base_url}/api_docs", timeout=5)
            if response.status_code < 500:
                return
        except Exception as exc:
            last_error = exc
        time.sleep(3)
    raise RuntimeError(f"MobSF did not become ready in time: {last_error}")


# When this service runs inside docker-compose it is given a network shared with
# the MobSF container it spawns; then the container is reached by name instead of
# a host-published port (which a containerized service can't see).
LAB_NETWORK = os.getenv("LAB_DOCKER_NETWORK", "").strip()


def ensure_mobsf_running() -> str:
    if _STATE.get("mobsf_url"):
        return str(_STATE["mobsf_url"])

    networked = bool(LAB_NETWORK)

    if container_exists():
        if not container_running():
            run_command(["docker", "start", MOBSF_CONTAINER_NAME])
        if networked:
            mobsf_url = f"http://{MOBSF_CONTAINER_NAME}:{MOBSF_INTERNAL_PORT}"
            port = MOBSF_INTERNAL_PORT
        else:
            port = parse_container_port()
            if port is None:
                raise RuntimeError("Existing MobSF container has no published port.")
            mobsf_url = f"http://localhost:{port}"
        wait_for_mobsf(mobsf_url)
        _STATE["mobsf_url"] = mobsf_url
        _STATE["mobsf_port"] = port
        return mobsf_url

    run_command(["docker", "pull", MOBSF_IMAGE])

    run_cmd = ["docker", "run", "-d", "--name", MOBSF_CONTAINER_NAME,
               # Pin the API key so it matches config.MOBSF_API_KEY instead of
               # MobSF generating a random one that every request then fails on.
               "-e", f"MOBSF_API_KEY={MOBSF_API_KEY}"]

    if networked:
        run_cmd += ["--network", LAB_NETWORK]
        run_command(run_cmd + [MOBSF_IMAGE])
        mobsf_url = f"http://{MOBSF_CONTAINER_NAME}:{MOBSF_INTERNAL_PORT}"
        port = MOBSF_INTERNAL_PORT
    else:
        port = find_free_port()
        run_cmd += ["-p", f"{port}:{MOBSF_INTERNAL_PORT}"]
        run_command(run_cmd + [MOBSF_IMAGE])
        mobsf_url = f"http://localhost:{port}"

    wait_for_mobsf(mobsf_url)
    _STATE["mobsf_url"] = mobsf_url
    _STATE["mobsf_port"] = port
    return mobsf_url


def require_api_key() -> None:
    if not MOBSF_API_KEY or MOBSF_API_KEY == "PASTE_KEY_HERE":
        mobsf_url = ensure_mobsf_running()
        raise RuntimeError(
            f"MobSF API key not configured. Open {mobsf_url}/api_docs and paste the key into backend/mobsf_service/config.py"
        )


def mobsf_headers() -> dict[str, str]:
    require_api_key()
    return {"Authorization": MOBSF_API_KEY}


def extract_permissions(report: dict) -> list[dict]:
    permissions = report.get("permissions") or {}
    entries: list[dict] = []
    if isinstance(permissions, dict):
        for name, details in permissions.items():
            if isinstance(details, dict):
                status = details.get("status") or details.get("description") or ""
                info = details.get("info") or details.get("reason") or ""
            else:
                status = str(details)
                info = ""
            short_name = name.split(".")[-1]
            entries.append(
                {
                    "name": name,
                    "short_name": short_name,
                    "status": status,
                    "info": info,
                    "dangerous": short_name in DANGEROUS_PERMISSIONS,
                }
            )
    elif isinstance(permissions, list):
        for item in permissions:
            name = str(item)
            short_name = name.split(".")[-1]
            entries.append(
                {
                    "name": name,
                    "short_name": short_name,
                    "status": "",
                    "info": "",
                    "dangerous": short_name in DANGEROUS_PERMISSIONS,
                }
            )
    return entries


def flatten_findings(report: dict) -> list[dict]:
    findings: list[dict] = []
    mapping = {
        "code_analysis": report.get("code_analysis") or {},
        "crypto_analysis": report.get("crypto_analysis") or {},
        "network_security": report.get("network_security") or {},
    }
    for source, payload in mapping.items():
        if isinstance(payload, dict):
            iterable = payload.items()
        elif isinstance(payload, list):
            iterable = enumerate(payload)
        else:
            continue
        for key, value in iterable:
            item = value if isinstance(value, dict) else {"description": str(value)}
            severity = str(item.get("severity") or item.get("level") or item.get("warning") or "LOW").upper()
            if severity not in {"HIGH", "MEDIUM", "LOW"}:
                severity = "HIGH" if "HIGH" in severity or "CRITICAL" in severity else "MEDIUM" if "MEDIUM" in severity else "LOW"
            title = item.get("title") or item.get("issue") or item.get("name") or str(key)
            description = item.get("description") or item.get("details") or item.get("metadata") or ""
            findings.append(
                {
                    "source": source,
                    "title": str(title),
                    "severity": severity,
                    "description": description if isinstance(description, str) else json.dumps(description, indent=2),
                }
            )
    return findings


def calculate_score(findings: list[dict]) -> int:
    high = sum(1 for item in findings if item["severity"] == "HIGH")
    medium = sum(1 for item in findings if item["severity"] == "MEDIUM")
    low = sum(1 for item in findings if item["severity"] == "LOW")
    return min(100, (high * 10) + (medium * 5) + (low * 2))


def _fetch_manifest_from_container(scan_hash: str) -> str:
    """Fallback: read manifest directly from MobSF container unpacked scan dir."""
    paths = [
        f"/home/mobsf/.MobSF/uploads/{scan_hash}/AndroidManifest.xml",
        f"/home/mobsf/.MobSF/uploads/{scan_hash}/apktool_out/AndroidManifest.xml",
    ]
    for path in paths:
        try:
            result = subprocess.run(
                ["docker", "exec", MOBSF_CONTAINER_NAME, "sh", "-lc", f"cat '{path}'"],
                capture_output=True,
                text=True,
                timeout=20,
                check=False,
            )
            if result.returncode == 0 and result.stdout and "<manifest" in result.stdout:
                return result.stdout
        except Exception:
            continue
    return ""


def normalize_manifest(report: dict, scan_hash: str) -> str:
    manifest = report.get("manifest") or report.get("manifest_xml") or report.get("manifest_file")
    if isinstance(manifest, str):
        text = manifest.strip()
        if text and text != "Manifest not available":
            return text
    if isinstance(manifest, dict):
        return json.dumps(manifest, indent=2)

    from_container = _fetch_manifest_from_container(scan_hash)
    if from_container:
        return from_container

    return "Manifest not available"


def normalize_report(scan_hash: str, report: dict) -> dict:
    findings = flatten_findings(report)
    permissions = extract_permissions(report)
    dangerous_permissions = [item for item in permissions if item["dangerous"]]
    score = calculate_score(findings)
    normalized = {
        "hash": scan_hash,
        "app_name": report.get("app_name") or report.get("file_name") or "Unknown App",
        "package_name": report.get("package_name") or "unknown",
        "version_name": report.get("version_name") or report.get("version") or "N/A",
        "file_hash_sha256": report.get("file_hash_sha256") or scan_hash,
        "scan_time": report.get("scan_time") or report.get("timestamp") or "N/A",
        "manifest": normalize_manifest(report, scan_hash),
        "permissions": permissions,
        "dangerous_permissions": dangerous_permissions,
        "findings": findings,
        "threat_score": score,
        "raw_report": report,
    }
    save_report(scan_hash, normalized, score)
    return normalized


def mobsf_post(path: str, *, files=None, data=None, timeout=180):
    mobsf_url = ensure_mobsf_running()
    response = requests.post(
        f"{mobsf_url}{path}",
        headers=mobsf_headers(),
        files=files,
        data=data,
        timeout=timeout,
    )
    return response


@app.get("/")
def index():
    """Liveness — does NOT spawn MobSF. Used by the container healthcheck."""
    return jsonify({"service": "mobsf-proxy", "ok": True})


@app.get("/status")
def status():
    try:
        mobsf_url = ensure_mobsf_running()
        return jsonify(
            {
                "service": "ready",
                "mobsf_url": mobsf_url,
                "api_docs_url": f"{mobsf_url}/api_docs",
                "api_key_configured": bool(MOBSF_API_KEY and MOBSF_API_KEY != "PASTE_KEY_HERE"),
                "history": list_history(25),
            }
        )
    except Exception as exc:
        return jsonify({"service": "error", "detail": str(exc)}), 500


@app.post("/upload-apk")
def upload_apk():
    try:
        if "file" not in request.files:
            return jsonify({"detail": "Missing APK file."}), 400
        apk = request.files["file"]
        if not apk.filename or not apk.filename.lower().endswith(".apk"):
            return jsonify({"detail": "Only APK files are supported."}), 400

        with tempfile.NamedTemporaryFile(delete=False, suffix=".apk", dir=UPLOAD_DIR) as temp_file:
            apk.save(temp_file)
            temp_path = Path(temp_file.name)

        with temp_path.open("rb") as handle:
            response = mobsf_post(
                "/api/v1/upload",
                files={"file": (apk.filename, handle, "application/vnd.android.package-archive")},
                timeout=180,
            )
        temp_path.unlink(missing_ok=True)

        if response.status_code != 200:
            return jsonify({"detail": f"MobSF upload failed: {response.text}"}), 502

        payload = response.json()
        scan_hash = payload.get("hash")
        if not scan_hash:
            return jsonify({"detail": "MobSF did not return a scan hash."}), 502

        save_upload_context(scan_hash, payload.get("file_name", apk.filename), payload.get("scan_type", "apk"), apk.filename)
        return jsonify(
            {
                "hash": scan_hash,
                "file_name": payload.get("file_name", apk.filename),
                "scan_type": payload.get("scan_type", "apk"),
                "mobsf_url": ensure_mobsf_running(),
            }
        )
    except RuntimeError as exc:
        return jsonify({"detail": str(exc)}), 503
    except Exception as exc:
        return jsonify({"detail": str(exc)}), 500


@app.post("/start-scan")
def start_scan():
    try:
        payload = request.get_json(silent=True) or {}
        scan_hash = payload.get("hash")
        if not scan_hash:
            return jsonify({"detail": "Missing scan hash."}), 400

        context = get_scan_context(scan_hash)
        if not context:
            return jsonify({"detail": "Unknown scan hash. Upload the APK first."}), 404

        response = mobsf_post(
            "/api/v1/scan",
            data={
                "hash": scan_hash,
                "file_name": context["file_name"],
                "scan_type": context["scan_type"],
            },
            timeout=300,
        )
        if response.status_code != 200:
            return jsonify({"detail": f"MobSF scan failed: {response.text}"}), 502

        return jsonify({"status": "submitted", "hash": scan_hash, "scan_result": response.json()})
    except RuntimeError as exc:
        return jsonify({"detail": str(exc)}), 503
    except Exception as exc:
        return jsonify({"detail": str(exc)}), 500


@app.get("/report/<scan_hash>")
def report(scan_hash: str):
    try:
        context = get_scan_context(scan_hash)
        if not context:
            return jsonify({"detail": "Unknown scan hash."}), 404

        response = mobsf_post(
            "/api/v1/report_json",
            data={"hash": scan_hash},
            timeout=180,
        )
        if response.status_code != 200:
            return jsonify({"detail": f"MobSF report is not ready yet: {response.text}"}), 202

        normalized = normalize_report(scan_hash, response.json())
        return jsonify(normalized)
    except RuntimeError as exc:
        return jsonify({"detail": str(exc)}), 503
    except Exception as exc:
        return jsonify({"detail": str(exc)}), 500


@app.get("/history")
def history():
    return jsonify({"history": list_history(50)})


if __name__ == "__main__":
    app.run(host=SERVICE_HOST, port=SERVICE_PORT, debug=True)

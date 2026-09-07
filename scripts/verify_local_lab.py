#!/usr/bin/env python3
"""
Live verification for the local (Docker) lab provider.

Unlike backend/tests/, this talks to a real Docker daemon: it launches a lab
container, waits for XRDP to accept connections, registers a Guacamole
connection, then tears everything down again.

Run it once after building the lab image:

    make lab-image
    python3 scripts/verify_local_lab.py

Requires Docker to be running. Guacamole checks are skipped (not failed) when
the Guacamole database is unreachable, so this is useful even without the
guacamole/ compose stack up.
"""

import os
import sys
import time
from pathlib import Path

BACKEND = Path(__file__).resolve().parents[1] / "backend"
sys.path.insert(0, str(BACKEND))
os.environ.setdefault("SECRET_KEY", "verify-script-placeholder")
os.environ.setdefault("INFRA_PROVIDER", "local")

from app.services.providers import (  # noqa: E402
    LabConfig,
    LabStatus,
    ProviderUnavailableError,
    get_lab_provider,
)

PASS, FAIL, SKIP = "\033[92mPASS\033[0m", "\033[91mFAIL\033[0m", "\033[93mSKIP\033[0m"
results = []


def check(name, ok, detail=""):
    tag = PASS if ok else FAIL
    results.append(bool(ok))
    print(f"  [{tag}] {name}{(' — ' + detail) if detail else ''}")
    return ok


def skip(name, why):
    print(f"  [{SKIP}] {name} — {why}")


def main():
    print("\nShadowTrust — local lab provider verification\n")

    provider = get_lab_provider()
    print(f"Provider: {provider.name}\n")

    # ── 1. Daemon reachable ──────────────────────────────────────────────────
    print("Docker connectivity")
    try:
        provider._client()
        check("Docker daemon reachable", True)
    except ProviderUnavailableError as exc:
        check("Docker daemon reachable", False, str(exc))
        print("\nCannot continue without Docker. Start Docker Desktop and retry.\n")
        return 1

    lab_id = None
    try:
        # ── 2. Launch ────────────────────────────────────────────────────────
        print("\nLab launch")
        try:
            info = provider.launch_lab(
                LabConfig(environment="kali", profile="light", protocol="rdp",
                          owner_id="verify-script")
            )
            lab_id = info.lab_id
            check("Lab launched", info.status == LabStatus.PROVISIONING, f"lab_id={lab_id}")
        except ProviderUnavailableError as exc:
            check("Lab launched", False, str(exc))
            return 1

        # ── 3. Readiness ─────────────────────────────────────────────────────
        print("\nReadiness (waiting for XRDP on 3389, up to 300s)")
        started = time.time()
        ready = provider.wait_until_ready(lab_id, timeout=300)
        elapsed = int(time.time() - started)
        check("Lab reached READY", ready.status == LabStatus.READY,
              f"{elapsed}s — {ready.message or 'xrdp accepting connections'}")

        # ── 4. Status + connection ───────────────────────────────────────────
        print("\nStatus and connection details")
        status = provider.get_lab_status(lab_id)
        check("Status reports RUNNING", status.status == LabStatus.RUNNING, status.status)

        conn = provider.get_connection(lab_id, "rdp")
        check("Connection details resolved", conn is not None)
        if conn:
            check("Targets RDP port 3389", conn.port == 3389, f"host={conn.host}")
            check("Carries lab credentials", bool(conn.username), f"user={conn.username}")

        # ── 5. Metrics ───────────────────────────────────────────────────────
        print("\nMetrics")
        metrics = provider.get_metrics()
        check("Lab counted in metrics", metrics.active_count >= 1,
              f"{metrics.active_count} active, {metrics.vcpu} vCPU, {metrics.ram} GB")

        # ── 6. Guacamole ─────────────────────────────────────────────────────
        print("\nGuacamole registration")
        if conn is None:
            skip("Guacamole connection", "no connection details")
        else:
            from app.services.guacamole_service import GuacamoleService
            guac = GuacamoleService()
            try:
                guac_id = guac.create_connection(
                    lab_id=lab_id, private_ip=conn.host, protocol=conn.protocol,
                    port=str(conn.port), username=conn.username, password=conn.password,
                )
                if guac_id:
                    check("Guacamole connection created", True, f"connection_id={guac_id}")
                    check("Guacamole connection deleted", guac.delete_connection(guac_id))
                else:
                    skip("Guacamole connection", "Guacamole DB unreachable (is the stack up?)")
            except Exception as exc:
                skip("Guacamole connection", f"{type(exc).__name__}: {exc}")

    finally:
        # ── 7. Teardown ──────────────────────────────────────────────────────
        if lab_id:
            print("\nTeardown")
            check("Lab terminated", provider.terminate_lab(lab_id))
            gone = provider.get_lab_status(lab_id)
            check("Lab no longer present", gone.status == LabStatus.TERMINATED)

    passed, total = sum(results), len(results)
    print(f"\n{passed}/{total} checks passed.\n")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())

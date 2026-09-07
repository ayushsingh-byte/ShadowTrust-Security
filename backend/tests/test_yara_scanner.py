"""YARA scanner — graceful degradation + match parsing."""

import os

from app.services import yara_scanner
from app.services.yara_scanner import yara_scan, worst_severity


EICAR = (
    r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
)


def test_missing_rules_dir_is_graceful(tmp_path):
    old = yara_scanner.YARA_RULES_DIR
    yara_scanner.YARA_RULES_DIR = str(tmp_path / "nothing")
    yara_scanner._COMPILED.update(mtime=None, rules=None, error=None)
    try:
        f = tmp_path / "s.txt"
        f.write_text("hello")
        res = yara_scan(str(f), "0" * 64)
        assert res["available"] is False
        assert res["matches"] == [] and res["count"] == 0
    finally:
        yara_scanner.YARA_RULES_DIR = old
        yara_scanner._COMPILED.update(mtime=None, rules=None, error=None)


def test_bundled_rules_match_eicar(tmp_path):
    if not os.path.isdir("yara_rules"):
        import pytest
        pytest.skip("yara_rules dir not present from test cwd")
    yara_scanner.YARA_RULES_DIR = os.path.abspath("yara_rules")
    yara_scanner._COMPILED.update(mtime=None, rules=None, error=None)

    f = tmp_path / "eicar.com"
    f.write_text(EICAR)
    res = yara_scan(str(f), "e" * 64)

    if not res["available"]:
        import pytest
        pytest.skip(f"yara engine unavailable: {res['error']}")
    names = {m["rule"] for m in res["matches"]}
    assert "EICAR_Test_File" in names
    assert res["count"] >= 1
    m = next(m for m in res["matches"] if m["rule"] == "EICAR_Test_File")
    assert m["meta"].get("severity") == "medium"


def test_clean_file_no_match(tmp_path):
    if not os.path.isdir("yara_rules"):
        import pytest
        pytest.skip("yara_rules dir not present")
    yara_scanner.YARA_RULES_DIR = os.path.abspath("yara_rules")
    yara_scanner._COMPILED.update(mtime=None, rules=None, error=None)
    f = tmp_path / "clean.txt"
    f.write_text("the quick brown fox\n" * 20)
    res = yara_scan(str(f), "c" * 64)
    if res["available"]:
        assert res["count"] == 0


def test_worst_severity():
    assert worst_severity([{"meta": {"severity": "high"}}, {"meta": {"severity": "low"}}]) == "HIGH"
    assert worst_severity([{"meta": {}}]) == ""

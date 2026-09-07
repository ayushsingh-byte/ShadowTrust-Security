"""
Local telemetry ingestion and deduplication.

These assert that LocalDirectorySource honours the same contract the S3 source
does, so the shared downstream pipeline behaves identically for both.
"""

import json
import os
import time
from datetime import datetime, timedelta

import pytest

from app.services.telemetry import get_source_name, get_telemetry_source
from app.services.telemetry.local_source import LocalDirectorySource


def write_events(directory, filename, events):
    """Write newline-delimited JSON, the shape honeypot logs arrive in."""
    path = os.path.join(directory, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as handle:
        for event in events:
            handle.write(json.dumps(event) + "\n")
    return path


SAMPLE = [
    {"timestamp": "2026-01-01T10:00:00Z", "src_ip": "203.0.113.5",
     "dst_port": 2222, "eventid": "cowrie.login.failed", "sensor": "cowrie"},
    {"timestamp": "2026-01-01T10:00:05Z", "src_ip": "203.0.113.5",
     "dst_port": 2222, "eventid": "cowrie.command.input", "sensor": "cowrie"},
]


class TestSourceSelection:
    def test_defaults_to_local(self):
        assert get_source_name() == "local"
        assert isinstance(get_telemetry_source(), LocalDirectorySource)

    def test_follows_infra_provider(self, monkeypatch):
        monkeypatch.setenv("INFRA_PROVIDER", "aws")
        assert get_source_name() == "s3"

    def test_explicit_override_wins(self, monkeypatch):
        monkeypatch.setenv("INFRA_PROVIDER", "aws")
        monkeypatch.setenv("TELEMETRY_SOURCE", "local")
        assert get_source_name() == "local"

    def test_invalid_source_raises(self, monkeypatch):
        monkeypatch.setenv("TELEMETRY_SOURCE", "kafka")
        with pytest.raises(ValueError) as exc:
            get_telemetry_source()
        assert "kafka" in str(exc.value)


class TestIngestion:
    def test_reads_newline_delimited_json(self, tmp_path):
        source = LocalDirectorySource(str(tmp_path))
        write_events(str(tmp_path), "cowrie.json", SAMPLE)

        events, keys = source.fetch({})

        assert len(events) == 2
        assert keys == {"cowrie.json"}
        assert events[0]["src_ip"] == "203.0.113.5"

    def test_creates_missing_directory(self, tmp_path):
        target = tmp_path / "does-not-exist-yet"
        source = LocalDirectorySource(str(target))
        assert source.is_configured() is True
        assert target.is_dir()

    def test_walks_nested_directories(self, tmp_path):
        source = LocalDirectorySource(str(tmp_path))
        write_events(str(tmp_path), "node-a/cowrie.json", SAMPLE)

        events, keys = source.fetch({})

        assert len(events) == 2
        # Key is the path relative to the watch root.
        assert keys == {os.path.join("node-a", "cowrie.json")}

    def test_ignores_unrelated_file_types(self, tmp_path):
        source = LocalDirectorySource(str(tmp_path))
        write_events(str(tmp_path), "cowrie.json", SAMPLE)
        (tmp_path / "notes.txt").write_text("not telemetry")
        (tmp_path / "capture.pcap").write_bytes(b"\x00\x01")

        _events, keys = source.fetch({})
        assert keys == {"cowrie.json"}

    def test_accepts_log_and_jsonl_suffixes(self, tmp_path):
        source = LocalDirectorySource(str(tmp_path))
        write_events(str(tmp_path), "a.log", SAMPLE[:1])
        write_events(str(tmp_path), "b.jsonl", SAMPLE[1:])

        events, keys = source.fetch({})
        assert len(events) == 2
        assert keys == {"a.log", "b.jsonl"}

    def test_malformed_lines_are_skipped_not_fatal(self, tmp_path):
        source = LocalDirectorySource(str(tmp_path))
        path = tmp_path / "mixed.json"
        path.write_text(
            json.dumps(SAMPLE[0]) + "\n"
            + "{ this is not json\n"
            + "\n"
            + json.dumps(SAMPLE[1]) + "\n"
        )

        events, _keys = source.fetch({})
        assert len(events) == 2

    def test_empty_directory_returns_nothing(self, tmp_path):
        source = LocalDirectorySource(str(tmp_path))
        assert source.fetch({}) == ([], set())


class TestDeduplication:
    def test_already_processed_file_is_skipped(self, tmp_path):
        source = LocalDirectorySource(str(tmp_path))
        write_events(str(tmp_path), "cowrie.json", SAMPLE)

        # Record it as processed in the future relative to its mtime.
        state = {"cowrie.json": datetime.utcnow() + timedelta(hours=1)}
        events, keys = source.fetch(state)

        assert events == []
        assert keys == set()

    def test_modified_file_is_reprocessed(self, tmp_path):
        source = LocalDirectorySource(str(tmp_path))
        write_events(str(tmp_path), "cowrie.json", SAMPLE)

        # Processed well before the file was written.
        state = {"cowrie.json": datetime.utcnow() - timedelta(hours=1)}
        events, keys = source.fetch(state)

        assert len(events) == 2
        assert keys == {"cowrie.json"}

    def test_unseen_file_is_always_processed(self, tmp_path):
        source = LocalDirectorySource(str(tmp_path))
        write_events(str(tmp_path), "old.json", SAMPLE[:1])
        write_events(str(tmp_path), "new.json", SAMPLE[1:])

        state = {"old.json": datetime.utcnow() + timedelta(hours=1)}
        _events, keys = source.fetch(state)

        assert keys == {"new.json"}

    def test_timezone_aware_state_is_handled(self, tmp_path):
        """
        DB-loaded timestamps can arrive tz-aware; comparison must not explode.
        This mirrors the tzinfo normalisation the S3 source performs.
        """
        from datetime import timezone

        source = LocalDirectorySource(str(tmp_path))
        write_events(str(tmp_path), "cowrie.json", SAMPLE)

        state = {
            "cowrie.json": (datetime.utcnow() + timedelta(hours=1)).replace(
                tzinfo=timezone.utc
            )
        }
        events, keys = source.fetch(state)
        assert events == []
        assert keys == set()


class TestPipelineCompatibility:
    def test_returns_same_shape_as_s3_source(self, tmp_path):
        """
        The pipeline unpacks (events, keys); both sources must agree on that
        contract or the shared downstream code breaks.
        """
        source = LocalDirectorySource(str(tmp_path))
        write_events(str(tmp_path), "cowrie.json", SAMPLE)

        result = source.fetch({})
        assert isinstance(result, tuple) and len(result) == 2
        events, keys = result
        assert isinstance(events, list)
        assert isinstance(keys, set)
        assert all(isinstance(e, dict) for e in events)

    def test_events_carry_fields_the_parser_reads(self, tmp_path):
        """The downstream parser reads src_ip / dst_port / eventid / sensor."""
        source = LocalDirectorySource(str(tmp_path))
        write_events(str(tmp_path), "cowrie.json", SAMPLE)

        events, _ = source.fetch({})
        event = events[0]
        for field in ("src_ip", "dst_port", "eventid", "sensor"):
            assert field in event

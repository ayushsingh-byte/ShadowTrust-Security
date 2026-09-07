# Local telemetry drop directory

When `INFRA_PROVIDER=local` (or `TELEMETRY_SOURCE=local`), the ingestion
pipeline watches `telemetry/raw/` (this directory's `raw/` subfolder) for
honeypot logs — that's the exact path docker-compose.yml bind-mounts
read-only into the backend container, and what each sensor container writes
into. Everything below refers to paths relative to `raw/`.

**Format:** newline-delimited JSON — one event object per line. Files ending in
`.json`, `.jsonl` or `.log` are read; everything else is ignored.

```json
{"timestamp":"2026-01-01T10:00:00Z","src_ip":"203.0.113.5","dst_port":2222,"eventid":"cowrie.login.failed","sensor":"cowrie"}
{"timestamp":"2026-01-01T10:00:05Z","src_ip":"203.0.113.5","dst_port":2222,"eventid":"cowrie.command.input","sensor":"cowrie"}
```

Subdirectories are walked, so per-sensor layout works:

```
telemetry/raw/
├── cowrie/cowrie.json
├── dionaea/dionaea.log
└── honeytrap/events.jsonl
```

Each file is read from the exact byte offset it left off at last cycle — not
just when its mtime advances — so a line already ingested is never re-parsed
and a line appended mid-file is never missed. That offset (plus the file's
inode and size, to detect rotation/truncation) is tracked per file in the
`ingest_cursors` table, keyed by the file's path relative to `raw/`. Content
hashing on top (`normalized_events.event_id`) means even a full re-read after
`ingest_cursors` is cleared — e.g. by `./reset.sh` — produces the same rows
instead of duplicates.

Point honeypot log shippers here, or symlink existing log files into it.

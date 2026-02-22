#!/usr/bin/env bash

# Backwards-compatible wrapper.
exec "$(cd "$(dirname "$0")" && pwd)/run.sh"

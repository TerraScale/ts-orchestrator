#!/usr/bin/env bash
set -euo pipefail
exec bash "$(cd "$(dirname "$0")" && pwd)/admit-provenance.sh" finalize

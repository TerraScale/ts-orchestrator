#!/usr/bin/env bash
set -euo pipefail
bin=$(realpath "$1")
here=$(cd "$(dirname "$0")" && pwd)
"$(dirname "$bin")/operator-truth"
bash "$here/startup.sh" "$bin" "$(dirname "$bin")/startup"

set -euo pipefail
exec bash "$(dirname "$0")/run.sh" "$1" metadata

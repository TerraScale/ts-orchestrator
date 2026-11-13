set -euo pipefail
bin=$(realpath "$1")
"$(dirname "$bin")/vault-policy" "$bin"

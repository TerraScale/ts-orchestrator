#!/usr/bin/env bash
set -euo pipefail
audit=0
retain=0
bash scripts/ci/audit-dependencies.sh release &
audit_pid=$!
bash scripts/ci/publish-qualification.sh &
retain_pid=$!
wait "$audit_pid" || audit=$?
wait "$retain_pid" || retain=$?
[[ $audit -eq 0 && $retain -eq 0 ]]

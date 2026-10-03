package racetest_test

import (
	"path/filepath"
	"testing"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/testutil/script"
)

// Some bash releases stop reporting shards that already terminated to
// wait -n, which then returns 127 without setting its -p variable. The
// shim below reproduces that through BASH_ENV: every wait -n waits until all
// listed shards have exited and then reports none. The scheduler must still
// reap every shard with its real status and finish the run (#127 11986).
func TestRaceSchedulerReapsShardsWaitNNoLongerReports(t *testing.T) {
	f := newScheduler(t)
	shim := filepath.Join(t.TempDir(), "old-wait.bash")
	script.Write(t, shim, []byte(`wait() {
	if [[ ${1-} == -n ]]; then
		local pid
		for pid in "${@:4}"; do
			while kill -0 "$pid" 2>/dev/null; do sleep 0.05; done
		done
		return 127
	fi
	builtin wait "$@"
}
`), 0o644)
	r := f.run(t, map[string]string{"BASH_ENV": shim})
	if r.Code != 0 {
		t.Fatalf("exit %d: %s %s", r.Code, r.Stdout, r.Stderr)
	}
	f.complete(t, r, false)
}

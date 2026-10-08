package rollout

import "testing"

func TestPreJournalInstallFailureRequiresNoopRollbackAcknowledgment(t *testing.T) {
	for _, missing := range []bool{false, true} {
		name := "installed"
		if missing {
			name = "first-install"
		}
		t.Run(name, func(t *testing.T) {
			f := newRolloutFixture(t)
			f.deferActions = true
			node := f.nodes[0]
			if missing {
				f.previous[node] = ""
				f.statuses[node] = Status{Missing: true}
			}
			target := rolloutTarget("0.80.0")
			f.advance(target, "install")
			// The worker acknowledged an error before pending.json or mutation.
			status := f.statuses[node]
			status.ActionID, status.Error = CommandID(f.record().ID, "install"), "snapshot preparation failed"
			f.statuses[node] = status
			f.advance(target, "rollback-check")
			if err := f.tick(target); err != nil || !f.drained[node] || f.record().RecoveryComplete || f.record().Phase != "rollback-check" {
				t.Fatalf("unchanged observation waived the required rollback proof: record=%+v error=%v", f.record(), err)
			}
			// Worker proof and its durable tombstone authorize this exact ack.
			status.ActionID, status.Error = CommandID(f.record().ID, "rollback"), ""
			f.statuses[node] = status
			if err := f.tick(target); err != nil || f.drained[node] || !f.record().RecoveryComplete || f.record().Phase != "failed" {
				t.Fatalf("proven no-op rollback stranded an unchanged node: record=%+v error=%v", f.record(), err)
			}
		})
	}
}

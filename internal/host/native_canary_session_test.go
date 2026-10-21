//go:build linux

package host

import (
	"context"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestNativeCanarySessionRejectsSuccessorAndOriginalCancellation(t *testing.T) {
	c, _, original, _ := reportedTestHost(t)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	admitted, err := (&Reader{controller: c}).AdmitNativeCanarySession(ctx, "node-a")
	if err != nil || !admitted.Deadline().Equal(original.ExpiresAt) {
		t.Fatal("native canary did not pin actual host session", err)
	}
	current, revision, _, err := c.sessionSnapshot(t.Context(), sessionKey(c.cell, "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	current.SessionID, current.Epoch = entityid.New(), current.Epoch+1
	if _, err := c.cas(t.Context(), sessionKey(c.cell, "node-a"), current, revision); err != nil {
		t.Fatal(err)
	}
	if admitted.Guard(t.Context()) == nil {
		t.Fatal("native canary inherited successor host session")
	}
	cancel()
	if admitted.Guard(t.Context()) == nil {
		t.Fatal("native canary survived original operation cancellation")
	}
}

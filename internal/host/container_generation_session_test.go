//go:build linux

package host

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestContainerGenerationObservationRejectsSessionReplacement(t *testing.T) {
	c, _, original, _ := reportedTestHost(t)
	admitted, err := (&Reader{controller: c}).AdmitContainerGenerationSession(t.Context(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	if !admitted.Deadline().Equal(original.ExpiresAt) {
		t.Fatal("generation observation did not preserve its original host session deadline")
	}
	current, revision, _, err := c.sessionSnapshot(t.Context(), sessionKey(c.cell, "node-a"))
	if err != nil {
		t.Fatal(err)
	}
	current.SessionID, current.Epoch = entityid.New(), current.Epoch+1
	if _, err := c.cas(t.Context(), sessionKey(c.cell, "node-a"), current, revision); err != nil {
		t.Fatal(err)
	}
	if err := admitted.Guard(t.Context()); err == nil {
		t.Fatal("generation observation followed a successor host session")
	}
}

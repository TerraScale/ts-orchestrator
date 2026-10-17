//go:build linux

package host

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func TestRootContainerMaterialPinsOriginalSessionAcrossRenewal(t *testing.T) {
	c, key, current, _ := reportedTestHost(t)
	registration, err := c.registration(t.Context(), "node-a")
	if err != nil {
		t.Fatal(err)
	}
	current.ExpiresAt = time.Now().Add(5 * time.Second)
	_, revision, _, err := c.sessionSnapshot(t.Context(), sessionKey(c.cell, registration.Node))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.cas(t.Context(), sessionKey(c.cell, registration.Node), current, revision); err != nil {
		t.Fatal(err)
	}
	binding := ContainerMaterialBinding{TaskID: strings.Repeat("a", 25), ServiceID: strings.Repeat("b", 25), NodeID: strings.Repeat("c", 25),
		InstanceID: "ocid1.instance.oc1..actual", Region: "sa-saopaulo-1", HostID: registration.ID, Fingerprint: strings.Repeat("d", 64)}
	req := signedHostRequest(t, key, "container-material", current.SessionID, current.Epoch,
		containerMaterialQuery{Binding: binding, RegistrationGeneration: registration.Generation, Length: materialChunkBytes, EphemeralPublicKey: make([]byte, 32)})
	original, cancel := context.WithCancel(t.Context())
	defer cancel()
	admitted, err := (&Reader{controller: c}).AdmitContainerMaterialSession(original, ContainerMaterialEvidence{Request: req.Envelope})
	if err != nil {
		t.Fatal(err)
	}
	if !admitted.Deadline().Equal(current.ExpiresAt) || admitted.Binding() != binding {
		t.Fatal("root admission did not pin the original session cap and exact task binding")
	}
	inventoryExpiry := time.Now().Add(time.Second)
	continuation := signedHostRequest(t, key, "container-material", current.SessionID, current.Epoch,
		containerMaterialQuery{Binding: binding, RegistrationGeneration: registration.Generation, Offset: 1, Length: materialChunkBytes,
			EphemeralPublicKey: make([]byte, 32), InventoryExpiresAt: inventoryExpiry, InventorySHA256: strings.Repeat("a", 64)})
	continued, err := (&Reader{controller: c}).AdmitContainerMaterialSession(original, ContainerMaterialEvidence{Request: continuation.Envelope})
	if err != nil || !continued.Deadline().Equal(inventoryExpiry) {
		t.Fatal("signed continuation did not shorten fresh root admission to original inventory expiry", err)
	}
	renew := signedHostRequest(t, key, "session", current.SessionID, current.Epoch, struct {
		Kind string `json:"kind"`
	}{"renew"})
	if _, err := c.handleSession(t.Context(), renew); err != nil {
		t.Fatal(err)
	}
	if err := admitted.Guard(t.Context()); err != nil {
		t.Fatal(err)
	}
	if !admitted.Deadline().Equal(current.ExpiresAt) {
		t.Fatal("session renewal extended original root material admission")
	}
	successor, revision, _, err := c.sessionSnapshot(t.Context(), sessionKey(c.cell, registration.Node))
	if err != nil {
		t.Fatal(err)
	}
	successor.SessionID, successor.Epoch = entityid.New(), successor.Epoch+1
	if _, err := c.cas(t.Context(), sessionKey(c.cell, registration.Node), successor, revision); err != nil {
		t.Fatal(err)
	}
	if err := admitted.Guard(t.Context()); err == nil {
		t.Fatal("successor session inherited the original material admission")
	}
	cancel()
	if err := admitted.Guard(t.Context()); err == nil {
		t.Fatal("material admission survived original request cancellation")
	}
}

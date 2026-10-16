package host

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/artifact"
	"github.com/nats-io/nats.go"
)

// A desired commit touches its artifact first, so a collector that read the
// artifact's metadata before the commit can no longer delete it, and a
// commit after a deletion is refused.
func TestApplyDesiredPinsItsArtifactAgainstCollection(t *testing.T) {
	c, conn, store, _, _ := testController(t)
	registerTestHost(t, c)
	js, err := conn.JetStream()
	if err != nil {
		t.Fatal(err)
	}
	var bucket string
	put := func(body string) (string, *nats.RawStreamMsg) {
		t.Helper()
		sum := sha256.Sum256([]byte(body))
		digest := hex.EncodeToString(sum[:])
		info, err := store.PutBytes(t.Context(), "sha256-"+digest, []byte(body))
		if err != nil {
			t.Fatal(err)
		}
		bucket = info.Bucket
		meta, err := js.GetLastMsg("OBJ_"+bucket, "$O."+bucket+".M."+base64.URLEncoding.EncodeToString([]byte(info.Name)))
		if err != nil {
			t.Fatal(err)
		}
		return digest, meta
	}
	running, chosen := put("running artifact")
	desired := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Digest: running, Generation: 1, AuthorityEpoch: 1}
	if _, err := c.ApplyDesired(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	if err := artifact.DeleteIfUnchanged(t.Context(), js, bucket, chosen); !errors.Is(err, artifact.ErrChanged) {
		t.Fatalf("collector deletion chosen before the desired commit = %v, want ErrChanged", err)
	}
	old, oldMeta := put("old artifact")
	if err := artifact.DeleteIfUnchanged(t.Context(), js, bucket, oldMeta); err != nil {
		t.Fatal(err)
	}
	rollback := desired
	rollback.Digest, rollback.Generation = old, 2
	if _, err := c.ApplyDesired(t.Context(), rollback); err == nil {
		t.Fatal("desired committed a deleted artifact")
	}
	if _, err := store.GetInfo(t.Context(), "sha256-"+running); err != nil {
		t.Fatalf("the desired artifact after a refused deletion: %v", err)
	}
}

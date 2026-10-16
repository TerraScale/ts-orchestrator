//go:build fixturetest

package materialsource

import (
	"bytes"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// This shares the real source actor, signed recipe, SDK HTTP endpoints and
// durable object directory of the source-publication integration scenario.
func assertDerivedSeedAdmission(t *testing.T, source *ColdStartMaterial, seed bootstrap.DerivedStartupAuthority, anchor bootstrap.VerifiedBootstrapAnchor, roots trust.Keyring, protocol *materialProtocol, now time.Time) {
	t.Helper()
	before, err := bootstrap.NewDerivedFounderPlan(t.Context(), seed, now)
	if err != nil {
		t.Fatal(err)
	}
	priorETag := source.etag
	state, err := source.PrepareSeedLedger(t.Context(), roots, anchor, seed, source.actor.Founder())
	if err != nil {
		t.Fatalf("publish genuine external-seed ledger: %v", err)
	}
	if state.Intent.Mode != bootstrap.IntentModeExternalSeed || state.Head.Attempt != 1 || state.Head.Generation != 1 || state.Intent.Slot != seed.Manifest().SeedSlot || state.ManifestRecord == nil || state.SeedReceiptRecord == nil || state.ResultRecord == nil || state.ManifestRecord.SHA256 != seed.Digest() || !bytes.Equal(state.ManifestRecord.Bytes, seed.Wire()) || state.Head.ResultDigest != state.ResultRecord.SHA256 {
		t.Fatal("external seed lost exact startup, receipt, result or first-attempt identity")
	}
	var checkpoint seedCheckpoint
	if json.Unmarshal(source.state.SeedCompletion, &checkpoint, json.RejectUnknownMembers(true)) != nil || checkpoint.StartupSHA256 != seed.Digest() || checkpoint.SourceSHA256 != seed.SourceSHA256() || checkpoint.GrantSHA256 != digestWire(seed.GrantWire()) || checkpoint.TemplateSHA256 != seed.TemplateDigest() || checkpoint.InstanceID != source.actor.Founder().InstanceID() || !bytes.Equal(checkpoint.Records.ReceiptWire, state.SeedReceiptRecord.Bytes) || !bytes.Equal(checkpoint.Records.ResultWire, state.ResultRecord.Bytes) || !bytes.Equal(checkpoint.Records.CompletedHeadWire, state.HeadRecord.Bytes) || priorETag == source.etag {
		t.Fatal("source CAS did not checkpoint exact durable external-seed completion")
	}
	after, err := bootstrap.NewDerivedFounderPlan(t.Context(), seed, now)
	if err != nil || after.Digest() != before.Digest() {
		t.Fatalf("real seed-completion CAS changed immutable founder authority: %v", err)
	}
	snapshot := func() map[string][]byte {
		t.Helper()
		entries, err := os.ReadDir(protocol.directory)
		if err != nil {
			t.Fatal(err)
		}
		files := make(map[string][]byte, len(entries))
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			wire, err := os.ReadFile(filepath.Join(protocol.directory, entry.Name()))
			if err != nil {
				t.Fatal(err)
			}
			files[entry.Name()] = wire
		}
		return files
	}
	wires, etag := snapshot(), source.etag
	replayed, err := source.PrepareSeedLedger(t.Context(), roots, anchor, seed, source.actor.Founder())
	if err != nil || replayed.ManifestRecord == nil || replayed.SeedReceiptRecord == nil || replayed.ResultRecord == nil || !bytes.Equal(replayed.ManifestRecord.Bytes, state.ManifestRecord.Bytes) || !bytes.Equal(replayed.SeedReceiptRecord.Bytes, state.SeedReceiptRecord.Bytes) || !bytes.Equal(replayed.ResultRecord.Bytes, state.ResultRecord.Bytes) || !bytes.Equal(replayed.HeadRecord.Bytes, state.HeadRecord.Bytes) || source.etag != etag {
		t.Fatalf("external-seed replay changed exact durable history: %v", err)
	}
	current := snapshot()
	if len(current) != len(wires) {
		t.Fatal("external-seed replay created additional durable objects")
	}
	for name, wire := range wires {
		if !bytes.Equal(current[name], wire) {
			t.Fatalf("external-seed replay replaced durable object %s", name)
		}
	}
	bootstrapstart.ExerciseDerivedSeedAdmission(t, seed, source.actor.Founder(), anchor, roots, source.directory)
}

func TestDerivedSeedCredentialChild(t *testing.T) {
	if os.Getenv("TS_ORCH_FIXTURE_CREDENTIAL_CHILD") != "1" {
		return
	}
	if err := bootstrapstart.ValidateDerivedSeedCredentialChild(os.Stdin); err != nil {
		t.Fatal(err)
	}
}

//go:build fixturetest

package materialsource

import (
	"bytes"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
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
	if protocol.interceptObject != nil {
		t.Fatal("seed crash scenario requires the unused object fault hook")
	}
	domain := seed.StorageDomain()
	var faultMu sync.Mutex
	var intentWire, initialHeadWire []byte
	var intentPath, headPath string
	var lostHead bool
	protocol.interceptObject = func(w http.ResponseWriter, r *http.Request) bool {
		if r.Method != http.MethodPut {
			return false
		}
		faultMu.Lock()
		defer faultMu.Unlock()
		if strings.Contains(r.URL.Path, "/b/"+domain.LedgerBucket+"/o/") && strings.HasSuffix(r.URL.Path, "/intent.json") {
			wire, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
				w.WriteHeader(http.StatusInternalServerError)
				return true
			}
			r.Body = io.NopCloser(bytes.NewReader(wire))
			if len(intentWire) == 0 {
				intentPath, intentWire = r.URL.Path, bytes.Clone(wire)
				base, _, ok := strings.CutLast(intentPath, "/attempt-")
				if !ok {
					t.Error("actual seed intent omitted its attempt path")
				}
				headPath = strings.Replace(base, "/b/"+domain.LedgerBucket+"/o/", "/b/"+domain.HeadBucket+"/o/", 1) + "/head.json"
			} else if !bytes.Equal(intentWire, wire) {
				t.Error("seed reservation retry changed the actual intent PUT bytes")
			}
			return false
		}
		if r.URL.Path != headPath || lostHead {
			return false
		}
		stored, err := os.ReadFile(protocol.objectPath(intentPath))
		if err != nil || !bytes.Equal(stored, intentWire) {
			t.Error("initial HEAD fault did not follow a committed exact intent")
		}
		initialHeadWire, err = io.ReadAll(r.Body)
		if err != nil {
			t.Error(err)
		}
		lostHead = true
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusServiceUnavailable)
		io.WriteString(w, `{"code":"ServiceUnavailable","message":"initial HEAD was not committed"}`)
		return true
	}
	defer func() { protocol.interceptObject = nil }()
	if _, err := source.PrepareSeedLedger(t.Context(), roots, anchor, seed, source.actor.Founder()); err == nil || !lostHead {
		t.Fatalf("actual seed intent/HEAD crash was not exercised: %v", err)
	}
	protocol.interceptObject = nil
	var reserved seedCheckpoint
	if json.Unmarshal(source.state.SeedCompletion, &reserved, json.RejectUnknownMembers(true)) != nil || !bytes.Equal(reserved.Records.Reservation.IntentWire, intentWire) || !bytes.Equal(reserved.Records.Reservation.InitialHeadWire, initialHeadWire) || len(reserved.Records.Completion.ResultWire) != 0 {
		t.Fatal("source CAS did not retain the exact reservation before the initial HEAD fault")
	}
	if _, err := os.ReadFile(protocol.objectPath(headPath)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("initial HEAD fault unexpectedly committed a slot head: %v", err)
	}
	reservation, err := trust.DecodeEnvelope(intentWire)
	if err != nil {
		t.Fatal(err)
	}
	timer := time.NewTimer(time.Until(reservation.IssuedAt.Add(2 * time.Second)))
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-t.Context().Done():
		t.Fatal(t.Context().Err())
	}
	state, err := source.PrepareSeedLedger(t.Context(), roots, anchor, seed, source.actor.Founder())
	if err != nil {
		t.Fatalf("publish genuine external-seed ledger: %v", err)
	}
	if state.Intent.Mode != bootstrap.IntentModeExternalSeed || state.Head.Attempt != 1 || state.Head.Generation != 1 || state.Intent.Slot != seed.Manifest().SeedSlot || state.ManifestRecord == nil || state.SeedReceiptRecord == nil || state.ResultRecord == nil || state.ManifestRecord.SHA256 != seed.Digest() || !bytes.Equal(state.ManifestRecord.Bytes, seed.Wire()) || state.Head.ResultDigest != state.ResultRecord.SHA256 {
		t.Fatal("external seed lost exact startup, receipt, result or first-attempt identity")
	}
	var checkpoint seedCheckpoint
	if json.Unmarshal(source.state.SeedCompletion, &checkpoint, json.RejectUnknownMembers(true)) != nil || checkpoint.StartupSHA256 != seed.Digest() || checkpoint.SourceSHA256 != seed.SourceSHA256() || checkpoint.GrantSHA256 != digestWire(seed.GrantWire()) || checkpoint.TemplateSHA256 != seed.TemplateDigest() || checkpoint.InstanceID != source.actor.Founder().InstanceID() || !bytes.Equal(checkpoint.Records.Reservation.IntentWire, intentWire) || !bytes.Equal(state.IntentRecord.Bytes, intentWire) || !bytes.Equal(checkpoint.Records.Reservation.InitialHeadWire, initialHeadWire) || !bytes.Equal(checkpoint.Records.Completion.ReceiptWire, state.SeedReceiptRecord.Bytes) || !bytes.Equal(checkpoint.Records.Completion.ResultWire, state.ResultRecord.Bytes) || !bytes.Equal(checkpoint.Records.Completion.CompletedHeadWire, state.HeadRecord.Bytes) || priorETag == source.etag {
		t.Fatal("source CAS did not checkpoint exact durable external-seed completion")
	}
	t.Log("seed recovered a committed intent without HEAD using its exact checkpointed reservation")
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
	protocol.logProgress(t, "seed ledger recovery and replay complete; entering actual Gate")
	bootstrapstart.ExerciseDerivedSeedAdmission(t, seed, source.actor.Founder(), anchor, roots, source.directory)
}

// The credential verifier reexecutes this same integration binary as the
// service user before the Go test runner parses its flags.
func init() {
	if len(os.Args) != 2 || os.Args[1] != "derived-seed-credential-child" {
		return
	}
	if err := bootstrapstart.ValidateDerivedSeedCredentialChild(os.Stdin); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	os.Exit(0)
}

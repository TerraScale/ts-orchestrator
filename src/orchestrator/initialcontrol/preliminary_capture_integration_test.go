//go:build linux

package initialcontrol_test

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialcontrol"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/preliminarycapture"
)

func awaitCapture(t *testing.T, runtime *initialcontrol.Runtime, state string) initialcontrol.PreliminaryCaptureStatus {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		status := runtime.PreliminaryCapture()
		if status.State == state {
			return status
		}
		select {
		case <-runtime.Completion():
			t.Fatalf("source runtime stopped while waiting for %s: %v", state, runtime.Err())
		case <-time.After(20 * time.Millisecond):
		}
	}
	t.Fatalf("capture did not reach %s: %+v", state, runtime.PreliminaryCapture())
	return initialcontrol.PreliminaryCaptureStatus{}
}

func captureRequest(t *testing.T, f *fixture, runtime *initialcontrol.Runtime, transition string) preliminarycapture.Request {
	t.Helper()
	accounts, err := initialcontrol.PreliminaryInventory(f.config.Cell, f.config.SeedInstance, f.config.Regional.Account, f.config.Global.Account)
	if err != nil {
		t.Fatal(err)
	}
	identity := f.proof.Identity()
	return preliminarycapture.Request{Version: 1, TransitionID: transition, SourceNodeID: f.config.NodeID, InitialGrantSHA256: identity.GrantSHA256, StoreScopeSHA256: identity.StoreScopeSHA256, ProfileSHA256: f.config.ProfileSHA256, Accounts: accounts, ControlEpoch: uint64(runtime.GlobalAuthority().Epoch), IssuedAt: time.Now().UTC().Add(-time.Second), ExpiresAt: time.Now().UTC().Add(10 * time.Minute)}
}

func publishCaptureRequest(t *testing.T, f *fixture, request preliminarycapture.Request) []byte {
	t.Helper()
	raw, err := preliminarycapture.SignRequest(f.owner, request)
	if err != nil {
		t.Fatal(err)
	}
	write(t, f.config.PreliminaryCapture.RequestFile, raw)
	return raw
}

func TestInitialRuntimePreliminaryCaptureBothAccountsAndReplay(t *testing.T) {
	namespace(t)
	config, participant := fixtureConfigCapture(t, true)
	if participant.PreliminaryCapture != nil {
		t.Fatal("participant received privileged source capture material")
	}
	f := admit(t, config)
	runtime, err := initialcontrol.Start(t.Context(), f.admission)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { runtime.Close() })
	awaitCapture(t, runtime, "idle")
	if _, err := os.Stat(config.PreliminaryCapture.OutputDir); !os.IsNotExist(err) {
		t.Fatal("idle worker created staging without signed request", err)
	}
	// Both accounts contain incompressible data exceeding the pinned server's
	// 8 MiB snapshot flow window. Production capture credentials must ACK chunks.
	for index, scope := range []struct {
		store  initialgrant.Store
		bucket string
	}{{config.Regional, "ORCH_DELIVERY"}, {*config.Global, "GLOBAL_DELIVERIES"}} {
		nc := client(t, config, *scope.store.Provisioner)
		js, err := jetstream.New(nc)
		if err != nil {
			t.Fatal(err)
		}
		bucket, err := js.KeyValue(t.Context(), scope.bucket)
		if err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 20; i++ {
			data := make([]byte, 512<<10)
			if _, err := rand.Read(data); err != nil {
				t.Fatal(err)
			}
			if _, err := bucket.Put(t.Context(), fmt.Sprintf("capture-%d-%d", index, i), data); err != nil {
				t.Fatal(err)
			}
		}
		nc.Close()
	}
	write(t, config.PreliminaryCapture.RequestFile, []byte(`{"payload":{},"signature":"invalid"}`))
	awaitCapture(t, runtime, "failed")
	if _, err := os.Stat(config.PreliminaryCapture.OutputDir); !os.IsNotExist(err) {
		t.Fatal("invalid request produced output", err)
	}
	request := captureRequest(t, f, runtime, "preliminary-large")
	raw := publishCaptureRequest(t, f, request)
	status := awaitCapture(t, runtime, "complete")
	if status.TotalStreams == 0 || status.CapturedStreams != status.TotalStreams || status.ReceiptSHA256 == "" {
		t.Fatalf("incomplete capture status: %+v", status)
	}
	receiptPath := filepath.Join(config.PreliminaryCapture.OutputDir, "receipt.json")
	receiptRaw, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	public, _ := base64.StdEncoding.DecodeString(config.Membership.PublicKey)
	receipt, err := preliminarycapture.VerifyReceipt(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: public}), receiptRaw)
	if err != nil {
		t.Fatal(err)
	}
	large := map[string]bool{}
	for _, object := range receipt.Objects {
		if object.Size > 8<<20 {
			large[object.Account] = true
		}
	}
	if !large[config.Regional.Account] || !large[config.Global.Account] || len(receipt.Objects) != status.TotalStreams || !receipt.Preliminary {
		t.Fatalf("missing full-window snapshots: %+v", receipt)
	}
	// Replacement is rejected after pinning, and restoring the original bytes
	// restores complete status without re-signing or replacing its artifacts.
	replacement := request
	replacement.TransitionID = "different-transition"
	publishCaptureRequest(t, f, replacement)
	awaitCapture(t, runtime, "failed")
	write(t, config.PreliminaryCapture.RequestFile, raw)
	resumed := awaitCapture(t, runtime, "complete")
	if resumed.ReceiptSHA256 != status.ReceiptSHA256 {
		t.Fatal("identical retry changed receipt identity")
	}
	after, err := os.ReadFile(receiptPath)
	if err != nil || !bytes.Equal(after, receiptRaw) {
		t.Fatal("retry replaced completed receipt", err)
	}
	expired := request
	expired.IssuedAt = time.Now().UTC().Add(-30 * time.Second)
	expired.ExpiresAt = time.Now().UTC().Add(-time.Second)
	publishCaptureRequest(t, f, expired)
	awaitCapture(t, runtime, "failed")
	write(t, config.PreliminaryCapture.RequestFile, raw)
	awaitCapture(t, runtime, "complete")
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	runtime, err = initialcontrol.Start(t.Context(), f.admission)
	if err != nil {
		t.Fatal(err)
	}
	// Restart elects a new real term. The old signed request cannot be upgraded
	// or substituted even though its previous immutable receipt remains valid.
	if runtime.GlobalAuthority().Epoch <= int64(request.ControlEpoch) {
		t.Fatal("source restart did not advance actual election term")
	}
	awaitCapture(t, runtime, "failed")
	after, err = os.ReadFile(receiptPath)
	if err != nil || !bytes.Equal(after, receiptRaw) {
		t.Fatal("old-term restart changed preliminary evidence", err)
	}
	retireCaptureSource(t, f, runtime)
}

func retireCaptureSource(t *testing.T, f *fixture, runtime *initialcontrol.Runtime) {
	t.Helper()
	nc := client(t, f.config, f.config.Regional.Runtime)
	js, _ := jetstream.New(nc)
	leaders, err := js.KeyValue(t.Context(), "ORCH_LEADERS")
	if err != nil {
		t.Fatal(err)
	}
	entry, err := leaders.Get(t.Context(), "authority.regional")
	if err != nil {
		t.Fatal(err)
	}
	var lease struct {
		AuthorityId          string
		Epoch                int64
		CandidateId, LeaseId string
		IssuedAt             time.Time
		DurationMilliseconds int64
	}
	if err := json.Unmarshal(entry.Value(), &lease); err != nil {
		t.Fatal(err)
	}
	command, err := hostmanifest.NewApplyManifestCommand("retire-after-preliminary", f.proof.Identity().ManifestSHA256, hostmanifest.HostManifest{})
	if err != nil {
		t.Fatal(err)
	}
	commandRaw, _ := json.Marshal(command)
	auth := nodeauthority.CommandAuthorization{NodeID: f.config.NodeID, AuthorityID: lease.AuthorityId, Epoch: lease.Epoch, CandidateID: lease.CandidateId, LeaseID: lease.LeaseId, ExpiresAt: lease.IssuedAt.Add(time.Duration(lease.DurationMilliseconds) * time.Millisecond), Command: commandRaw}
	if err := f.epochs.Admit(auth); err != nil {
		t.Fatal(err)
	}
	digest, _ := hostmanifest.HostManifestSha256(command.Manifest)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := f.epochs.RetireInitialR1(ctx, nodeauthority.InitialR1AdmissionDirectory, f.proof.Identity(), auth, command.CommandId, command.ExpectedManifestSha256, digest); err != nil {
		t.Fatal(err)
	}
	select {
	case <-runtime.Completion():
	case <-ctx.Done():
		t.Fatal("capture worker prevented retirement shutdown")
	}
	if _, err := initialcontrol.Start(t.Context(), f.admission); err == nil {
		t.Fatal("retired source reopened capture broker")
	}
	// The receipt remains immutable evidence after retirement, not live authority.
	raw, err := os.ReadFile(filepath.Join(f.config.PreliminaryCapture.OutputDir, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(raw)
	if runtime.PreliminaryCapture().ReceiptSHA256 != "" && runtime.PreliminaryCapture().ReceiptSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("retirement replaced capture receipt")
	}
}

package nodeauthority

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestBootstrapAdmissionPinsAndRetiresAcrossRestart(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := NewEpochStore(directory, "gru-1")
	if err != nil {
		t.Fatal(err)
	}
	grant, manifest := strings.Repeat("a", 64), strings.Repeat("b", 64)
	if err = store.AdmitBootstrap(grant, manifest); err != nil {
		t.Fatal(err)
	}
	if runtime, err := store.AdmittedManifest(manifest); err != nil || runtime {
		t.Fatalf("bootstrap admission runtime=%v err=%v", runtime, err)
	}
	if err = store.AdmitBootstrap(strings.Repeat("c", 64), manifest); err == nil {
		t.Fatal("replacement grant admitted")
	}
	if err = store.AdmitBootstrap(grant, strings.Repeat("c", 64)); err == nil {
		t.Fatal("replacement manifest admitted")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewEpochStore(directory, "gru-1")
	if err != nil {
		t.Fatal(err)
	}
	if err = store.AdmitBootstrap(grant, manifest); err != nil {
		t.Fatal(err)
	}
	if err = store.AdmitRuntimeManifest(strings.Repeat("c", 64), manifest); err == nil {
		t.Fatal("runtime manifest admitted without actual epoch")
	}
	command := CommandAuthorization{NodeID: "gru-1", AuthorityID: "gru-regional", Epoch: 7, CandidateID: "gru-controller-1", LeaseID: "actual-lease"}
	if err = store.Admit(command); err != nil {
		t.Fatal(err)
	}
	if err = store.AdmitBootstrap(grant, manifest); err == nil {
		t.Fatal("bootstrap survived runtime handoff")
	}
	if err = store.AdmitRuntimeManifest(strings.Repeat("c", 64), manifest); err != nil {
		t.Fatal(err)
	}
	if _, err = store.AdmittedManifest(manifest); err != nil {
		t.Fatal("previous admission lost before manifest fsync")
	}
	if err = store.CommitRuntimeManifest(strings.Repeat("c", 64)); err != nil {
		t.Fatal(err)
	}
	if _, err = store.AdmittedManifest(manifest); err == nil {
		t.Fatal("superseded desired manifest admitted")
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewEpochStore(directory, "gru-1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.AdmitBootstrap(grant, manifest); err == nil {
		t.Fatal("bootstrap reopened after restart")
	}
	if runtime, err := store.AdmittedManifest(strings.Repeat("c", 64)); err != nil || !runtime {
		t.Fatalf("runtime admission %v %v", runtime, err)
	}
	if err = os.WriteFile(filepath.Join(directory, "manifest-admission.json"), []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = store.AdmittedManifest(strings.Repeat("c", 64)); err == nil {
		t.Fatal("corrupt manifest admission accepted")
	}
	if err = store.AdmitRuntimeManifest(manifest, strings.Repeat("c", 64)); err == nil {
		t.Fatal("corrupt admission silently replaced")
	}
}

func TestPendingRuntimeManifestKeepsActualDiskAdmission(t *testing.T) {
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal(err)
	}
	store, err := NewEpochStore(directory, "gru-1")
	if err != nil {
		t.Fatal(err)
	}
	a, b, c := strings.Repeat("a", 64), strings.Repeat("b", 64), strings.Repeat("c", 64)
	if err = store.AdmitBootstrap(strings.Repeat("d", 64), a); err != nil {
		t.Fatal(err)
	}
	if err = store.Admit(CommandAuthorization{NodeID: "gru-1", AuthorityID: "gru-regional", Epoch: 7, CandidateID: "gru-controller-1", LeaseID: "actual-lease"}); err != nil {
		t.Fatal(err)
	}
	// Both publication attempts fail before replacing the actual disk manifest A.
	if err = store.AdmitRuntimeManifest(b, a); err != nil {
		t.Fatal(err)
	}
	if err = store.AdmitRuntimeManifest(c, a); err != nil {
		t.Fatal(err)
	}
	if err = store.Close(); err != nil {
		t.Fatal(err)
	}
	store, err = NewEpochStore(directory, "gru-1")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if runtime, err := store.AdmittedManifest(a); err != nil || !runtime {
		t.Fatalf("disk admission lost after failed updates: %v %v", runtime, err)
	}
	if _, err = store.AdmittedManifest(b); err == nil {
		t.Fatal("superseded pending manifest stayed admitted")
	}
	if err = store.AdmitRuntimeManifest(c, a); err != nil {
		t.Fatal(err)
	}
	if err = store.CommitRuntimeManifest(c); err != nil {
		t.Fatal(err)
	}
	if _, err = store.AdmittedManifest(a); err == nil {
		t.Fatal("old disk admission retained after successful commit")
	}
}

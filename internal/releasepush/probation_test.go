package releasepush

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"testing"
	"time"
)

// onProbation lays out a state dir and binary just after install swapped in "new".
func onProbation(t *testing.T, installed time.Time) (state, binary string) {
	t.Helper()
	state = t.TempDir()
	binary = filepath.Join(t.TempDir(), "terrascale-orchestrator")
	for path, data := range map[string]string{binary: "new", binary + ".prev": "old"} {
		if err := os.WriteFile(path, []byte(data), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(state, "nats"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := writeJSON(trialFile(state), trial{SHA: testSHA, RunID: "100", Installed: installed}); err != nil {
		t.Fatal(err)
	}
	return state, binary
}

func assertRolledBack(t *testing.T, state, binary string) {
	t.Helper()
	data, _ := os.ReadFile(binary)
	_, prev := os.Stat(binary + ".prev")
	_, marker := os.Stat(trialFile(state))
	record := readRollback(rollbackFile(state))
	if string(data) != "old" || !os.IsNotExist(prev) || !os.IsNotExist(marker) || record == nil || record.SHA != testSHA || record.RunID != "100" {
		t.Fatalf("binary %q prev %v marker %v record %+v", data, prev, marker, record)
	}
}

func TestProbationRollsBackAfterFailedStarts(t *testing.T) {
	now := time.Now()
	state, binary := onProbation(t, now)
	for start := 1; start <= trialStarts; start++ {
		p, err := probe(state, binary, testSHA, now, io.Discard, func() { t.Error("exit") })
		if err != nil || p == nil {
			t.Fatalf("start %d: probation %v err %v", start, p, err)
		}
		p.timer.Stop() // this start crashed before serving
	}
	if _, err := probe(state, binary, testSHA, now, io.Discard, nil); err == nil || !strings.Contains(err.Error(), "rolled back release "+testSHA) {
		t.Fatalf("third start err = %v", err)
	}
	assertRolledBack(t, state, binary)
	// The restored binary is not on probation.
	if p, err := probe(state, binary, strings.Repeat("e", 40), now, io.Discard, nil); p != nil || err != nil {
		t.Fatalf("restored start: probation %v err %v", p, err)
	}
}

func TestProbationRollsBackAtDeadline(t *testing.T) {
	now := time.Now()
	state, binary := onProbation(t, now.Add(-probationWait))
	if _, err := probe(state, binary, testSHA, now, io.Discard, nil); err == nil {
		t.Fatal("a start past the deadline did not roll back")
	}
	assertRolledBack(t, state, binary)

	// A start that hangs rolls back and exits at the deadline.
	state, binary = onProbation(t, now.Add(-probationWait+50*time.Millisecond))
	exited := make(chan struct{})
	if _, err := probe(state, binary, testSHA, now, io.Discard, func() { close(exited) }); err != nil {
		t.Fatal(err)
	}
	select {
	case <-exited:
	case <-time.After(5 * time.Second):
		t.Fatal("no rollback at the deadline")
	}
	assertRolledBack(t, state, binary)
}

func TestProbationServedClearsMarker(t *testing.T) {
	now := time.Now()
	state, binary := onProbation(t, now.Add(-probationWait+50*time.Millisecond))
	p, err := probe(state, binary, testSHA, now, io.Discard, func() { t.Error("exit after serving") })
	if err != nil || p == nil {
		t.Fatalf("probation %v err %v", p, err)
	}
	p.Served()
	time.Sleep(100 * time.Millisecond) // past the deadline
	data, _ := os.ReadFile(binary)
	_, marker := os.Stat(trialFile(state))
	if string(data) != "new" || !os.IsNotExist(marker) || readRollback(rollbackFile(state)) != nil {
		t.Fatalf("binary %q marker %v after serving", data, marker)
	}
	// A marker for another binary (an install that never swapped) is dropped.
	state, binary = onProbation(t, now)
	if p, err := probe(state, binary, strings.Repeat("e", 40), now, io.Discard, nil); p != nil || err != nil {
		t.Fatalf("foreign marker: probation %v err %v", p, err)
	}
	if _, err := os.Stat(trialFile(state)); !os.IsNotExist(err) {
		t.Fatalf("foreign marker kept: %v", err)
	}
}

func TestOrchRefusesRolledBackRun(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	h, binary := testHandler(t, i, now, []byte("new"))
	h.rolledBack.Store(&Rollback{SHA: testSHA, RunID: "100", Reason: "exited 2 times before serving"})
	retry := i.sign(t, goodClaims(now))
	if reply := h.orch(context.Background(), orchRequest(t, retry, []byte("new"), nil)); reply.State != "rolled_back" || reply.RolledBack != testSHA {
		t.Fatalf("retry reply = %+v", reply)
	}
	if data, _ := os.ReadFile(binary); string(data) != "old" {
		t.Fatalf("binary = %q after a refused retry", data)
	}
	// A newer run of the same commit installs on probation and clears the record.
	newer := i.sign(t, with(goodClaims(now), "run_id", "101"))
	reply := h.orch(context.Background(), orchRequest(t, newer, []byte("new"), func(r *OrchRelease) {
		r.Binaries[runtime.GOARCH] = Binary{URL: ReleaseURL(testSHA, "101", runtime.GOARCH), SHA256: r.Binaries[runtime.GOARCH].SHA256}
	}))
	var marker trial
	data, _ := os.ReadFile(h.TrialFile)
	if reply.State != "installed" || h.version().RolledBack != "" || json.Unmarshal(data, &marker) != nil || marker.SHA != testSHA || marker.RunID != "101" {
		t.Fatalf("newer run reply = %+v version %+v marker %s", reply, h.version(), data)
	}
}

func TestInstallImmutableBinary(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	h, binary := testHandler(t, i, now, []byte("new"))
	link = func(old, new string) error { return &os.LinkError{Op: "link", Old: old, New: new, Err: syscall.EPERM} }
	t.Cleanup(func() { link = os.Link })
	reply := h.orch(context.Background(), orchRequest(t, i.sign(t, goodClaims(now)), []byte("new"), nil))
	if reply.State != "rejected" || !strings.Contains(reply.Error, "chattr -i "+binary) {
		t.Fatalf("reply = %+v", reply)
	}
	data, _ := os.ReadFile(binary)
	_, next := os.Stat(binary + ".next")
	_, marker := os.Stat(h.TrialFile)
	if string(data) != "old" || !os.IsNotExist(next) || !os.IsNotExist(marker) {
		t.Fatalf("binary %q next %v marker %v", data, next, marker)
	}
}

func TestPushRegionReportsRollback(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	srv, auth, url, pin := startServerIn(t, i.verifier(now), t.TempDir())
	local, err := auth.Connect(srv)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	// The restored binary serves: it reports the release it rolled back.
	h := &Handler{Verifier: i.verifier(now), Revision: strings.Repeat("e", 40), pending: testSHA}
	h.rolledBack.Store(&Rollback{SHA: testSHA, RunID: "99", Reason: "not serving 2m0s after install"})
	if err := h.Serve(local); err != nil {
		t.Fatal(err)
	}
	release := OrchRelease{SHA: testSHA, Token: i.sign(t, goodClaims(now)), Binaries: map[string]Binary{
		runtime.GOARCH: {URL: ReleaseURL(testSHA, "100", runtime.GOARCH), SHA256: strings.Repeat("0", 64)},
	}}
	result := pushRegion(t.Context(), Region{Region: "gru", NATS: url, SPKISHA256: pin}, release)
	if result.State != "rolled_back" || !strings.Contains(result.Error, "not serving") || result.ServingMS != 0 {
		t.Fatalf("result = %+v", result)
	}
}

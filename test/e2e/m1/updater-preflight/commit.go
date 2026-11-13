package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

var (
	shaA = strings.Repeat("a", 40)
	shaB = strings.Repeat("b", 40)
	shaC = strings.Repeat("c", 40)
	shaD = strings.Repeat("d", 40)
	shaE = strings.Repeat("e", 40)
)

func stamped(data []byte, sha, mode string) []byte {
	before := []byte("vcs.revision=" + releasepush.Revision())
	require(bytes.Contains(data, before), "journey helper must have a clean build revision")
	return append(bytes.ReplaceAll(data, before, []byte("vcs.revision="+sha)), []byte("\nCANDIDATE:"+mode)...)
}

func writeExecutable(path string, data []byte) {
	syscall.ForkLock.RLock()
	defer syscall.ForkLock.RUnlock()
	must(os.WriteFile(path, data, 0o755))
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func record(path string) map[string]any {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	must(err)
	var value map[string]any
	must(json.Unmarshal(data, &value))
	return value
}

func fence(work string) string {
	data, err := os.ReadFile(filepath.Join(work, "nats/release-run-id"))
	if os.IsNotExist(err) {
		return ""
	}
	must(err)
	return string(data)
}

func read(path string) []byte {
	data, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil
	}
	must(err)
	return data
}

func revisionOf(path string) string {
	info, err := buildinfo.ReadFile(path)
	must(err)
	for _, setting := range info.Settings {
		if setting.Key == "vcs.revision" {
			return setting.Value
		}
	}
	return "unknown"
}

func listener(h *releasepush.Handler) (*nats.Conn, func()) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, NoLog: true})
	must(err)
	go srv.Start()
	require(srv.ReadyForConnections(5*time.Second), "release listener must listen")
	conn, err := nats.Connect(srv.ClientURL())
	must(err)
	must(h.Serve(conn))
	return conn, func() { conn.Close(); srv.Shutdown() }
}

func hostBytes() ([]byte, []byte) {
	helper, err := os.Executable()
	must(err)
	data := read(helper)
	return stamped(data, shaA, "original"), stamped(data, shaB, "pass")
}

func preparedHost(work string) (*releasepush.Handler, []byte, []byte) {
	must(os.MkdirAll(filepath.Join(work, "nats"), 0o700))
	original, candidate := hostBytes()
	binary := filepath.Join(work, "installed")
	if _, err := os.Stat(binary); os.IsNotExist(err) {
		writeExecutable(binary, original)
		write(binary+".prev", "superseded")
		write(binary+".prev.staged", "leftover")
		writeExecutable(filepath.Join(work, "asset"), candidate)
		write(filepath.Join(work, "nats/release-run-id"), "1")
	}
	h, err := releasepush.NewHandler(work)
	must(err)
	h.Binary, h.Revision = binary, revisionOf(binary)
	return h, original, candidate
}

func installAsset(ctx context.Context, h *releasepush.Handler, conn *nats.Conn, asset, sha, run string) releasepush.Reply {
	release, verifier, client, closeProvider := signedRelease(ctx, asset, sha, run, "1")
	defer closeProvider()
	h.Verifier, h.Client = verifier, client
	payload, err := json.Marshal(release)
	must(err)
	return request(ctx, conn, releasepush.SubjectOrch, payload)
}

func installRequest(ctx context.Context, h *releasepush.Handler, conn *nats.Conn, work, sha, run string) releasepush.Reply {
	return installAsset(ctx, h, conn, filepath.Join(work, "asset"), sha, run)
}

func otherAsset(work, sha string) string {
	helper, err := os.Executable()
	must(err)
	path := filepath.Join(work, "asset-"+sha[:1])
	if read(path) == nil {
		writeExecutable(path, stamped(read(helper), sha, "pass"))
	}
	return path
}

func commitCase(ctx context.Context, work, outcome string) {
	h, _, _ := preparedHost(work)
	if outcome == "persistent" {
		write(filepath.Join(work, "armed"), "ready")
		must(syscall.Exec(h.Binary, []string{h.Binary, "self-update", work, "postcommit-failures"}, os.Environ()))
	}
	conn, closeListener := listener(h)
	defer closeListener()
	h.Relay = func(context.Context, []byte) []releasepush.HostVersion { return nil }
	write(filepath.Join(work, "armed"), "ready")
	reply := installRequest(ctx, h, conn, work, shaB, "2")
	switch outcome {
	case "rejected":
		require(reply.State == "rejected" && reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalHost, fmt.Sprintf("precommit failure must be a host refusal: %+v", reply))
	case "installed", "busy":
		require(reply.State == "installed", fmt.Sprintf("postcommit failure must stay installed: %+v", reply))
		select {
		case <-h.Installed:
		case <-ctx.Done():
			panic("installed release must request restart")
		}
	}
	fmt.Println("traced install:", reply.State)
}

func stageCase(ctx context.Context, work string, starts int, mode string) {
	h, _, _ := preparedHost(work)
	conn, closeListener := listener(h)
	reply := installRequest(ctx, h, conn, work, shaB, "2")
	closeListener()
	require(reply.State == "installed", fmt.Sprintf("staged candidate must install: %+v", reply))
	setStarts(work, starts)
	write(filepath.Join(work, "armed"), "ready")
	must(syscall.Exec(h.Binary, []string{h.Binary, "start-state", work, mode}, os.Environ()))
}

func setStarts(work string, starts int) {
	path := filepath.Join(work, "nats/release-trial")
	trial := record(path)
	trial["starts"] = starts
	data, err := json.Marshal(trial)
	must(err)
	must(os.WriteFile(path, data, 0o600))
}

type started struct {
	Revision    string `json:"revision"`
	State       string `json:"state"`
	Error       string `json:"error"`
	RolledBack  string `json:"rolled_back"`
	HealthState string `json:"health_state"`
	Served      bool   `json:"served"`
	After       string `json:"after"`
	Restarts    int    `json:"restarts"`
}

func startState(ctx context.Context, work, mode string) {
	probation, err := releasepush.Probe(work, os.Stdout)
	if err != nil {
		require(strings.Contains(err.Error(), "rolled back"), "a failed start must be a rollback: "+err.Error())
		fmt.Println("START rolled-back")
		return
	}
	h, err := releasepush.NewHandler(work)
	must(err)
	conn, closeListener := listener(h)
	defer closeListener()
	version := request(ctx, conn, releasepush.SubjectVersion, nil)
	health := request(ctx, conn, releasepush.SubjectHealth, nil)
	result := started{Revision: h.Revision, State: version.State, Error: version.Error, RolledBack: version.RolledBack, HealthState: health.State}
	if mode == "race" {
		replacement := installAsset(ctx, h, conn, otherAsset(work, shaC), shaC, "3")
		require(replacement.State == "installed", fmt.Sprintf("a replacement must install before confirmation: %+v", replacement))
	}
	if mode == "serve" || mode == "race" {
		result.Served = probation.Served()
		result.After = request(ctx, conn, releasepush.SubjectVersion, nil).State
	}
	data, err := json.Marshal(result)
	must(err)
	fmt.Println(string(data))
}

func startOnce(ctx context.Context, work, mode string) string {
	output, err := exec.CommandContext(ctx, filepath.Join(work, "installed"), "start-state", work, mode).CombinedOutput()
	require(err == nil, fmt.Sprintf("installed binary must start: %v: %s", err, output))
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	return lines[len(lines)-1]
}

func startInstalled(ctx context.Context, work, mode string) started {
	for restarts := range 3 {
		last := startOnce(ctx, work, mode)
		if last == "START rolled-back" {
			continue
		}
		var result started
		must(json.Unmarshal([]byte(last), &result))
		result.Restarts = restarts
		return result
	}
	panic("installed binary kept rolling back")
}

func resumeCase(ctx context.Context, work, flow string) {
	original, candidate := hostBytes()
	installed := read(filepath.Join(work, "installed"))
	swapped := bytes.Equal(installed, candidate)
	require(swapped || bytes.Equal(installed, original), "installed binary must be exactly the original or the candidate")
	switch flow {
	case "commit":
		resumeCommit(ctx, work, swapped, original)
	case "rollback":
		resumeRollback(ctx, work, original)
	case "replace":
		resumeReplace(ctx, work, swapped, false)
	case "damaged-replace":
		resumeReplace(ctx, work, swapped, true)
	case "rollback-kept":
		trial := record(filepath.Join(work, "nats/release-trial"))
		decided := record(filepath.Join(work, "nats/release-rolled-back"))
		require(!swapped && trial != nil && trial["sha"] == shaB && decided != nil && decided["sha"] == shaB, fmt.Sprintf("a rollback whose directory sync failed keeps the trial beside its record: %v %v", trial, decided))
		resumeRollback(ctx, work, original)
		require(record(filepath.Join(work, "nats/release-trial")) == nil, "the next start finishes the rollback and removes the trial")
	case "expiry":
		require(swapped && bytes.Equal(read(filepath.Join(work, "installed.prev")), original), "the replacement must be committed with the incumbent at .prev")
		trial := record(filepath.Join(work, "nats/release-trial"))
		require(trial != nil && trial["sha"] == shaB && trial["run_id"] == "2" && trial["failure"] == nil, fmt.Sprintf("an expiry after the replacement committed must leave its trial: %v", trial))
		state := startInstalled(ctx, work, "hold")
		require(state.Revision == shaB && state.State == "probation" && record(filepath.Join(work, "nats/release-trial"))["starts"] == float64(1), fmt.Sprintf("the replacement starts on probation: %+v", state))
		fmt.Println("resume expiry: replacement trial intact; replacement on probation")
	case "settle":
		require(swapped && bytes.Equal(read(filepath.Join(work, "nats/release-trial")), read(filepath.Join(work, "before-trial"))), "a leftover trial is kept while the binary directory cannot be synced")
		state := startInstalled(ctx, work, "serve")
		require(state.Revision == shaB && state.State == "" && state.Served && record(filepath.Join(work, "nats/release-trial")) == nil, fmt.Sprintf("the next start removes the leftover trial: %+v", state))
		fmt.Println("resume settle: leftover kept after failed sync; removed at the next start")
	case "confirm":
		require(swapped, "a confirming candidate must stay installed")
		state := startInstalled(ctx, work, "serve")
		require(state.Revision == shaB && state.Restarts == 0 && state.Served && (state.State == "probation" || state.State == ""), fmt.Sprintf("served candidate must confirm without rollback: %+v", state))
		require(record(filepath.Join(work, "nats/release-trial")) == nil, "confirmation must remove the trial")
		h, _, _ := preparedHost(work)
		conn, closeListener := listener(h)
		defer closeListener()
		require(installRequest(ctx, h, conn, work, shaB, "2").State == "current", "confirmed candidate must be current")
		fmt.Println("resume confirm: candidate", state.State, "-> confirmed")
	}
}

func requireProtected(work string, original []byte, run string) {
	require(bytes.Equal(read(filepath.Join(work, "installed.prev")), original), "a swapped binary must keep the exact previous binary at .prev")
	require(fence(work) == run, "a swapped binary must have its run fence: "+fence(work))
	trial := record(filepath.Join(work, "nats/release-trial"))
	require(trial != nil && trial["sha"] == shaB && trial["run_id"] == run, "a swapped binary must have its trial")
}

func resumeCommit(ctx context.Context, work string, swapped bool, original []byte) {
	if swapped {
		first := startInstalled(ctx, work, "hold")
		require(first.Revision == shaB && first.State == "probation" && first.Restarts == 0, fmt.Sprintf("swapped candidate must start on probation: %+v", first))
		requireProtected(work, original, "2")
	} else {
		require(fence(work) == "1" || fence(work) == "2", "the run fence must never fall: "+fence(work))
	}
	state := startInstalled(ctx, work, "serve")
	requireUnstaged(work)
	if swapped {
		require(state.Revision == shaB && state.State == "probation" && state.Served && state.Restarts == 0, fmt.Sprintf("swapped candidate must start on probation and confirm: %+v", state))
	} else {
		require(state.Revision == shaA && state.State == "" && state.Served, fmt.Sprintf("original binary must start unaffected: %+v", state))
	}
	h, _, _ := preparedHost(work)
	conn, closeListener := listener(h)
	defer closeListener()
	reply := installRequest(ctx, h, conn, work, shaB, "2")
	if swapped {
		require(reply.State == "current", fmt.Sprintf("retry of the installed run must be current: %+v", reply))
	} else {
		require(reply.State == "installed", fmt.Sprintf("retry of the same run must install: %+v", reply))
		requireProtected(work, original, "2")
		retried := startInstalled(ctx, work, "serve")
		require(retried.Revision == shaB && retried.State == "probation" && retried.Served, fmt.Sprintf("retried candidate must start on probation: %+v", retried))
	}
	stale := installAsset(ctx, h, conn, otherAsset(work, shaC), shaC, "1")
	require(stale.State == "stale", fmt.Sprintf("an older run must be refused after recovery: %+v", stale))
	fmt.Println("resume commit: swapped", swapped, "-> start", state.State, "-> retry", reply.State, "-> older run stale")
}

func resumeRollback(ctx context.Context, work string, original []byte) {
	state := startInstalled(ctx, work, "serve")
	require(bytes.Equal(read(filepath.Join(work, "installed")), original), "rollback must restore the exact previous bytes")
	require(read(filepath.Join(work, "installed.prev")) == nil, "the restored binary leaves no .prev")
	require(state.Revision == shaA && state.RolledBack == shaB && state.Served, fmt.Sprintf("restored binary must report the rollback: %+v", state))
	rollback := record(filepath.Join(work, "nats/release-rolled-back"))
	require(rollback != nil && rollback["sha"] == shaB && rollback["run_id"] == "2", "rollback record must name the rejected run")
	h, _, _ := preparedHost(work)
	conn, closeListener := listener(h)
	defer closeListener()
	replay := installRequest(ctx, h, conn, work, shaB, "2")
	require(replay.State == "rolled_back" && replay.RolledBack == shaB, fmt.Sprintf("the rejected run must be refused on replay: %+v", replay))
	stale := installAsset(ctx, h, conn, otherAsset(work, shaC), shaC, "1")
	require(stale.State == "stale", fmt.Sprintf("an older run must be refused after rollback: %+v", stale))
	fmt.Println("resume rollback: restarts", state.Restarts, "; previous bytes restored; replay rolled_back; older run stale")
}

func requireUnstaged(work string) {
	require(read(filepath.Join(work, "nats/release-trial.staged")) == nil && read(filepath.Join(work, "installed.prev.staged")) == nil, "no staged trial or previous copy is left after a start")
}

func probationHost(work string, starts int, damaged bool) {
	must(os.MkdirAll(filepath.Join(work, "nats"), 0o700))
	original, candidate := hostBytes()
	helper, err := os.Executable()
	must(err)
	previous := stamped(read(helper), shaD, "original")
	binary := filepath.Join(work, "installed")
	writeExecutable(binary, original)
	writeExecutable(binary+".prev", previous)
	writeExecutable(filepath.Join(work, "asset"), candidate)
	write(filepath.Join(work, "nats/release-run-id"), "1")
	trial := fmt.Sprintf(`{"sha":%q,"sha256":%q,"run_id":"1","installed":%q,"starts":%d,"previous":{"sha":%q,"sha256":%q}}`, shaA, digest(original), time.Now().UTC().Format(time.RFC3339Nano), starts, shaD, digest(previous))
	if damaged {
		trial = "{"
	}
	write(filepath.Join(work, "nats/release-trial"), trial)
	write(filepath.Join(work, "nats/release-rolled-back"), fmt.Sprintf(`{"sha":%q,"sha256":%q,"run_id":"0","reason":"earlier release rolled back"}`, shaE, digest([]byte(shaE))))
	for name, path := range map[string]string{"before-trial": "nats/release-trial", "before-prev": "installed.prev", "before-record": "nats/release-rolled-back"} {
		must(os.WriteFile(filepath.Join(work, name), read(filepath.Join(work, path)), 0o600))
	}
}

func requireIncumbent(work string) {
	for name, path := range map[string]string{"before-trial": "nats/release-trial", "before-prev": "installed.prev", "before-record": "nats/release-rolled-back"} {
		require(bytes.Equal(read(filepath.Join(work, path)), read(filepath.Join(work, name))), "a replacement that did not commit must leave "+path+" byte for byte")
	}
}

func replaceCase(ctx context.Context, work string, damaged bool) {
	probationHost(work, 1, damaged)
	h, err := releasepush.NewHandler(work)
	must(err)
	h.Binary, h.Revision = filepath.Join(work, "installed"), shaA
	conn, closeListener := listener(h)
	defer closeListener()
	h.Relay = func(context.Context, []byte) []releasepush.HostVersion { return nil }
	write(filepath.Join(work, "armed"), "ready")
	reply := installRequest(ctx, h, conn, work, shaB, "2")
	require(reply.State == "rejected" && reply.Refusal != nil, fmt.Sprintf("a failed replacement must be refused: %+v", reply))
	requireIncumbent(work)
	require(read(filepath.Join(work, "nats/release-trial.staged")) == nil && read(filepath.Join(work, "installed.prev.staged")) == nil, "a failed replacement removes only its staged files")
	fmt.Println("traced replace:", reply.State)
}

func resumeReplace(ctx context.Context, work string, swapped, damaged bool) {
	original, _ := hostBytes()
	trialPath := filepath.Join(work, "nats/release-trial")
	if !swapped {
		requireIncumbent(work)
		if damaged {
			state := startInstalled(ctx, work, "serve")
			require(state.Revision == shaA && state.State == "unconfirmed" && state.HealthState == "unconfirmed" && !state.Served && string(read(trialPath)) == "{", fmt.Sprintf("a damaged incumbent trial stays the active unconfirmed marker: %+v", state))
			requireUnstaged(work)
			fmt.Println("resume damaged replace: incumbent unconfirmed by its damaged trial; staged files removed")
			return
		}
		state := startInstalled(ctx, work, "hold")
		require(state.Revision == shaA && state.State == "probation" && record(trialPath)["starts"] == float64(2), fmt.Sprintf("the incumbent stays on probation: %+v %v", state, record(trialPath)))
		requireUnstaged(work)
		require(startOnce(ctx, work, "hold") == "START rolled-back" && bytes.Equal(read(filepath.Join(work, "installed")), read(filepath.Join(work, "before-prev"))), "the incumbent still rolls back to its own previous binary")
		decided := record(filepath.Join(work, "nats/release-rolled-back"))
		require(decided != nil && decided["sha"] == shaA && decided["run_id"] == "1", fmt.Sprintf("the incumbent's rollback is recorded: %v", decided))
		fmt.Println("resume replace: incumbent kept trial, .prev and record; still on probation; rolled back to its previous binary")
		return
	}
	state := startInstalled(ctx, work, "hold")
	trial := record(trialPath)
	require(state.Revision == shaB && state.State == "probation" && trial["sha"] == shaB && trial["run_id"] == "2" && trial["starts"] == float64(1), fmt.Sprintf("the committed replacement starts on its own trial: %+v %v", state, trial))
	require(bytes.Equal(read(filepath.Join(work, "installed.prev")), original) && read(filepath.Join(work, "nats/release-rolled-back")) == nil, "the committed replacement has the incumbent at .prev and no stale rollback record")
	requireUnstaged(work)
	if damaged {
		require(string(read(trialPath+".damaged")) == "{", "the damaged incumbent trial is archived")
	}
	fmt.Println("resume replace: replacement on probation with its trial; incumbent at .prev")
}

func expiryRaceCase(work string) {
	probationHost(work, 0, false)
	must(os.Remove(filepath.Join(work, "nats/release-rolled-back")))
	binary := filepath.Join(work, "installed")
	must(syscall.Exec(binary, []string{binary, "expiry-race-start", work}, os.Environ()))
}

func expiryRaceStart(ctx context.Context, work string) {
	probation, err := releasepush.Probe(work, os.Stdout)
	must(err)
	require(probation != nil, "the incumbent must start on probation")
	h, err := releasepush.NewHandler(work)
	must(err)
	conn, closeListener := listener(h)
	defer closeListener()
	h.Relay = func(context.Context, []byte) []releasepush.HostVersion { return nil }
	write(filepath.Join(work, "armed"), "ready")
	reply := installRequest(ctx, h, conn, work, shaB, "2")
	state := request(ctx, conn, releasepush.SubjectVersion, nil).State
	<-h.Installed
	fmt.Println("traced expiry race:", reply.State, state)
}

func settleCase(work string) {
	must(os.MkdirAll(filepath.Join(work, "nats"), 0o700))
	_, candidate := hostBytes()
	binary := filepath.Join(work, "installed")
	writeExecutable(binary, candidate)
	write(filepath.Join(work, "nats/release-trial"), fmt.Sprintf(`{"sha":%q,"sha256":%q,"run_id":"3","installed":%q,"starts":1}`, shaB, digest([]byte("another build")), time.Now().UTC().Format(time.RFC3339Nano)))
	must(os.WriteFile(filepath.Join(work, "before-trial"), read(filepath.Join(work, "nats/release-trial")), 0o600))
	write(filepath.Join(work, "armed"), "ready")
	must(syscall.Exec(binary, []string{binary, "start-state", work, "serve"}, os.Environ()))
}

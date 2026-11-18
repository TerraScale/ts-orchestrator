package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/secretpreflight"
	"github.com/nats-io/nats.go"
	"golang.org/x/sys/unix"
)

func temporary(prefix string) (string, func()) {
	path, err := os.MkdirTemp("", prefix)
	must(err)
	return path, func() { must(os.RemoveAll(path)) }
}

func run(ctx context.Context, binary, previous string) {
	must(exec.CommandContext(ctx, binary, "release", "preflight").Run())
	work, cleanup := temporary("updater-preflight-")
	defer cleanup()
	h, original, _ := preparedHost(work)
	conn, closeListener := listener(h)
	defer closeListener()
	helper, err := os.Executable()
	must(err)
	data, err := os.ReadFile(helper)
	must(err)
	probationDone := make(chan struct{})
	go func() {
		rollbackCases(ctx)
		lostRollbackCase(ctx)
		confirmRaceCase(ctx)
		mainFormatCase(ctx)
		staleRecordCase(ctx)
		upgradeCases(ctx, data, previous)
		close(probationDone)
	}()
	preflightDone := make(chan struct{})
	go func() {
		preflightCases(ctx, work, h, conn, data, original)
		damagedCases(ctx)
		fenceCase(ctx)
		networkCases(ctx, work, h, conn, data)
		slowWriteCase(ctx)
		close(preflightDone)
	}()
	watchdogDone := make(chan struct{})
	go func() {
		watchdogCase(ctx, binary)
		close(watchdogDone)
	}()
	replacementCase(ctx)
	rebuildCase(ctx)
	<-preflightDone
	<-probationDone
	<-watchdogDone
	crossFilesystem(ctx)
	selfExitCase(ctx, data)
	fmt.Println("updater-preflight e2e: PASS")
}

func preflightCases(ctx context.Context, work string, h *releasepush.Handler, conn *nats.Conn, data, original []byte) {
	for i, mode := range []string{"refuse", "noise", "cannot-execute", "hang"} {
		candidate := stamped(data, shaB, mode)
		if mode == "cannot-execute" {
			candidate = []byte("invalid executable")
		}
		writeExecutable(filepath.Join(work, "asset"), candidate)
		start := time.Now()
		reply := installRequest(ctx, h, conn, work, shaB, fmt.Sprint(i+2))
		require(reply.State == "rejected" && reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalHost && reply.Refusal.Preflight, "candidate preflight failure must be a structured host refusal")
		require(reply.Refusal.SHA256 == digest(candidate) && reply.Refusal.RunID != "", "refusal must name candidate digest and attempt")
		require(bytes.Equal(read(h.Binary), original) && record(h.TrialFile) == nil && string(read(h.Binary+".prev")) == "superseded", "preflight refusal must stage nothing")
		require(fence(work) == "1", "refusal must preserve the run fence")
		reported := request(ctx, conn, releasepush.PullSubject("stg", "host"), nil).Refusal
		require(reported != nil && reported.SHA256 == digest(candidate), "the installed binary must report its refusal")
		require(len(reply.Refusal.Reason) <= secretpreflight.MaxOutputBytes && utf8.ValidString(reply.Refusal.Reason) && !strings.ContainsFunc(reply.Refusal.Reason, unicode.IsControl), "diagnostic must be bounded valid text")
		if mode == "hang" {
			require(time.Since(start) >= 70*time.Second && time.Since(start) < 75*time.Second, "preflight must keep its 70-second bound")
		}
		fmt.Println("ok preflight", mode, ": refused; binary, fence and probation unchanged; refusal reported")
	}
}

func damagedCases(ctx context.Context) {
	for _, content := range []string{"", "{", "{}", "[]"} {
		work, cleanup := temporary("damaged-trial-")
		h, original, candidate := preparedHost(work)
		write(h.TrialFile, content)
		state := startInstalled(ctx, work, "serve")
		require(state.Revision == shaA && state.State == "unconfirmed" && strings.Contains(state.Error, "damaged") && state.HealthState == "unconfirmed" && !state.Served, fmt.Sprintf("a damaged trial must serve unconfirmed without adopting inventory: %q %+v", content, state))
		require(string(read(h.TrialFile)) == content && bytes.Equal(read(h.Binary), original), "a damaged trial must not be rewritten or acted on")
		again := startInstalled(ctx, work, "serve")
		require(again.State == "unconfirmed" && again.Restarts == 0, "a damaged trial stays unconfirmed on every start")
		conn, closeListener := listener(h)
		reply := installRequest(ctx, h, conn, work, shaB, "2")
		require(reply.State == "installed" && bytes.Equal(read(h.Binary), candidate), fmt.Sprintf("a replacement must reach a damaged host: %+v", reply))
		require(string(read(h.TrialFile+".damaged")) == content, "the damaged trial must be kept, not overwritten")
		write(h.TrialFile, "second "+content)
		again2 := installAsset(ctx, h, conn, otherAsset(work, shaC), shaC, "3")
		require(again2.State == "installed" && string(read(h.TrialFile+".damaged")) == content && string(read(h.TrialFile+".damaged.1")) == "second "+content && record(h.TrialFile)["sha"] == shaC, fmt.Sprintf("a later damaged trial gets its own archive: %+v", again2))
		closeListener()
		cleanup()
	}
	fmt.Println("ok damaged trial: empty, truncated, empty-object and array trials serve unconfirmed, never adopt, kept as .damaged, .damaged.1 on replacement")
}

type failTransport struct{}

func (failTransport) RoundTrip(*http.Request) (*http.Response, error) {
	return nil, errors.New("host network unavailable")
}

type interruptedTransport struct{ base http.RoundTripper }

func (t interruptedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := t.base.RoundTrip(r)
	if err != nil {
		return nil, err
	}
	response.Body.Close()
	response.Body = io.NopCloser(failedRead{})
	return response, nil
}

type failedRead struct{}

func (failedRead) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

func networkCases(ctx context.Context, work string, h *releasepush.Handler, conn *nats.Conn, data []byte) {
	writeExecutable(filepath.Join(work, "asset"), stamped(data, strings.Repeat("b", 40), "pass"))
	release, verifier, client, closeProvider := signedRelease(ctx, filepath.Join(work, "asset"), strings.Repeat("b", 40), "20", "1")
	defer closeProvider()
	payload := pulledPayload(release, "20")
	fresh := releasepush.NewVerifier()
	fresh.Client = &http.Client{Transport: failTransport{}}
	h.Verifier, h.Client = fresh, &http.Client{Transport: failTransport{}}
	reply := request(ctx, conn, releasepush.PullSubject("stg", "host"), payload)
	require(reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalHost, "unavailable attestation must be host prerequisite")
	h.Verifier = verifier
	for _, entry := range []struct {
		name      string
		transport http.RoundTripper
		kind      string
	}{
		{"download network", failTransport{}, releasepush.RefusalHost},
		{"incomplete bytes", interruptedTransport{client.Transport}, releasepush.RefusalHost},
		{"fully received digest mismatch", corruptTransport{client.Transport}, releasepush.RefusalIntegrity},
	} {
		h.Client = &http.Client{Transport: entry.transport}
		reply = request(ctx, conn, releasepush.PullSubject("stg", "host"), payload)
		require(reply.Refusal != nil && reply.Refusal.Kind == entry.kind, entry.name+" refusal must classify proven evidence")
		fmt.Println("ok classification:", entry.name, "->", entry.kind)
	}
	fmt.Println("ok classification: unavailable attestation -> host_prerequisite")
	candidate := filepath.Join(work, "noisy")
	writeExecutable(candidate, stamped(data, strings.Repeat("b", 40), "noise"))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err := secretpreflight.Check(ctx, candidate)
	runtime.ReadMemStats(&after)
	require(err != nil && strings.Contains(err.Error(), "[truncated]") && after.TotalAlloc-before.TotalAlloc < 1<<20, "10 MiB output must drain with less than 1 MiB allocation")
	fmt.Println("ok output: 10 MiB drained with less than 1 MiB allocated")
}

func stagedCandidate(ctx context.Context, prefix string) (string, func(), []byte, []byte) {
	work, cleanup := temporary(prefix)
	h, original, candidate := preparedHost(work)
	conn, closeListener := listener(h)
	reply := installRequest(ctx, h, conn, work, shaB, "2")
	closeListener()
	require(reply.State == "installed" && bytes.Equal(read(h.Binary), candidate), "candidate must install")
	requireProtected(work, original, "2")
	return work, cleanup, original, candidate
}

func rollbackCases(ctx context.Context) {
	work, cleanup, original, _ := stagedCandidate(ctx, "rolled-back-")
	for starts := 1; starts <= 2; starts++ {
		state := startInstalled(ctx, work, "hold")
		require(state.Revision == shaB && state.State == "probation" && record(filepath.Join(work, "nats/release-trial"))["starts"] == float64(starts), fmt.Sprintf("each start before serving must count: %+v", state))
	}
	resumeRollback(ctx, work, original)
	cleanup()
	fmt.Println("ok probation rolled-back: two counted starts, third start restores exact previous bytes; replay refused")
	work, cleanup, _, candidate := stagedCandidate(ctx, "wrong-previous-")
	helper, err := os.Executable()
	must(err)
	writeExecutable(filepath.Join(work, "installed.prev"), stamped(read(helper), strings.Repeat("d", 40), "pass"))
	setStarts(work, 2)
	state := startInstalled(ctx, work, "serve")
	require(state.Revision == shaB && state.State == "unconfirmed" && strings.Contains(state.Error, "not the recorded build") && !state.Served && bytes.Equal(read(filepath.Join(work, "installed")), candidate), fmt.Sprintf("a previous binary of another build must not be restored: %+v", state))
	cleanup()
	fmt.Println("ok probation wrong-previous: another build at .prev is never restored; candidate serves unconfirmed")
}

func replacementCase(ctx context.Context) {
	work, cleanup, _, candidate := stagedCandidate(ctx, "replacement-")
	defer cleanup()
	must(os.Remove(filepath.Join(work, "installed.prev")))
	setStarts(work, 2)
	state := startInstalled(ctx, work, "serve")
	require(state.Revision == shaB && state.State == "unconfirmed" && strings.Contains(state.Error, "rollback unavailable") && state.HealthState == "unconfirmed" && !state.Served, fmt.Sprintf("a missing previous binary must leave the candidate serving unconfirmed: %+v", state))
	require(record(filepath.Join(work, "nats/release-rolled-back")) == nil && record(filepath.Join(work, "nats/release-trial"))["failure"] != nil, "an impossible rollback keeps the trial with its failure and records no rollback")
	again := startInstalled(ctx, work, "serve")
	require(again.State == "unconfirmed" && record(filepath.Join(work, "nats/release-trial"))["starts"] == float64(3), "an unconfirmed candidate is not counted again")
	h, err := releasepush.NewHandler(work)
	must(err)
	h.Binary, h.Revision = filepath.Join(work, "installed"), shaB
	conn, closeListener := listener(h)
	defer closeListener()
	reply := installAsset(ctx, h, conn, otherAsset(work, shaC), shaC, "3")
	require(reply.State == "installed", fmt.Sprintf("a pulled replacement must reach an unconfirmed host: %+v", reply))
	require(bytes.Equal(read(filepath.Join(work, "installed.prev")), candidate), "replacement lost the unconfirmed previous binary")
	replaced := startInstalled(ctx, work, "serve")
	require(replaced.Revision == shaC && replaced.Served, "pulled replacement did not confirm its probation")
	fmt.Println("ok replacement: an unconfirmed host accepts a verified pull and confirms its replacement")
}

func payloadFile(work, name string, release releaseFixture) string {
	data, err := json.Marshal(release)
	must(err)
	path := filepath.Join(work, name)
	must(os.WriteFile(path, data, 0o600))
	return path
}

func previousRun(ctx context.Context, binary string, args ...string) map[string]any {
	output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	require(err == nil, fmt.Sprintf("the previous build must run on this state: %v: %s", err, output))
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var result map[string]any
	must(json.Unmarshal([]byte(lines[len(lines)-1]), &result))
	return result
}

func upgradeCases(ctx context.Context, data []byte, previous string) {
	work, cleanup := temporary("upgrade-")
	defer cleanup()
	must(os.Mkdir(filepath.Join(work, "nats"), 0o700))
	previousBytes := read(previous)
	writeExecutable(filepath.Join(work, "installed"), previousBytes)
	candidate := stamped(data, shaB, "pass")
	asset := filepath.Join(work, "asset")
	writeExecutable(asset, candidate)
	release, verifier, client, closeProvider := signedRelease(ctx, asset, shaB, "2", "1")
	defer closeProvider()
	binaryURL := client.Transport.(providerTransport).url
	installed := previousRun(ctx, previous, "install", work, payloadFile(work, "run-2.json", release), binaryURL, revisionOf(previous), verifier.JWKSURL)
	require(installed["install"] == "installed", fmt.Sprintf("the previous build must install this build: %v", installed))
	trialPath := filepath.Join(work, "nats/release-trial")
	trial := record(trialPath)
	require(trial["sha"] == shaB && trial["run_id"] == "2" && trial["starts"] == float64(0) && trial["installed"] != nil && trial["sha256"] == nil, fmt.Sprintf("the previous build leaves its own trial format: %v", trial))
	require(bytes.Equal(read(filepath.Join(work, "installed")), candidate) && bytes.Equal(read(filepath.Join(work, "installed.prev")), previousBytes) && fence(work) == "2", "the previous build leaves .prev and a decimal run fence")
	trial["installed"] = time.Now().Add(-time.Hour).UTC().Format(time.RFC3339Nano)
	encoded, err := json.Marshal(trial)
	must(err)
	must(os.WriteFile(trialPath, encoded, 0o600))
	first := startInstalled(ctx, work, "hold")
	require(first.Revision == shaB && first.State == "probation" && first.Restarts == 0 && record(trialPath)["starts"] == float64(1), fmt.Sprintf("this build's first start after the previous build installed it is on probation, an hour after install: %+v", first))
	h, err := releasepush.NewHandler(work)
	must(err)
	h.Binary, h.Revision = filepath.Join(work, "installed"), shaB
	conn, closeListener := listener(h)
	stale := installAsset(ctx, h, conn, otherAsset(work, shaC), shaC, "1")
	closeListener()
	require(stale.State == "stale" && fence(work) == "2", fmt.Sprintf("the fence the previous build wrote refuses an older run: %+v", stale))
	second := startInstalled(ctx, work, "hold")
	require(second.State == "probation" && record(trialPath)["starts"] == float64(2), fmt.Sprintf("the second start is counted: %+v %v", second, record(trialPath)))
	third := startOnce(ctx, work, "hold")
	require(third == "START rolled-back" && bytes.Equal(read(filepath.Join(work, "installed")), previousBytes) && read(filepath.Join(work, "installed.prev")) == nil, "the third start restores the previous build byte for byte: "+third)
	older, olderVerifier, _, closeOlder := signedRelease(ctx, otherAsset(work, shaC), shaC, "1", "1")
	defer closeOlder()
	restored := previousRun(ctx, filepath.Join(work, "installed"), "start", work, payloadFile(work, "replay.json", release), verifier.JWKSURL, payloadFile(work, "older.json", older), olderVerifier.JWKSURL)
	require(restored["restart"] == nil && restored["served"] == true && restored["rolled_back"] == shaB && restored["replay"] == "rolled_back" && restored["older"] == "stale", fmt.Sprintf("the previous build reads the state this build leaves: %v", restored))
	newer, newerVerifier, newerClient, closeNewer := signedRelease(ctx, asset, shaB, "3", "1")
	defer closeNewer()
	again := previousRun(ctx, filepath.Join(work, "installed"), "install", work, payloadFile(work, "run-3.json", newer), newerClient.Transport.(providerTransport).url, revisionOf(previous), newerVerifier.JWKSURL)
	require(again["install"] == "installed" && bytes.Equal(read(filepath.Join(work, "installed")), candidate), fmt.Sprintf("the previous build installs this build again after the rollback: %v", again))
	upgraded := startInstalled(ctx, work, "serve")
	require(upgraded.Revision == shaB && upgraded.State == "probation" && upgraded.Served && upgraded.After == "" && record(trialPath) == nil, fmt.Sprintf("this build installed again by the previous build starts on probation and confirms: %+v", upgraded))
	fmt.Println("ok upgrade: previous build installs this build; probation counts from its trial; its fence refuses run 1; third start restores its exact bytes; it then refuses the replay and run 1; it installs this build again, which confirms")
}

func crossFilesystem(ctx context.Context) {
	work, cleanup := temporary("split-binary-")
	defer cleanup()
	state, err := os.MkdirTemp("/dev/shm", "split-state-")
	must(err)
	defer os.RemoveAll(state)
	var binaryStat, stateStat syscall.Stat_t
	must(syscall.Stat(work, &binaryStat))
	must(syscall.Stat(state, &stateStat))
	require(binaryStat.Dev != stateStat.Dev, "binary and state must use different filesystems")
	must(os.Symlink(state, filepath.Join(work, "nats")))
	commitCase(ctx, work, "twice")
	fmt.Println("ok filesystems: binary on disk; state on tmpfs; restart and second release verified")
}

func selfExitCase(ctx context.Context, data []byte) {
	work, cleanup := temporary("self-exit-")
	defer cleanup()
	binary := filepath.Join(work, "installed")
	writeExecutable(binary, stamped(data, strings.Repeat("a", 40), "pass"))
	writeExecutable(filepath.Join(work, "asset"), stamped(data, strings.Repeat("b", 40), "pass"))
	command := exec.CommandContext(ctx, binary, "self-update", work, "slow-shutdown")
	output, err := command.CombinedOutput()
	require(err == nil && strings.Contains(string(output), "installed reply collected") && strings.Contains(string(output), "duplicates installed installed") && strings.Contains(string(output), "ordinary shutdown finished"), fmt.Sprintf("the old process must finish its ordinary shutdown after commit despite duplicate notifications: %v %s", err, output))
	fresh, err := os.Stat(filepath.Join(work, "nats"))
	require(err == nil && fresh.IsDir() && fresh.Mode().Perm() == 0o700 && fence(work) == "2", fmt.Sprintf("a host without a release state directory creates it 0700 and records the release it installs: %v", err))
	fmt.Println("ok process exit: a host with no nats state directory installed the release; installed reply collected; two duplicate requests during a 4-second ordinary shutdown coalesced; shutdown finished; old process exited")
}

func selfUpdate(ctx context.Context, work, mode string) {
	h, err := releasepush.NewHandler(work)
	must(err)
	conn, closeListener := listener(h)
	defer closeListener()
	if mode == "postcommit-failures" {
		release, verifier, client, closeProvider := signedRelease(ctx, filepath.Join(work, "asset"), shaB, "2", "1")
		defer closeProvider()
		h.Verifier, h.Client = verifier, client
		h.PrepareStop = func(context.Context) error {
			conn.Close()
			return nil
		}
		observer, err := nats.Connect(conn.ConnectedUrl())
		must(err)
		must(observer.PublishRequest(releasepush.PullSubject("stg", "host"), nats.NewInbox(), pulledPayload(release, "2")))
		must(observer.Flush())
		observer.Close()
		select {
		case <-h.Installed:
		case <-ctx.Done():
			panic("old process was not told to restart after a lost reply")
		}
		return
	}
	reply := installRequest(ctx, h, conn, work, strings.Repeat("b", 40), "2")
	require(reply.State == "installed", "self update must return installed")
	fmt.Println("installed reply collected")
	if mode == "watchdog" {
		<-ctx.Done()
		return
	}
	select {
	case <-h.Installed:
	case <-ctx.Done():
		panic("restart notification missing")
	}
	first := installRequest(ctx, h, conn, work, strings.Repeat("b", 40), "2")
	second := installRequest(ctx, h, conn, work, strings.Repeat("b", 40), "2")
	fmt.Println("duplicates", first.State, second.State)
	select {
	case <-time.After(4 * time.Second):
	case <-ctx.Done():
	}
	fmt.Println("ordinary shutdown finished")
}

func fenceCase(ctx context.Context) {
	work, cleanup := temporary("fence-preflight-")
	defer cleanup()
	h, original, candidate := preparedHost(work)
	conn, closeListener := listener(h)
	defer closeListener()
	write(h.RunIDFile, "5")
	reply := installRequest(ctx, h, conn, work, shaB, "4")
	require(reply.State == "stale" && fence(work) == "5", fmt.Sprintf("an older run must be refused: %+v", reply))
	for _, content := range []string{"", "{", "[]", "x5"} {
		write(h.RunIDFile, content)
		reply = installRequest(ctx, h, conn, work, shaB, "9")
		require(reply.State == "rejected" && reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalFence && strings.Contains(reply.Error, "run fence damaged"), fmt.Sprintf("a damaged fence must refuse every run as its own kind: %+v", reply))
		reported := request(ctx, conn, releasepush.PullSubject("stg", "host"), nil).Refusal
		require(reported != nil && reported.Kind == releasepush.RefusalFence && record(h.RefusalFile)["kind"] == releasepush.RefusalFence, fmt.Sprintf("a damaged fence refusal must be saved and reported: %+v", reported))
		require(fence(work) == content && bytes.Equal(read(h.Binary), original), "a damaged fence must never be overwritten")
	}
	write(h.RunIDFile, "5")
	reply = installRequest(ctx, h, conn, work, shaB, "6")
	require(reply.State == "installed" && fence(work) == "6" && bytes.Equal(read(h.Binary), candidate), fmt.Sprintf("a newer run must install: %+v", reply))
	fmt.Println("ok fence: older run stale; damaged fence refuses every run as run_fence_damaged, saved, and stays; newer run installs")
}

func slowWriteCase(ctx context.Context) {
	work, cleanup := temporary("slow-write-")
	defer cleanup()
	h, original, _ := preparedHost(work)
	conn, closeListener := listener(h)
	defer closeListener()
	fan, err := unix.FanotifyInit(unix.FAN_CLASS_CONTENT|unix.FAN_CLOEXEC, unix.O_RDONLY|unix.O_CLOEXEC)
	must(err)
	must(unix.FanotifyMark(fan, unix.FAN_MARK_ADD, unix.FAN_OPEN_PERM|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, work))
	held := make(chan func(uint32), 1)
	go answerOpens(fan, h.Binary+".next", held)
	replied := make(chan releasepush.Reply, 1)
	go func() { replied <- installRequest(ctx, h, conn, work, shaB, "2") }()
	answer := <-held
	helper, err := os.Executable()
	must(err)
	started := make(chan time.Duration, 1)
	go func() {
		command := exec.CommandContext(ctx, helper, "release", "preflight")
		begin := time.Now()
		must(command.Start())
		started <- time.Since(begin)
		must(command.Wait())
	}()
	var delay time.Duration
	select {
	case delay = <-started:
	case <-time.After(5 * time.Second):
		delay = 5 * time.Second
	}
	answer(unix.FAN_DENY)
	reply := <-replied
	must(unix.FanotifyMark(fan, unix.FAN_MARK_REMOVE, unix.FAN_OPEN_PERM|unix.FAN_EVENT_ON_CHILD, unix.AT_FDCWD, work))
	require(delay < time.Second, fmt.Sprintf("a command started while the candidate open was held must not wait for it: started after %s", delay))
	require(reply.State == "rejected" && bytes.Equal(read(h.Binary), original), fmt.Sprintf("a candidate that cannot be written is refused: %+v", reply))
	fmt.Println("ok slow write: a command started while the fresh candidate open was held started in", delay.Round(time.Millisecond))
}

func answerOpens(fan int, candidate string, held chan<- func(uint32)) {
	buffer := make([]byte, 4096)
	for {
		n, err := unix.Read(fan, buffer)
		must(err)
		for offset := 0; offset < n; {
			var event unix.FanotifyEventMetadata
			must(binary.Read(bytes.NewReader(buffer[offset:n]), binary.NativeEndian, &event))
			offset += int(event.Event_len)
			answer := func(response uint32) {
				var reply bytes.Buffer
				must(binary.Write(&reply, binary.NativeEndian, unix.FanotifyResponse{Fd: event.Fd, Response: response}))
				_, err := unix.Write(fan, reply.Bytes())
				must(errors.Join(err, unix.Close(int(event.Fd))))
			}
			if path, _ := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", event.Fd)); path == candidate && held != nil {
				held <- answer
				held = nil
				continue
			}
			answer(unix.FAN_ALLOW)
		}
	}
}

func lostRollbackCase(ctx context.Context) {
	work, cleanup, original, candidate := stagedCandidate(ctx, "lost-rollback-")
	defer cleanup()
	installed := filepath.Join(work, "installed")
	setStarts(work, 2)
	require(startOnce(ctx, work, "hold") == "START rolled-back" && bytes.Equal(read(installed), original) && record(filepath.Join(work, "nats/release-trial")) == nil, "the third start must roll back")
	writeExecutable(installed, candidate)
	writeExecutable(installed+".prev", original)
	finished := startOnce(ctx, work, "serve")
	require(finished == "START rolled-back" && bytes.Equal(read(installed), original) && read(installed+".prev") == nil, "a lost rollback rename with its trial gone must be finished by the rejected candidate's start: "+finished)
	state := startInstalled(ctx, work, "serve")
	require(state.Revision == shaA && state.RolledBack == shaB && state.Served && state.Restarts == 0, fmt.Sprintf("the restored binary serves and reports the rollback: %+v", state))
	fmt.Println("ok probation lost rollback: rollback record without trial finished; rejected candidate never served")
}

func confirmRaceCase(ctx context.Context) {
	work, cleanup, _, _ := stagedCandidate(ctx, "confirm-race-")
	defer cleanup()
	trialPath := filepath.Join(work, "nats/release-trial")
	state := startInstalled(ctx, work, "race")
	trial := record(trialPath)
	require(state.Revision == shaB && state.Served && trial != nil && trial["sha"] == shaC && trial["run_id"] == "3", fmt.Sprintf("confirmation must leave a replacement's trial: %+v %v", state, trial))
	replacement := startInstalled(ctx, work, "serve")
	require(replacement.Revision == shaC && replacement.State == "probation" && replacement.Served && record(trialPath) == nil, fmt.Sprintf("the replacement starts on probation: %+v", replacement))
	fmt.Println("ok probation confirmation race: replacement staged before Served keeps its trial and starts on probation")
}

func rebuildCase(ctx context.Context) {
	work, cleanup := temporary("rebuild-")
	defer cleanup()
	h, _, _ := preparedHost(work)
	helper, err := os.Executable()
	must(err)
	first := stamped(read(helper), shaB, "original")
	writeExecutable(h.Binary, first)
	h.Revision = shaB
	conn, closeListener := listener(h)
	reply := installRequest(ctx, h, conn, work, shaB, "10")
	require(reply.State == "installed", "another digest of the installed commit was treated as current")
	closeListener()
	for starts := 1; starts <= 2; starts++ {
		state := startInstalled(ctx, work, "hold")
		require(state.State == "probation" && !state.Served && record(h.TrialFile)["starts"] == float64(starts), "an unserved rebuild must count every start")
	}
	failed := startInstalled(ctx, work, "hold")
	require(failed.RolledBack == shaB && bytes.Equal(read(h.Binary), first), "an unserved rebuild did not restore the exact previous digest")
	next, err := releasepush.NewHandler(work)
	must(err)
	next.Binary, next.Revision = h.Binary, shaB
	conn, closeListener = listener(next)
	defer closeListener()
	reply = installAsset(ctx, next, conn, otherAsset(work, shaB), shaB, "11")
	require(reply.State == "installed", "a newer rebuild did not install after rollback")
	served := startInstalled(ctx, work, "serve")
	require(served.Served, "the new rebuild did not confirm its probation")
	fmt.Println("ok rebuild: the same commit with another digest installs, rolls back by digest, and accepts a newer signed rebuild")
}

func mainFormatCase(ctx context.Context) {
	work, cleanup := temporary("main-format-")
	defer cleanup()
	must(os.Mkdir(filepath.Join(work, "nats"), 0o700))
	original, candidate := hostBytes()
	writeExecutable(filepath.Join(work, "installed"), candidate)
	writeExecutable(filepath.Join(work, "installed.prev"), original)
	trialPath := filepath.Join(work, "nats/release-trial")
	write(trialPath, fmt.Sprintf(`{"sha":%q,"run_id":"2","installed":%q,"starts":0}`, shaB, time.Now().UTC().Format(time.RFC3339Nano)))
	state := startInstalled(ctx, work, "serve")
	require(state.Revision == shaB && state.State == "probation" && state.Served && state.After == "" && state.Restarts == 0 && record(trialPath) == nil, fmt.Sprintf("a trial in the previous updater's format for the running binary is kept, counted and confirmed: %+v", state))
	fmt.Println("ok probation previous format: trial without digest kept for the running binary, on probation, confirmed")
}

func staleRecordCase(ctx context.Context) {
	work, cleanup := temporary("stale-record-")
	defer cleanup()
	must(os.MkdirAll(filepath.Join(work, "nats"), 0o700))
	_, candidate := hostBytes()
	write(filepath.Join(work, "nats/release-rolled-back"), fmt.Sprintf(`{"sha":%q,"sha256":%q,"run_id":"1","reason":"exited 2 times before serving"}`, shaB, digest(candidate)))
	h, _, _ := preparedHost(work)
	conn, closeListener := listener(h)
	reply := installRequest(ctx, h, conn, work, shaB, "2")
	closeListener()
	require(reply.State == "installed", fmt.Sprintf("a newer run of a rolled-back build installs: %+v", reply))
	confirmed := startInstalled(ctx, work, "serve")
	require(confirmed.Revision == shaB && confirmed.State == "probation" && confirmed.Served && confirmed.After == "", fmt.Sprintf("the newer run confirms: %+v", confirmed))
	again := startInstalled(ctx, work, "serve")
	require(again.Revision == shaB && again.State == "" && again.RolledBack == "" && again.Restarts == 0 && bytes.Equal(read(filepath.Join(work, "installed")), candidate), fmt.Sprintf("a confirmed binary is never rolled back by an older rollback record: %+v", again))
	fmt.Println("ok probation stale record: rollback record of run 1, run 2 installed and confirmed, restart keeps it")
}

func watchdogCase(ctx context.Context, _ string) {
	work, cleanup := temporary("watchdog-")
	defer cleanup()
	h, _, _ := preparedHost(work)
	started := time.Now()
	output, err := exec.CommandContext(ctx, h.Binary, "self-update", work, "watchdog").CombinedOutput()
	require(err == nil && time.Since(started) >= 40*time.Second && strings.Contains(string(output), "installed reply collected"), fmt.Sprintf("the installed host must exit by its shutdown watchdog: %v %s", err, output))
	served := startInstalled(ctx, work, "serve")
	require(served.Served && served.Revision == shaB, "the watchdog replacement did not start and serve")
	fmt.Println("ok watchdog: stuck shutdown exits after install and the verified replacement serves")
}

package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats.go"
)

func run(ctx context.Context, binary, previous string) {
	must(exec.CommandContext(ctx, binary, "release", "preflight").Run())
	fmt.Println("ok ts-orch release preflight: exits 0")
	marksDir, cleanupMarks := temporary("previous-marks-")
	defer cleanupMarks()
	previousMark := filepath.Join(marksDir, "preflight")
	must(os.Setenv("UPDATER_PREFLIGHT_MARK", previousMark))
	var groups sync.WaitGroup
	groups.Go(func() { preflightCases(ctx) })
	groups.Go(func() {
		orphanCases(ctx)
		busyCases(ctx)
		slowWriteCase(ctx)
		keyCases(ctx)
		declarationCase(ctx)
	})
	groups.Go(func() {
		equivalenceCases(ctx, previous)
		mainBuildCase(ctx, previous, previousMark)
		rollbackCase(ctx)
		upgradeCase(ctx, previous)
		timingCase(ctx, previous)
	})
	groups.Go(func() { mainPusherCase(ctx, previous) })
	rolloutCases(ctx)
	relayCase(ctx)
	rebuildCase(ctx)
	oldHostCase(ctx)
	unreadableCase(ctx)
	slowCase(ctx)
	groups.Wait()
	fmt.Println("updater-preflight e2e: PASS")
}

func refusedUnchanged(reply releasepush.Reply, kind string, preflight bool, asset []byte) {
	require(reply.State == "rejected" && reply.Refusal != nil && reply.Refusal.Kind == kind && reply.Refusal.Preflight == preflight, fmt.Sprintf("refusal must be %s preflight=%v: %+v", kind, preflight, reply))
	require(reply.Refusal.SHA == shaB && reply.Refusal.SHA256 == digest(asset) && reply.Refusal.RunAttempt == "1" && reply.Refusal.RunID != "", fmt.Sprintf("refusal must name the candidate: %+v", reply.Refusal))
	require(len(reply.Refusal.Reason) <= 4<<10 && utf8.ValidString(reply.Refusal.Reason) && !strings.ContainsFunc(reply.Refusal.Reason, unicode.IsControl), "diagnostic must be bounded valid text")
}

func unchanged(before map[string]entry, work, what string) {
	after := snapshot(false, work)
	require(sameFiles(before, after) == "", what+" must leave every file byte-identical, timestamps included: "+sameFiles(before, after))
}

func preflightCases(ctx context.Context) {
	work, cleanup := temporary("preflight-")
	defer cleanup()
	h := newHost(work, true)
	handler := h.handler()
	conn, closeListener := listener(handler)
	defer closeListener()
	for i, mode := range []string{"refuse", "noise", "cannot-execute", "hang"} {
		asset := stamped(helperBytes(), shaB, mode)
		if mode == "cannot-execute" {
			asset = []byte("invalid executable")
		}
		p := newProvider(asset)
		handler.Verifier, handler.Client = p.verifier(), p.client()
		before := snapshot(false, work)
		release := p.release(shaB, fmt.Sprint(i+2), "e2e")
		start := time.Now()
		reply := send(ctx, conn, release, p.declaration())
		elapsed := time.Since(start)
		p.server.Close()
		refusedUnchanged(reply, releasepush.RefusalHost, true, asset)
		unchanged(before, work, "a preflight refusal")
		if mode == "noise" {
			require(strings.HasSuffix(reply.Refusal.Reason, "[truncated]"), "10 MiB of output must be cut to the diagnostic bound")
		}
		if mode == "hang" {
			require(elapsed >= 70*time.Second && elapsed < 75*time.Second, fmt.Sprintf("preflight must keep its 70-second bound: %s", elapsed))
		}
		fmt.Println("ok preflight", mode, ": declared release, host_prerequisite preflight refusal; binary, .prev, trial, fence and rollback record byte-identical with their timestamps")
	}
}

func running(pid int) bool {
	stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if errors.Is(err, os.ErrNotExist) {
		return false
	}
	must(err)
	fields := strings.Fields(string(stat[bytes.LastIndexByte(stat, ')')+1:]))
	return fields[0] != "Z"
}

func orphanCases(ctx context.Context) {
	for _, mode := range []string{"orphan-pass", "orphan-fail"} {
		work, cleanup := temporary("orphan-")
		marksDir, cleanupMarks := temporary("orphan-marks-")
		mark := filepath.Join(marksDir, "child")
		h := newHost(work, false)
		handler := h.handler()
		conn, closeListener := listener(handler)
		asset := stamped(helperBytes(), shaB, mode+":"+mark)
		p := newProvider(asset)
		handler.Verifier, handler.Client = p.verifier(), p.client()
		before := snapshot(false, work)
		reply := send(ctx, conn, p.release(shaB, "2", "e2e"), p.declaration())
		children := marks(mark)
		require(len(children) == 1, fmt.Sprintf("the candidate must have started one child: %v %+v", children, reply))
		var pid int
		_, err := fmt.Sscan(children[0], &pid)
		must(err)
		require(!running(pid), fmt.Sprintf("the child %d left in the preflight's process group must be gone when the preflight returns (%s)", pid, mode))
		if mode == "orphan-pass" {
			require(reply.State == "installed" && bytes.Equal(read(h.binary), asset), fmt.Sprintf("a passing preflight with a leftover child installs: %+v", reply))
		} else {
			refusedUnchanged(reply, releasepush.RefusalHost, true, asset)
			unchanged(before, work, "a refusing preflight that left a child")
		}
		fmt.Println("ok process group", mode, ": the child left in the candidate's process group is killed before the preflight returns")
		p.server.Close()
		closeListener()
		cleanupMarks()
		cleanup()
	}
}

func busyCases(ctx context.Context) {
	for _, hold := range []time.Duration{300 * time.Millisecond, 6 * time.Second} {
		work, cleanup := temporary("busy-")
		h := newHost(work, true)
		handler := h.handler()
		conn, closeListener := listener(handler)
		heldDir, cleanupHeld := temporary("busy-held-")
		mark := filepath.Join(heldDir, "preflight-ran")
		asset := stamped(helperBytes(), shaB, "mark:"+mark)
		p := newProvider(asset)
		handler.Verifier, handler.Client = p.verifier(), p.client()
		before := snapshot(false, work)
		held := filepath.Join(heldDir, "candidate")
		must(os.Symlink(held, h.binary+".next"))
		writer, err := os.OpenFile(held, os.O_CREATE|os.O_WRONLY, 0o755)
		must(err)
		watch, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
		must(err)
		_, err = syscall.InotifyAddWatch(watch, held, syscall.IN_CLOSE_WRITE)
		must(err)
		replied := make(chan releasepush.Reply, 1)
		var repliedAt time.Time
		release := p.release(shaB, "2", "e2e")
		declaration := p.declaration()
		go func() {
			reply := send(ctx, conn, release, declaration)
			repliedAt = time.Now()
			replied <- reply
		}()
		event := make([]byte, 4096)
		_, err = syscall.Read(watch, event)
		must(errors.Join(err, syscall.Close(watch)))
		written := time.Now()
		timer := time.NewTimer(hold)
		select {
		case <-timer.C:
		case <-ctx.Done():
			panic("busy case outlived the lane")
		}
		released := time.Now()
		must(writer.Close())
		reply := <-replied
		waited := repliedAt.Sub(written)
		if hold < textBusyLimit {
			ran := marks(mark)
			require(len(ran) == 1, fmt.Sprintf("the released candidate's preflight must run once: %v", ran))
			at, err := time.Parse(time.RFC3339Nano, ran[0])
			require(err == nil && at.After(released) && reply.State == "installed" && repliedAt.After(released), fmt.Sprintf("a candidate busy for %s must be retried until it is released, then installed: %+v after %s, preflight ran %s", hold, reply, waited, at))
			require(bytes.Equal(read(h.binary), asset) && h.trial()["sha"] == shaB, "the retried candidate must be installed by main's flow")
			fmt.Println("ok busy candidate: ETXTBSY for", hold, "retried; installed after", waited.Round(time.Millisecond))
		} else {
			refusedUnchanged(reply, releasepush.RefusalHost, false, asset)
			require(read(mark) == nil, "a candidate that stayed busy must never have run")
			require(strings.Contains(reply.Refusal.Reason, "still open for writing") && waited >= textBusyLimit-time.Second, fmt.Sprintf("a candidate busy past 5 s must be a host refusal that is not a preflight refusal: %+v", reply.Refusal))
			unchanged(before, work, "a busy refusal")
			fmt.Println("ok busy candidate: ETXTBSY past 5 s is host_prerequisite without preflight; files byte-identical")
		}
		p.server.Close()
		closeListener()
		cleanupHeld()
		cleanup()
	}
}

const textBusyLimit = 5 * time.Second

func slowWriteCase(ctx context.Context) {
	work, cleanup := temporary("slow-write-")
	defer cleanup()
	h := newHost(work, false)
	handler := h.handler()
	conn, closeListener := listener(handler)
	defer closeListener()
	p := newProvider(stamped(helperBytes(), shaB, "pass"))
	defer p.server.Close()
	handler.Verifier, handler.Client = p.verifier(), p.client()
	must(syscall.Mkfifo(h.binary+".next", 0o600))
	replied := make(chan releasepush.Reply, 1)
	release := p.release(shaB, "2", "e2e")
	declaration := p.declaration()
	go func() { replied <- send(ctx, conn, release, declaration) }()
	reader, err := os.OpenFile(h.binary+".next", os.O_RDONLY, 0)
	must(err)
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
	_, err = io.Copy(io.Discard, reader)
	must(errors.Join(err, reader.Close()))
	reply := <-replied
	require(delay < time.Second, fmt.Sprintf("a command started during a stalled candidate write must not wait for it: started after %s", delay))
	require(reply.State == "rejected" && bytes.Equal(read(h.binary), h.original), fmt.Sprintf("a candidate that cannot be synced is refused: %+v", reply))
	fmt.Println("ok slow write: a command started while the candidate write was stalled started in", delay.Round(time.Millisecond))
}

func keyCases(ctx context.Context) {
	asset := stamped(helperBytes(), shaB, "pass")
	var hosts [2]host
	var handlers [2]*releasepush.Handler
	var conns [2]func(releasepush.OrchRelease) releasepush.Reply
	for i := range hosts {
		work, cleanup := temporary("keys-")
		defer cleanup()
		hosts[i] = newHost(work, false)
		handlers[i] = hosts[i].handler()
		conn, closeListener := listener(handlers[i])
		defer closeListener()
		conns[i] = func(release releasepush.OrchRelease) releasepush.Reply { return send(ctx, conn, release, "") }
	}
	kind := func(reply releasepush.Reply) string {
		require(reply.State == "rejected" && reply.Refusal != nil, fmt.Sprintf("a key failure must be a classified refusal: %+v", reply))
		return reply.Refusal.Kind
	}

	failing := newProvider(asset)
	defer failing.server.Close()
	fail := func(w http.ResponseWriter) { http.Error(w, "unavailable", http.StatusServiceUnavailable) }
	failing.jwks.Store(&fail)
	handlers[0].Verifier = failing.verifier()
	require(kind(conns[0](failing.release(shaB, "2", "e2e"))) == releasepush.RefusalHost, "a failed key fetch must be host_prerequisite")
	fmt.Println("ok keys: failed fetch -> host_prerequisite")

	shared := func(p *provider, serve func(http.ResponseWriter), kid string) [2]string {
		entered, release := make(chan struct{}), make(chan struct{})
		var once sync.Once
		held := func(w http.ResponseWriter) {
			once.Do(func() { close(entered) })
			<-release
			serve(w)
		}
		p.jwks.Store(&held)
		p.hits.Store(0)
		verifier := p.verifier()
		handlers[0].Verifier, handlers[1].Verifier = verifier, verifier
		request := p.release(shaB, "3", kid)
		var kinds [2]string
		var replies sync.WaitGroup
		replies.Go(func() { kinds[0] = kind(conns[0](request)) })
		<-entered
		replies.Go(func() { kinds[1] = kind(conns[1](request)) })
		hold := time.NewTimer(time.Second)
		<-hold.C
		close(release)
		replies.Wait()
		require(p.hits.Load() == 1, fmt.Sprintf("the waiting request must share the running fetch: %d fetches", p.hits.Load()))
		return kinds
	}
	failedShared := newProvider(asset)
	defer failedShared.server.Close()
	kinds := shared(failedShared, fail, "e2e")
	require(kinds == [2]string{releasepush.RefusalHost, releasepush.RefusalHost}, fmt.Sprintf("the fetcher and the waiter of a failed fetch are host_prerequisite: %v", kinds))
	fmt.Println("ok keys: shared failed fetch -> host_prerequisite for the fetcher and the waiter")

	lacking := newProvider(asset)
	defer lacking.server.Close()
	kinds = shared(lacking, lacking.keys, "other")
	require(kinds == [2]string{releasepush.RefusalIntegrity, releasepush.RefusalIntegrity}, fmt.Sprintf("a key missing from a fresh shared key set is release_integrity for both: %v", kinds))
	fmt.Println("ok keys: shared fresh key set without the key -> release_integrity for the fetcher and the waiter")
	plain := func(w http.ResponseWriter) { lacking.keys(w) }
	lacking.jwks.Store(&plain)
	require(kind(conns[0](lacking.release(shaB, "4", "other"))) == releasepush.RefusalHost && lacking.hits.Load() == 1, "a key missing from a key set fetched under 30 s ago is host_prerequisite without a refetch")
	fmt.Println("ok keys: throttled refetch -> host_prerequisite")
	handlers[0].Verifier = lacking.verifier()
	require(kind(conns[0](lacking.release(shaB, "5", "other"))) == releasepush.RefusalIntegrity && lacking.hits.Load() == 2, "a key missing from the key set this request fetched is release_integrity")
	fmt.Println("ok keys: own fresh key set without the key -> release_integrity")

	good := newProvider(asset)
	defer good.server.Close()
	handlers[0].Verifier = good.verifier()
	handlers[0].Client = &http.Client{Transport: failTransport{}}
	require(kind(conns[0](good.release(shaB, "6", "e2e"))) == releasepush.RefusalHost, "a failed download is host_prerequisite")
	handlers[0].Client = &http.Client{Transport: corruptTransport{good.client().Transport}}
	require(kind(conns[0](good.release(shaB, "7", "e2e"))) == releasepush.RefusalIntegrity, "a fully received binary with another digest is release_integrity")
	fmt.Println("ok classification: download failure -> host_prerequisite; digest mismatch -> release_integrity")
}

func declarationCase(ctx context.Context) {
	work, cleanup := temporary("declaration-")
	defer cleanup()
	h := newHost(work, true)
	handler := h.handler()
	conn, closeListener := listener(handler)
	defer closeListener()
	asset := stamped(helperBytes(), shaB, "refuse")
	p := newProvider(asset)
	defer p.server.Close()
	handler.Verifier, handler.Client = p.verifier(), p.client()
	otherRun := p.mint(tokenClaims{shaB, "3", "e2e"}, releasepush.PreflightAudience)
	releaseAudience := p.mint(tokenClaims{shaB, "2", "e2e"}, releasepush.Audience)
	release := p.release(shaB, "2", "e2e")
	before := snapshot(false, work)
	for _, declaration := range []string{otherRun, releaseAudience} {
		refusedUnchanged(send(ctx, conn, release, declaration), releasepush.RefusalIntegrity, false, asset)
		unchanged(before, work, "a refused declaration")
	}
	fmt.Println("ok declaration: a preflight declaration from another run, or a release token passed as one, is release_integrity before anything is downloaded or run; files byte-identical")
}

func payloadFile(dir, name string, release releasepush.OrchRelease) string {
	data, err := json.Marshal(release)
	must(err)
	path := filepath.Join(dir, name)
	must(os.WriteFile(path, data, 0o600))
	return path
}

func previousRun(ctx context.Context, binary string, args ...string) map[string]any {
	output, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
	require(err == nil, fmt.Sprintf("main's updater must run on this state: %v: %s", err, output))
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var result map[string]any
	must(json.Unmarshal([]byte(lines[len(lines)-1]), &result))
	return result
}

func equivalenceCases(ctx context.Context, previous string) {
	for _, probation := range []bool{false, true} {
		mainWork, cleanupMain := temporary("main-updater-")
		plainWork, cleanupPlain := temporary("this-updater-")
		declaredWork, cleanupDeclared := temporary("this-declared-")
		payloads, cleanupPayloads := temporary("payloads-")
		newHost(mainWork, probation)
		plainHost, declaredHost := newHost(plainWork, probation), newHost(declaredWork, probation)
		mark := filepath.Join(payloads, "preflight-ran")
		asset := stamped(helperBytes(), shaB, "mark:"+mark)
		p := newProvider(asset)
		release := p.release(shaB, "2", "e2e")
		installed := previousRun(ctx, previous, "install", mainWork, payloadFile(payloads, "run-2.json", release), p.server.URL+"/binary", shaA, p.server.URL+"/jwks")
		require(installed["install"] == "installed", fmt.Sprintf("main's updater must install the candidate: %v", installed))
		for i, h := range []host{plainHost, declaredHost} {
			handler := h.handler()
			handler.Verifier, handler.Client = p.verifier(), p.client()
			conn, closeListener := listener(handler)
			declaration := ""
			if i == 1 {
				declaration = p.declaration()
			}
			reply := send(ctx, conn, release, declaration)
			closeListener()
			require(reply.State == "installed", fmt.Sprintf("this updater must install the candidate: %+v", reply))
			ran := len(marks(mark))
			require(ran == map[bool]int{false: 0, true: 1}[declaration != ""], fmt.Sprintf("the preflight runs only for a declared release: declared %v, ran %d", declaration != "", ran))
			require(sameFiles(snapshot(true, mainWork), snapshot(true, h.work)) == "", "the host must hold exactly what main's updater writes: "+sameFiles(snapshot(true, mainWork), snapshot(true, h.work)))
			trial := h.trial()
			require(bytes.Equal(read(h.binary), asset) && bytes.Equal(read(h.binary+".prev"), h.original) && trial["sha"] == shaB && trial["run_id"] == "2" && trial["starts"] == float64(0) && string(read(filepath.Join(h.work, "nats/release-run-id"))) == "2" && read(filepath.Join(h.work, "nats/release-rolled-back")) == nil, "main's install: candidate swapped, .prev, trial, fence, rollback record removed")
		}
		for _, work := range []string{mainWork, plainWork, declaredWork} {
			first := startParsed(ctx, work, "hold")
			require(first.Revision == shaB && first.Probation && first.Starts == 1 && first.Digest == digest(asset), fmt.Sprintf("the candidate's first start is on probation and reports its digest: %+v", first))
		}
		require(sameFiles(snapshot(true, mainWork), snapshot(true, plainWork)) == "" && sameFiles(snapshot(true, mainWork), snapshot(true, declaredWork)) == "", "after the first start the hosts must still be identical")
		fmt.Printf("ok equivalence (incumbent on probation: %v): without a declaration no preflight runs, with one it runs once; both byte-identical to main's updater after install and after the first start\n", probation)
		p.server.Close()
		cleanupPayloads()
		cleanupDeclared()
		cleanupPlain()
		cleanupMain()
	}
}

func mainBuildCase(ctx context.Context, previous, previousMark string) {
	thisWork, cleanupThis := temporary("main-build-")
	defer cleanupThis()
	mainWork, cleanupMain := temporary("main-build-main-")
	defer cleanupMain()
	payloads, cleanupPayloads := temporary("main-build-payloads-")
	defer cleanupPayloads()
	h := newHost(thisWork, false)
	newHost(mainWork, false)
	asset := read(previous)
	sha := revisionOf(previous)
	require(len(sha) == 40, "main's build must carry a commit revision: "+sha)
	p := newProvider(asset)
	defer p.server.Close()
	release := p.release(sha, "2", "e2e")
	handler := h.handler()
	handler.Verifier, handler.Client = p.verifier(), p.client()
	conn, closeListener := listener(handler)
	reply := send(ctx, conn, release, "")
	closeListener()
	require(reply.State == "installed" && bytes.Equal(read(h.binary), asset) && read(previousMark) == nil, fmt.Sprintf("a release of main's build carries no declaration and installs without a preflight: %+v", reply))
	installed := previousRun(ctx, previous, "install", mainWork, payloadFile(payloads, "run-2.json", release), p.server.URL+"/binary", shaA, p.server.URL+"/jwks")
	require(installed["install"] == "installed" && sameFiles(snapshot(true, mainWork), snapshot(true, thisWork)) == "", "this updater writes exactly what main's updater writes for main's build: "+sameFiles(snapshot(true, mainWork), snapshot(true, thisWork)))
	probed := previousRun(ctx, h.binary, "probe", thisWork)
	require(probed["revision"] == sha && probed["probation"] == true && probed["starts"] == float64(1) && probed["served"] == true && h.trial() == nil, fmt.Sprintf("main's build starts on its own probation and confirms: %v", probed))
	fmt.Println("ok rollback release to main's build: no declaration, no preflight run, files identical to main's updater; main's build starts on main's probation (start 1) and confirms")
}

func rollbackCase(ctx context.Context) {
	work, cleanup := temporary("rollback-")
	defer cleanup()
	h := newHost(work, false)
	asset := stamped(helperBytes(), shaB, "pass")
	p := newProvider(asset)
	defer p.server.Close()
	handler := h.handler()
	handler.Verifier, handler.Client = p.verifier(), p.client()
	conn, closeListener := listener(handler)
	release := p.release(shaB, "2", "e2e")
	require(send(ctx, conn, release, p.declaration()).State == "installed", "the candidate must install")
	closeListener()
	for starts := 1; starts <= 2; starts++ {
		state := startParsed(ctx, work, "hold")
		require(state.Revision == shaB && state.Probation && state.Starts == starts, fmt.Sprintf("each start before serving must count: %+v", state))
	}
	require(startOnce(ctx, work, "hold") == "START rolled-back", "the third start must roll back")
	require(bytes.Equal(read(h.binary), h.original) && read(h.binary+".prev") == nil && h.trial() == nil, "the rollback must restore the previous binary byte for byte")
	restored := startParsed(ctx, work, "serve")
	require(restored.Revision == shaA && restored.RolledBack == shaB && !restored.Probation && restored.Served, fmt.Sprintf("the restored binary must report the rollback: %+v", restored))
	handler = h.handler()
	handler.Verifier, handler.Client = p.verifier(), p.client()
	conn, closeListener = listener(handler)
	defer closeListener()
	require(send(ctx, conn, release, p.declaration()).State == "rolled_back", "a replay of the rolled-back run must be refused")
	fmt.Println("ok probation rollback: two counted starts, third start restores the previous bytes, reported, replay refused")
}

func upgradeCase(ctx context.Context, previous string) {
	work, cleanup := temporary("upgrade-")
	defer cleanup()
	payloads, cleanupPayloads := temporary("upgrade-payloads-")
	defer cleanupPayloads()
	must(os.Mkdir(filepath.Join(work, "nats"), 0o700))
	previousBytes := read(previous)
	installed := filepath.Join(work, "installed")
	writeExecutable(installed, previousBytes)
	candidate := stamped(helperBytes(), shaB, "pass")
	p := newProvider(candidate)
	defer p.server.Close()
	release := p.release(shaB, "2", "e2e")
	result := previousRun(ctx, previous, "install", work, payloadFile(payloads, "run-2.json", release), p.server.URL+"/binary", revisionOf(previous), p.server.URL+"/jwks")
	require(result["install"] == "installed" && bytes.Equal(read(installed), candidate) && bytes.Equal(read(installed+".prev"), previousBytes), fmt.Sprintf("main's updater must install this build: %v", result))
	for starts := 1; starts <= 2; starts++ {
		state := startParsed(ctx, work, "hold")
		require(state.Revision == shaB && state.Probation && state.Starts == starts, fmt.Sprintf("this build counts its starts on main's trial: %+v", state))
	}
	require(startOnce(ctx, work, "hold") == "START rolled-back" && bytes.Equal(read(installed), previousBytes), "the third start restores main's build byte for byte")
	older := newProvider(stamped(helperBytes(), shaC, "pass"))
	defer older.server.Close()
	restored := previousRun(ctx, installed, "start", work, payloadFile(payloads, "replay.json", release), p.server.URL+"/jwks", payloadFile(payloads, "older.json", older.release(shaC, "1", "e2e")), older.server.URL+"/jwks")
	require(restored["restart"] == nil && restored["served"] == true && restored["rolled_back"] == shaB && restored["replay"] == "rolled_back" && restored["older"] == "stale", fmt.Sprintf("main's build reads the state this build leaves: %v", restored))
	again := p.release(shaB, "3", "e2e")
	result = previousRun(ctx, installed, "install", work, payloadFile(payloads, "run-3.json", again), p.server.URL+"/binary", revisionOf(previous), p.server.URL+"/jwks")
	require(result["install"] == "installed" && bytes.Equal(read(installed), candidate), fmt.Sprintf("main's build installs this build again: %v", result))
	confirmed := startParsed(ctx, work, "serve")
	require(confirmed.Revision == shaB && confirmed.Probation && confirmed.Served && !confirmed.TrialLeft, fmt.Sprintf("this build installed again by main's updater starts on probation and confirms: %+v", confirmed))
	fmt.Println("ok upgrade: main's updater installs this build; probation counts; third start restores main's exact bytes; main refuses the replay and an older run; main installs this build again, which confirms")
}

func thisSignal(ctx context.Context) time.Duration {
	work, cleanup := temporary("signal-this-")
	defer cleanup()
	h := newHost(work, false)
	handler := h.handler()
	p := newProvider(stamped(helperBytes(), shaB, "pass"))
	defer p.server.Close()
	handler.Verifier, handler.Client = p.verifier(), p.client()
	conn, closeListener := listener(handler)
	defer closeListener()
	handler.Relay = func(request []byte, header nats.Header) {
		must(errors.Join(conn.PublishMsg(&nats.Msg{Subject: "lane.silent-workers", Data: request, Header: header}), conn.Flush()))
	}
	release := p.release(shaB, "2", "e2e")
	declaration := p.declaration()
	replied := make(chan releasepush.Reply, 1)
	go func() { replied <- send(ctx, conn, release, declaration) }()
	<-handler.Installed
	signalled := time.Now()
	require((<-replied).State == "installed", "the founder must install")
	installed, err := time.Parse(time.RFC3339Nano, h.trial()["installed"].(string))
	must(err)
	return signalled.Sub(installed)
}

func mainSignal(ctx context.Context, previous string) time.Duration {
	work, cleanup := temporary("signal-main-")
	defer cleanup()
	payloads, cleanupPayloads := temporary("signal-payloads-")
	defer cleanupPayloads()
	newHost(work, false)
	p := newProvider(stamped(helperBytes(), shaB, "pass"))
	defer p.server.Close()
	result := previousRun(ctx, previous, "signal", work, payloadFile(payloads, "run-2.json", p.release(shaB, "2", "e2e")), p.server.URL+"/binary", shaA, p.server.URL+"/jwks")
	return time.Duration(result["signal_ns"].(float64))
}

func median(samples []time.Duration) time.Duration {
	sorted := slices.Clone(samples)
	slices.Sort(sorted)
	return sorted[len(sorted)/2]
}

func timingCase(ctx context.Context, previous string) {
	var mainSamples, thisSamples []time.Duration
	for range 5 {
		mainSamples = append(mainSamples, mainSignal(ctx, previous))
		thisSamples = append(thisSamples, thisSignal(ctx))
	}
	mainMedian, thisMedian := median(mainSamples), median(thisSamples)
	require((thisMedian-mainMedian).Abs() < 100*time.Millisecond, fmt.Sprintf("with a silent worker the founder must signal its restart as soon as main's does: main %v, this %v", mainSamples, thisSamples))
	fmt.Println("ok founder timing: trial write to restart signal with a silent worker, median main", mainMedian.Round(time.Microsecond), "this", thisMedian.Round(time.Microsecond), "samples main", mainSamples, "this", thisSamples)
}

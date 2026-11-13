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
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
)

func run(ctx context.Context, binary, previous string) {
	must(exec.CommandContext(ctx, binary, "release", "preflight").Run())
	fmt.Println("ok ts-orch release preflight: exits 0")
	var groups sync.WaitGroup
	groups.Go(func() { preflightCases(ctx) })
	groups.Go(func() {
		busyCases(ctx)
		slowWriteCase(ctx)
		keyCases(ctx)
	})
	groups.Go(func() {
		equivalenceCases(ctx, previous)
		rollbackCase(ctx)
		upgradeCase(ctx, previous)
	})
	rolloutCases(ctx)
	rebuildCase(ctx)
	oldHostCase(ctx)
	groups.Wait()
	fmt.Println("updater-preflight e2e: PASS")
}

func refusedUnchanged(reply releasepush.Reply, kind string, preflight bool, asset []byte) {
	require(reply.State == "rejected" && reply.Refusal != nil && reply.Refusal.Kind == kind && reply.Refusal.Preflight == preflight, fmt.Sprintf("refusal must be %s preflight=%v: %+v", kind, preflight, reply))
	require(reply.Refusal.SHA == shaB && reply.Refusal.SHA256 == digest(asset) && reply.Refusal.RunAttempt == "1" && reply.Refusal.RunID != "", fmt.Sprintf("refusal must name the candidate: %+v", reply.Refusal))
	require(len(reply.Refusal.Reason) <= 4<<10 && utf8.ValidString(reply.Refusal.Reason) && !strings.ContainsFunc(reply.Refusal.Reason, unicode.IsControl), "diagnostic must be bounded valid text")
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
		before := snapshot(work)
		start := time.Now()
		reply := send(ctx, conn, p.release(shaB, fmt.Sprint(i+2), "e2e"))
		elapsed := time.Since(start)
		p.server.Close()
		refusedUnchanged(reply, releasepush.RefusalHost, true, asset)
		require(sameFiles(before, snapshot(work)) == "", "a preflight refusal must leave every file as it was: "+sameFiles(before, snapshot(work)))
		if mode == "noise" {
			require(strings.HasSuffix(reply.Refusal.Reason, "[truncated]"), "10 MiB of output must be cut to the diagnostic bound")
		}
		if mode == "hang" {
			require(elapsed >= 70*time.Second && elapsed < 75*time.Second, fmt.Sprintf("preflight must keep its 70-second bound: %s", elapsed))
		}
		fmt.Println("ok preflight", mode, ": host_prerequisite preflight refusal; binary, .prev, trial, fence and rollback record byte-identical")
	}
}

func busyCases(ctx context.Context) {
	for _, hold := range []time.Duration{300 * time.Millisecond, 6 * time.Second} {
		work, cleanup := temporary("busy-")
		h := newHost(work, true)
		handler := h.handler()
		conn, closeListener := listener(handler)
		asset := stamped(helperBytes(), shaB, "pass")
		p := newProvider(asset)
		handler.Verifier, handler.Client = p.verifier(), p.client()
		before := snapshot(work)
		heldDir, cleanupHeld := temporary("busy-held-")
		held := filepath.Join(heldDir, "candidate")
		must(os.Symlink(held, h.binary+".next"))
		writer, err := os.OpenFile(held, os.O_CREATE|os.O_WRONLY, 0o755)
		must(err)
		watch, err := syscall.InotifyInit1(syscall.IN_CLOEXEC)
		must(err)
		_, err = syscall.InotifyAddWatch(watch, held, syscall.IN_CLOSE_WRITE)
		must(err)
		replied := make(chan releasepush.Reply, 1)
		go func() { replied <- send(ctx, conn, p.release(shaB, "2", "e2e")) }()
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
		must(writer.Close())
		reply := <-replied
		waited := time.Since(written)
		if hold < textBusyLimit {
			require(reply.State == "installed" && waited >= hold, fmt.Sprintf("a candidate busy for %s must be retried and installed: %+v after %s", hold, reply, waited))
			require(bytes.Equal(read(h.binary), asset) && h.trial()["sha"] == shaB, "the retried candidate must be installed by main's flow")
			fmt.Println("ok busy candidate: ETXTBSY for", hold, "retried; installed after", waited.Round(time.Millisecond))
		} else {
			refusedUnchanged(reply, releasepush.RefusalHost, false, asset)
			require(strings.Contains(reply.Refusal.Reason, "still open for writing") && waited >= textBusyLimit-time.Second, fmt.Sprintf("a candidate busy past 5 s must be a host refusal that is not a preflight refusal: %+v", reply.Refusal))
			require(sameFiles(before, snapshot(work)) == "", "a busy refusal must leave every file as it was: "+sameFiles(before, snapshot(work)))
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
	go func() { replied <- send(ctx, conn, p.release(shaB, "2", "e2e")) }()
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
		conns[i] = func(release releasepush.OrchRelease) releasepush.Reply { return send(ctx, conn, release) }
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
		thisWork, cleanupThis := temporary("this-updater-")
		payloads, cleanupPayloads := temporary("payloads-")
		newHost(mainWork, probation)
		thisHost := newHost(thisWork, probation)
		require(sameFiles(snapshot(mainWork), snapshot(thisWork)) == "", "both hosts must start identical")
		asset := stamped(helperBytes(), shaB, "pass")
		p := newProvider(asset)
		release := p.release(shaB, "2", "e2e")
		installed := previousRun(ctx, previous, "install", mainWork, payloadFile(payloads, "run-2.json", release), p.server.URL+"/binary", shaA, p.server.URL+"/jwks")
		require(installed["install"] == "installed", fmt.Sprintf("main's updater must install the candidate: %v", installed))
		handler := thisHost.handler()
		handler.Verifier, handler.Client = p.verifier(), p.client()
		conn, closeListener := listener(handler)
		reply := send(ctx, conn, release)
		closeListener()
		require(reply.State == "installed", fmt.Sprintf("this updater must install the candidate: %+v", reply))
		require(sameFiles(snapshot(mainWork), snapshot(thisWork)) == "", "after a passing preflight the host must hold exactly what main's updater writes: "+sameFiles(snapshot(mainWork), snapshot(thisWork)))
		trial := thisHost.trial()
		require(bytes.Equal(read(thisHost.binary), asset) && bytes.Equal(read(thisHost.binary+".prev"), thisHost.original) && trial["sha"] == shaB && trial["run_id"] == "2" && trial["starts"] == float64(0) && string(read(filepath.Join(thisWork, "nats/release-run-id"))) == "2" && read(filepath.Join(thisWork, "nats/release-rolled-back")) == nil, "main's install: candidate swapped, .prev, trial, fence, rollback record removed")
		for _, work := range []string{mainWork, thisWork} {
			first := startParsed(ctx, work, "hold")
			require(first.Revision == shaB && first.Probation && first.Starts == 1 && first.Digest == digest(asset), fmt.Sprintf("the candidate's first start is on probation and reports its digest: %+v", first))
		}
		require(sameFiles(snapshot(mainWork), snapshot(thisWork)) == "", "after the first start both hosts must still be identical: "+sameFiles(snapshot(mainWork), snapshot(thisWork)))
		fmt.Printf("ok equivalence (incumbent on probation: %v): state and binary directories byte-identical to main's updater after install and after the first start\n", probation)
		p.server.Close()
		cleanupPayloads()
		cleanupThis()
		cleanupMain()
	}
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
	require(send(ctx, conn, release).State == "installed", "the candidate must install")
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
	require(send(ctx, conn, release).State == "rolled_back", "a replay of the rolled-back run must be refused")
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

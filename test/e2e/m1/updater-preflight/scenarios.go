package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/secretpreflight"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
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
	rolloutCases(ctx, data)
	replacementCase(ctx)
	rebuildCase(ctx)
	oldHostCase(ctx)
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
		require(reply.Refusal.SHA256 == digest(candidate) && reply.Refusal.RunAttempt == "1", "refusal must name candidate digest and attempt")
		require(bytes.Equal(read(h.Binary), original) && record(h.TrialFile) == nil && string(read(h.Binary+".prev")) == "superseded", "preflight refusal must stage nothing")
		require(fence(work) == "1", "refusal must preserve the run fence")
		reported := request(ctx, conn, releasepush.SubjectVersion, nil).Refusal
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
	payload, err := json.Marshal(release)
	must(err)
	fresh := releasepush.NewVerifier()
	fresh.Client = &http.Client{Transport: failTransport{}}
	h.Verifier, h.Client = fresh, client
	reply := request(ctx, conn, releasepush.SubjectOrch, payload)
	require(reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalHost, "unavailable signing keys must be host prerequisite")
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
		reply = request(ctx, conn, releasepush.SubjectOrch, payload)
		require(reply.Refusal != nil && reply.Refusal.Kind == entry.kind, entry.name+" refusal must classify proven evidence")
		fmt.Println("ok classification:", entry.name, "->", entry.kind)
	}
	fmt.Println("ok classification: unavailable JWKS -> host_prerequisite")
	candidate := filepath.Join(work, "noisy")
	writeExecutable(candidate, stamped(data, strings.Repeat("b", 40), "noise"))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err = secretpreflight.Check(ctx, candidate)
	runtime.ReadMemStats(&after)
	require(err != nil && strings.Contains(err.Error(), "[truncated]") && after.TotalAlloc-before.TotalAlloc < 1<<20, "10 MiB output must drain with less than 1 MiB allocation")
	fmt.Println("ok output: 10 MiB drained with less than 1 MiB allocated")
}

func rolloutCases(ctx context.Context, data []byte) {
	work, cleanup := temporary("rollout-preflight-")
	defer cleanup()
	worker, _, _ := preparedHost(work)
	writeExecutable(filepath.Join(work, "asset"), stamped(data, shaB, "refuse"))
	accepted := filepath.Join(work, "accepted")
	writeExecutable(accepted, stamped(data, shaB, "refuse"))
	release, verifier, client, closeProvider := signedRelease(ctx, filepath.Join(work, "asset"), strings.Repeat("b", 40), "100", "1")
	defer closeProvider()
	worker.Verifier, worker.Client = verifier, client
	workerConn, closeWorker := listener(worker)
	defer closeWorker()
	must(worker.ServeWorker(workerConn, "lane.workers", "worker-one"))
	_, err := workerConn.Subscribe("lane.no-worker", func(*nats.Msg) {})
	must(err)
	must(workerConn.Flush())
	founder, err := releasepush.NewHandler(work)
	must(err)
	later, err := releasepush.NewHandler(work)
	must(err)
	founder.Binary, founder.Revision, founder.Verifier = accepted, release.SHA, verifier
	later.Binary, later.Revision, later.Verifier = accepted, release.SHA, verifier
	founder.Digest = release.Binaries[runtime.GOARCH].SHA256
	later.Digest = founder.Digest
	var broken, laterBroken atomic.Bool
	founder.Health = func(_ context.Context, _ string) releasepush.HealthResult {
		if broken.Load() {
			return releasepush.HealthResult{Service: errors.New("candidate health broken")}
		}
		return releasepush.HealthResult{}
	}
	later.Health = func(_ context.Context, _ string) releasepush.HealthResult {
		if laterBroken.Load() {
			return releasepush.HealthResult{Service: errors.New("services unreadable")}
		}
		return releasepush.HealthResult{}
	}
	var visited atomic.Bool
	later.Relay = func(context.Context, []byte) []releasepush.HostVersion { visited.Store(true); return nil }
	regions := []releasepush.Region{}
	for i, handler := range []*releasepush.Handler{founder, later} {
		options, err := releasepush.Options(work, nil)
		must(err)
		options.Host, options.Port, options.CustomClientAuthentication = "127.0.0.1", -1, nil
		srv, err := server.NewServer(options)
		must(err)
		go srv.Start()
		require(srv.ReadyForConnections(5*time.Second), "regional listener must listen")
		defer srv.Shutdown()
		conn, err := nats.Connect(srv.ClientURL(), nats.Secure(&tls.Config{InsecureSkipVerify: true}))
		must(err)
		defer conn.Close()
		must(handler.Serve(conn))
		certificate, err := x509.ParseCertificate(options.TLSConfig.Certificates[0].Certificate[0])
		must(err)
		pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
		regions = append(regions, releasepush.Region{Region: []string{"sjc", "gru"}[i], NATS: srv.ClientURL(), SPKISHA256: hex.EncodeToString(pin[:])})
	}
	regionBytes, err := json.Marshal(regions)
	must(err)
	write(filepath.Join(work, "regions.json"), string(regionBytes))
	assets := filepath.Join(work, "assets")
	must(os.Mkdir(assets, 0o700))
	writeExecutable(filepath.Join(assets, "terrascale-orchestrator-linux-"+runtime.GOARCH), stamped(data, release.SHA, "refuse"))
	endpoint := strings.TrimSuffix(client.Transport.(providerTransport).url, "/binary") + "/token?"
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", endpoint))
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "lane"))
	nodes := []*api.Node{{ID: "worker-one", Role: api.NodeRoleWorker}}
	for _, mode := range []string{"worker-integrity", "first-integrity", "unknown-kind", "absent-kind", "host-refusal", "all-preflight", "refusal-silence", "unhealthy-refusal", "unhealthy-fleet", "repair-unhealthy-fleet"} {
		visited.Store(false)
		broken.Store(strings.HasSuffix(mode, "unhealthy-fleet"))
		laterBroken.Store(strings.HasSuffix(mode, "unhealthy-fleet"))
		worker.Client = client
		founder.Revision = release.SHA
		founder.Client = client
		if mode == "worker-integrity" {
			worker.Client = &http.Client{Transport: corruptTransport{client.Transport}}
		}
		founder.Relay = func(ctx context.Context, payload []byte) []releasepush.HostVersion {
			switch mode {
			case "unknown-kind":
				return []releasepush.HostVersion{{Host: "worker-one", Refusal: &releasepush.Refusal{Kind: "unrecognized", SHA: release.SHA, Reason: "unknown refusal"}}}
			case "absent-kind":
				return []releasepush.HostVersion{{Host: "worker-one", Refusal: &releasepush.Refusal{SHA: release.SHA, Reason: "older agent refusal"}}}
			case "refusal-silence":
				return releasepush.RelayWorkers(ctx, workerConn, "lane.no-worker", payload, nodes)
			case "unhealthy-refusal":
				broken.Store(true)
			case "unhealthy-fleet", "repair-unhealthy-fleet":
				return nil
			}
			return releasepush.RelayWorkers(ctx, workerConn, "lane.workers", payload, nodes)
		}
		if mode == "first-integrity" || mode == "all-preflight" || mode == "refusal-silence" {
			founder.Revision = strings.Repeat("a", 40)
			if mode == "first-integrity" {
				founder.Client = &http.Client{Transport: corruptTransport{client.Transport}}
			}
		}
		var output bytes.Buffer
		pushCtx, cancelPush := context.WithCancel(ctx)
		if mode == "unhealthy-refusal" {
			pushCtx, cancelPush = context.WithTimeout(ctx, 45*time.Second)
		}
		if mode == "repair-unhealthy-fleet" {
			pushCtx, cancelPush = context.WithTimeout(ctx, 20*time.Second)
		}
		args := []string{"--sha", release.SHA, "--dir", assets, "--regions", filepath.Join(work, "regions.json")}
		if mode == "repair-unhealthy-fleet" {
			args = append(args, "--repair-unhealthy-fleet")
		}
		err := releasepush.Push(pushCtx, args, &output)
		cancelPush()
		results, skipped := []releasepush.Result{}, []releasepush.Result{}
		scanner := bufio.NewScanner(&output)
		for scanner.Scan() {
			var result releasepush.Result
			must(json.Unmarshal(scanner.Bytes(), &result))
			if result.State == "repair_skipped_health" {
				require(len(results) == 0, "skipped hosts must be printed before any region is pushed: "+output.String())
				skipped = append(skipped, result)
				continue
			}
			results = append(results, result)
		}
		require(len(results) == 2, fmt.Sprintf("both regional outcomes must be reported: %s", output.String()))
		require((len(skipped) == 2) == (mode == "repair-unhealthy-fleet"), "only a repair push skips the initial health check: "+output.String())
		if mode == "unhealthy-fleet" {
			require(results[0].State == "failed" && strings.Contains(results[0].Error, "candidate health broken") && results[0].ConnectMS == 0, "an ordinary push refuses a fleet whose first host reports a health error: "+output.String())
		}
		if mode == "repair-unhealthy-fleet" {
			require(skipped[0].Region == "sjc" && skipped[0].Health == `"candidate health broken"` && skipped[1].Region == "gru" && skipped[1].Health == `"services unreadable"`, "each skipped host is printed with its health: "+output.String())
			require(results[0].State == "current" && results[0].Repair == `"candidate health broken"` && strings.Contains(results[0].Error, "health of") && results[0].Health == "candidate health broken", "a repair push reaches the unhealthy first host and still waits for its health: "+output.String())
		}
		fatal := mode != "host-refusal" && mode != "refusal-silence"
		if fatal {
			require(err != nil && !visited.Load() && results[1].State == "skipped", "fatal refusal must stop later regions: "+mode)
			if mode == "all-preflight" {
				require(strings.Contains(results[0].Error, "every host in the first region"), "uniform preflight must explain rollout stop")
			}
			if mode == "unhealthy-refusal" {
				require(results[0].Health == "candidate health broken" && strings.Contains(results[0].Error, "health of") && strings.HasPrefix(results[0].State, "refused on"), "an accepted first host with broken health must stop the rollout despite a refusing worker: "+output.String())
			}
		} else {
			require(visited.Load() && results[1].Error == "" && err != nil, "a host refusal fails at the end and allows the next region: "+mode)
			if mode == "host-refusal" {
				require(results[0].Health == "ok" && results[0].HealthyMS > 0, "an accepted first host is health-checked even when a worker refuses")
			}
			if mode == "refusal-silence" {
				require(!strings.Contains(results[0].Error, "every host") && len(results[0].Workers) == 1 && results[0].Workers[0].Error == "no answer" && results[0].Workers[0].Refusal == nil, "a silent worker is not a refusal: "+output.String())
			}
		}
		fmt.Println("ok rollout", mode, ": regional outcomes verified")
	}
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

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func serveRegion(ctx context.Context, args []string) {
	work, port, jwks, binaryURL := args[0], args[1], args[2], args[3]
	mode := candidateMode()
	probation, err := releasepush.Probe(work, os.Stdout)
	if err != nil {
		fmt.Println("START", err)
		return
	}
	if mode == "crash" {
		os.Exit(3)
	}
	h, err := releasepush.NewHandler(work)
	must(err)
	h.Verifier.JWKSURL = jwks
	h.Client = &http.Client{Transport: providerTransport{binaryURL}}
	h.Health = func(context.Context, string) releasepush.HealthResult { return releasepush.HealthResult{} }
	options, err := releasepush.Options(work, nil)
	must(err)
	options.Host, options.CustomClientAuthentication = "127.0.0.1", nil
	fmt.Sscan(port, &options.Port)
	srv, err := server.NewServer(options)
	must(err)
	go srv.Start()
	require(srv.ReadyForConnections(5*time.Second), "region listener must listen")
	conn, err := nats.Connect(srv.ClientURL(), nats.Secure(&tls.Config{InsecureSkipVerify: true}))
	must(err)
	must(h.Serve(conn))
	fmt.Println("SERVING", probation.Served())
	select {
	case <-h.Installed:
		if mode == "stuck" {
			<-ctx.Done()
		}
		conn.Close()
		srv.Shutdown()
		srv.WaitForShutdown()
	case <-ctx.Done():
	}
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
	asset := otherAsset(work, shaC)
	release, verifier, client, closeProvider := signedRelease(ctx, asset, shaC, "3", "1")
	defer closeProvider()
	port := freePort()
	provider := strings.TrimSuffix(client.Transport.(providerTransport).url, "/binary")
	region := func() *exec.Cmd {
		return exec.CommandContext(ctx, filepath.Join(work, "installed"), "serve-region", work, fmt.Sprint(port), verifier.JWKSURL, provider+"/binary")
	}
	unconfirmed := region()
	ready(unconfirmed, "SERVING false")
	restarted := make(chan *exec.Cmd, 1)
	go func() {
		_ = unconfirmed.Wait()
		next := region()
		ready(next, "SERVING true")
		restarted <- next
	}()
	options, err := releasepush.Options(work, nil)
	must(err)
	certificate, err := x509.ParseCertificate(options.TLSConfig.Certificates[0].Certificate[0])
	must(err)
	pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	regions, err := json.Marshal([]releasepush.Region{{Region: "sjc", NATS: fmt.Sprintf("nats://127.0.0.1:%d", port), SPKISHA256: hex.EncodeToString(pin[:])}})
	must(err)
	write(filepath.Join(work, "replacement-regions.json"), string(regions))
	assets := filepath.Join(work, "replacement-assets")
	must(os.Mkdir(assets, 0o700))
	writeExecutable(filepath.Join(assets, "terrascale-orchestrator-linux-"+runtime.GOARCH), read(asset))
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", provider+"/token?"))
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "lane"))
	var output bytes.Buffer
	err = releasepush.Push(ctx, []string{"--sha", release.SHA, "--dir", assets, "--regions", filepath.Join(work, "replacement-regions.json")}, &output)
	require(err == nil, fmt.Sprintf("a replacement must reach an unconfirmed host: %v %s", err, output.String()))
	var result releasepush.Result
	must(json.Unmarshal(bytes.TrimSpace(output.Bytes()), &result))
	require(result.State == "installed" && result.Health == "ok" && strings.Contains(result.Unconfirmed, "rollback unavailable"), "the unconfirmed candidate stays visible in the rollout output: "+output.String())
	require(bytes.Equal(read(filepath.Join(work, "installed")), read(asset)) && bytes.Equal(read(filepath.Join(work, "installed.prev")), candidate), "the replacement must install with the unconfirmed candidate as previous")
	stop(<-restarted)
	fmt.Println("ok replacement: unconfirmed candidate admitted, replaced by run 3 and reported:", result.Unconfirmed)
}

func payloadFile(work, name string, release releasepush.OrchRelease) string {
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
	must(os.Mkdir(filepath.Join(work, "nats"), 0o700))
	binary := filepath.Join(work, "installed")
	writeExecutable(binary, stamped(data, strings.Repeat("a", 40), "pass"))
	writeExecutable(filepath.Join(work, "asset"), stamped(data, strings.Repeat("b", 40), "pass"))
	command := exec.CommandContext(ctx, binary, "self-update", work, "slow-shutdown")
	output, err := command.CombinedOutput()
	require(err == nil && strings.Contains(string(output), "installed reply collected") && strings.Contains(string(output), "duplicates installed installed") && strings.Contains(string(output), "ordinary shutdown finished"), fmt.Sprintf("the old process must finish its ordinary shutdown after commit despite duplicate notifications: %v %s", err, output))
	fmt.Println("ok process exit: installed reply collected; two duplicate requests during a 4-second ordinary shutdown coalesced; shutdown finished; old process exited")
}

func selfUpdate(ctx context.Context, work, mode string) {
	h, err := releasepush.NewHandler(work)
	must(err)
	conn, closeListener := listener(h)
	defer closeListener()
	if mode == "postcommit-failures" {
		h.Relay = func(context.Context, []byte) []releasepush.HostVersion {
			conn.Close()
			return []releasepush.HostVersion{{Host: "worker", Error: "relay network unavailable"}}
		}
		release, verifier, client, closeProvider := signedRelease(ctx, filepath.Join(work, "asset"), strings.Repeat("b", 40), "2", "1")
		defer closeProvider()
		h.Verifier, h.Client = verifier, client
		payload, err := json.Marshal(release)
		must(err)
		must(conn.Publish(releasepush.SubjectOrch, payload))
		must(conn.Flush())
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
		reported := request(ctx, conn, releasepush.SubjectVersion, nil).Refusal
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
	must(syscall.Mkfifo(h.Binary+".next", 0o600))
	replied := make(chan releasepush.Reply, 1)
	go func() { replied <- installRequest(ctx, h, conn, work, shaB, "2") }()
	reader, err := os.OpenFile(h.Binary+".next", os.O_RDONLY, 0)
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
	require(reply.State == "rejected" && bytes.Equal(read(h.Binary), original), fmt.Sprintf("a candidate that cannot be synced is refused: %+v", reply))
	fmt.Println("ok slow write: a command started while the candidate write was stalled started in", delay.Round(time.Millisecond))
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

func keepServing(ctx context.Context, start func() *exec.Cmd) func() {
	var mu sync.Mutex
	var current *exec.Cmd
	stopped := false
	up, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		for first := true; ctx.Err() == nil; first = false {
			mu.Lock()
			if stopped {
				mu.Unlock()
				return
			}
			current = start()
			if first {
				ready(current, "SERVING true")
				close(up)
			} else {
				must(current.Start())
			}
			command := current
			mu.Unlock()
			_ = command.Wait()
		}
	}()
	<-up
	return func() {
		mu.Lock()
		stopped = true
		_ = current.Process.Kill()
		mu.Unlock()
		<-done
	}
}

func regionFile(work, name, address string) string {
	options, err := releasepush.Options(work, nil)
	must(err)
	certificate, err := x509.ParseCertificate(options.TLSConfig.Certificates[0].Certificate[0])
	must(err)
	pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	regions, err := json.Marshal([]releasepush.Region{{Region: "sjc", NATS: address, SPKISHA256: hex.EncodeToString(pin[:])}})
	must(err)
	path := filepath.Join(work, name)
	write(path, string(regions))
	return path
}

func pushOne(ctx context.Context, work, name string, asset []byte, release releasepush.OrchRelease, provider, regions string) (releasepush.Result, error) {
	assets := filepath.Join(work, name)
	must(os.Mkdir(assets, 0o700))
	writeExecutable(filepath.Join(assets, "terrascale-orchestrator-linux-"+runtime.GOARCH), asset)
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", provider+"/token?"))
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "lane"))
	var output bytes.Buffer
	err := releasepush.Push(ctx, []string{"--sha", release.SHA, "--dir", assets, "--regions", regions}, &output)
	var result releasepush.Result
	must(json.Unmarshal(bytes.TrimSpace(output.Bytes()), &result))
	return result, err
}

func rebuildCase(ctx context.Context) {
	work, cleanup := temporary("rebuild-")
	defer cleanup()
	must(os.Mkdir(filepath.Join(work, "nats"), 0o700))
	helper, err := os.Executable()
	must(err)
	data := read(helper)
	installed := filepath.Join(work, "installed")
	first := stamped(data, shaB, "original")
	writeExecutable(installed, first)
	port := freePort()
	regions := regionFile(work, "regions.json", fmt.Sprintf("nats://127.0.0.1:%d", port))
	push := func(mode, run string) (releasepush.Result, []byte, error) {
		build := stamped(data, shaB, mode)
		asset := filepath.Join(work, "asset-"+mode)
		writeExecutable(asset, build)
		release, verifier, client, closeProvider := signedRelease(ctx, asset, shaB, run, "1")
		defer closeProvider()
		provider := strings.TrimSuffix(client.Transport.(providerTransport).url, "/binary")
		stopRegion := keepServing(ctx, func() *exec.Cmd {
			return exec.CommandContext(ctx, installed, "serve-region", work, fmt.Sprint(port), verifier.JWKSURL, provider+"/binary")
		})
		defer stopRegion()
		result, err := pushOne(ctx, work, "assets-"+mode, build, release, provider, regions)
		return result, build, err
	}
	crashed, _, err := push("crash", "10")
	require(err != nil && crashed.State == "rolled_back" && bytes.Equal(read(installed), first), fmt.Sprintf("a rebuild of the same commit that rolls back to the first build is not serving: %v %+v", err, crashed))
	rebuilt, build, err := push("pass", "11")
	require(err == nil && rebuilt.State == "installed" && rebuilt.Health == "ok" && rebuilt.RevisionOnly == "" && bytes.Equal(read(installed), build), fmt.Sprintf("another build of the installed commit installs and serves: %v %+v", err, rebuilt))
	fmt.Println("ok rebuild: same commit, other digest installs; its rollback to the first build is reported rolled_back, not serving")
}

func oldHostCase(ctx context.Context) {
	work, cleanup := temporary("old-host-")
	defer cleanup()
	must(os.Mkdir(filepath.Join(work, "nats"), 0o700))
	helper, err := os.Executable()
	must(err)
	build := stamped(read(helper), shaB, "pass")
	asset := filepath.Join(work, "asset")
	writeExecutable(asset, build)
	release, _, client, closeProvider := signedRelease(ctx, asset, shaB, "5", "1")
	defer closeProvider()
	options, err := releasepush.Options(work, nil)
	must(err)
	options.Host, options.Port, options.CustomClientAuthentication = "127.0.0.1", -1, nil
	srv, err := server.NewServer(options)
	must(err)
	go srv.Start()
	require(srv.ReadyForConnections(5*time.Second), "old host listener must listen")
	defer srv.Shutdown()
	conn, err := nats.Connect(srv.ClientURL(), nats.Secure(&tls.Config{InsecureSkipVerify: true}))
	must(err)
	defer conn.Close()
	answers := map[string]string{
		releasepush.SubjectVersion: `{"version":"` + shaB + `"}`,
		releasepush.SubjectHealth:  `{"version":"` + shaB + `","health":"ok"}`,
		releasepush.SubjectOrch:    `{"state":"current","version":"` + shaB + `"}`,
	}
	for subject, answer := range answers {
		_, err := conn.Subscribe(subject, func(m *nats.Msg) { must(m.Respond([]byte(answer))) })
		must(err)
	}
	must(conn.Flush())
	result, err := pushOne(ctx, work, "assets", build, release, strings.TrimSuffix(client.Transport.(providerTransport).url, "/binary"), regionFile(work, "regions.json", srv.ClientURL()))
	require(err == nil && result.State == "current" && result.Health == "ok" && strings.Contains(result.RevisionOnly, "revision only"), fmt.Sprintf("a host without a digest in its version answer is confirmed by revision and says so: %v %+v", err, result))
	fmt.Println("ok old host: no digest in the version answer; serving confirmed by revision only and reported")
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

func watchdogCase(ctx context.Context, pusher string) {
	work, cleanup := temporary("watchdog-")
	defer cleanup()
	must(os.Mkdir(filepath.Join(work, "nats"), 0o700))
	helper, err := os.Executable()
	must(err)
	data := read(helper)
	installed := filepath.Join(work, "installed")
	writeExecutable(installed, stamped(data, shaA, "stuck"))
	port := freePort()
	regions := regionFile(work, "regions.json", fmt.Sprintf("nats://127.0.0.1:%d", port))
	build := stamped(data, shaB, "pass")
	asset := filepath.Join(work, "asset")
	writeExecutable(asset, build)
	release, verifier, client, closeProvider := signedRelease(ctx, asset, shaB, "2", "1")
	defer closeProvider()
	provider := strings.TrimSuffix(client.Transport.(providerTransport).url, "/binary")
	stopRegion := keepServing(ctx, func() *exec.Cmd {
		return exec.CommandContext(ctx, installed, "serve-region", work, fmt.Sprint(port), verifier.JWKSURL, provider+"/binary")
	})
	defer stopRegion()
	assets := filepath.Join(work, "assets")
	must(os.Mkdir(assets, 0o700))
	writeExecutable(filepath.Join(assets, "terrascale-orchestrator-linux-"+runtime.GOARCH), build)
	push := exec.CommandContext(ctx, pusher, "release", "push", "--sha", release.SHA, "--dir", assets, "--regions", regions)
	push.Env = append(os.Environ(), "ACTIONS_ID_TOKEN_REQUEST_URL="+provider+"/token?", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=lane")
	output, err := push.Output()
	var result releasepush.Result
	must(json.Unmarshal(bytes.TrimSpace(output), &result))
	waited := time.Duration(result.ServingMS-result.AcceptedMS) * time.Millisecond
	require(err == nil && result.State == "installed" && bytes.Equal(read(installed), build) && waited >= 45*time.Second && waited <= 2*time.Minute, fmt.Sprintf("a shutdown stuck until the watchdog ends with the new binary serving early enough to leave a whole probation inside the pusher's wait: %v %+v", err, result))
	fmt.Println("ok watchdog: stuck shutdown ended by the watchdog; new binary serving", waited.Round(time.Second), "after the reply")
}

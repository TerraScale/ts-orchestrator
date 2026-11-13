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
	go func() { rollbackCases(ctx); upgradeCases(ctx, data, previous); close(probationDone) }()
	preflightDone := make(chan struct{})
	go func() {
		preflightCases(ctx, work, h, conn, data, original)
		damagedCases(ctx)
		fenceCase(ctx)
		networkCases(ctx, work, h, conn, data)
		close(preflightDone)
	}()
	rolloutCases(ctx, data)
	replacementCase(ctx)
	<-preflightDone
	<-probationDone
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
		must(os.WriteFile(filepath.Join(work, "asset"), candidate, 0o755))
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
		closeListener()
		cleanup()
	}
	fmt.Println("ok damaged trial: empty, truncated, empty-object and array trials serve unconfirmed, never adopt, kept as .damaged on replacement")
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
	must(os.WriteFile(filepath.Join(work, "asset"), stamped(data, strings.Repeat("b", 40), "pass"), 0o755))
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
	must(os.WriteFile(candidate, stamped(data, strings.Repeat("b", 40), "noise"), 0o755))
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
	must(os.WriteFile(filepath.Join(work, "asset"), stamped(data, shaB, "refuse"), 0o755))
	accepted := filepath.Join(work, "accepted")
	must(os.WriteFile(accepted, stamped(data, shaB, "refuse"), 0o755))
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
	var broken atomic.Bool
	founder.Health = func(context.Context) error {
		if broken.Load() {
			return errors.New("candidate health broken")
		}
		return nil
	}
	later.Health = func(context.Context) error { return nil }
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
	must(os.WriteFile(filepath.Join(assets, "terrascale-orchestrator-linux-"+runtime.GOARCH), stamped(data, release.SHA, "refuse"), 0o755))
	endpoint := strings.TrimSuffix(client.Transport.(providerTransport).url, "/binary") + "/token?"
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", endpoint))
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "lane"))
	nodes := []*api.Node{{ID: "worker-one", Role: api.NodeRoleWorker}}
	for _, mode := range []string{"worker-integrity", "first-integrity", "unknown-kind", "absent-kind", "host-refusal", "all-preflight", "refusal-silence", "unhealthy-refusal"} {
		visited.Store(false)
		broken.Store(false)
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
		err := releasepush.Push(pushCtx, []string{"--sha", release.SHA, "--dir", assets, "--regions", filepath.Join(work, "regions.json")}, &output)
		cancelPush()
		results := []releasepush.Result{}
		scanner := bufio.NewScanner(&output)
		for scanner.Scan() {
			var result releasepush.Result
			must(json.Unmarshal(scanner.Bytes(), &result))
			results = append(results, result)
		}
		require(len(results) == 2, fmt.Sprintf("both regional outcomes must be reported: %s", output.String()))
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
	must(os.WriteFile(filepath.Join(work, "installed.prev"), stamped(read(helper), strings.Repeat("d", 40), "pass"), 0o755))
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
	probation, err := releasepush.Probe(work, os.Stdout)
	if err != nil {
		fmt.Println("START", err)
		return
	}
	h, err := releasepush.NewHandler(work)
	must(err)
	h.Verifier.JWKSURL = jwks
	h.Client = &http.Client{Transport: providerTransport{binaryURL}}
	h.Health = func(context.Context) error { return nil }
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
	must(os.WriteFile(filepath.Join(assets, "terrascale-orchestrator-linux-"+runtime.GOARCH), read(asset), 0o755))
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
	must(os.WriteFile(filepath.Join(work, "installed"), previousBytes, 0o755))
	candidate := stamped(data, shaB, "pass")
	asset := filepath.Join(work, "asset")
	must(os.WriteFile(asset, candidate, 0o755))
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
	fmt.Println("ok upgrade: previous build installs this build; probation counts from its trial; its fence refuses run 1; third start restores its exact bytes; it then refuses the replay and run 1")
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
	must(os.WriteFile(binary, stamped(data, strings.Repeat("a", 40), "pass"), 0o755))
	must(os.WriteFile(filepath.Join(work, "asset"), stamped(data, strings.Repeat("b", 40), "pass"), 0o755))
	command := exec.CommandContext(ctx, binary, "self-update", work, "lost-notification")
	output, err := command.CombinedOutput()
	require(err == nil && strings.Contains(string(output), "installed reply collected"), fmt.Sprintf("old process must exit after reply without a restart receiver: %v %s", err, output))
	fmt.Println("ok process exit: installed reply collected; restart channel unobserved; old process exited")
}

func selfUpdate(ctx context.Context, work, mode string) {
	h, err := releasepush.NewHandler(work)
	must(err)
	conn, closeListener := listener(h)
	defer closeListener()
	if mode == "postcommit-failures" {
		h.Installed = nil
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
		<-ctx.Done()
		panic("old process did not exit after lost reply and notification")
	}
	reply := installRequest(ctx, h, conn, work, strings.Repeat("b", 40), "2")
	require(reply.State == "installed", "self update must return installed")
	fmt.Println("installed reply collected")
	<-ctx.Done()
	panic("old process did not exit")
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
		require(reply.State == "rejected" && reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalHost && strings.Contains(reply.Error, "run fence damaged"), fmt.Sprintf("a damaged fence must refuse every run: %+v", reply))
		require(fence(work) == content && bytes.Equal(read(h.Binary), original), "a damaged fence must never be overwritten")
	}
	write(h.RunIDFile, "5")
	reply = installRequest(ctx, h, conn, work, shaB, "6")
	require(reply.State == "installed" && fence(work) == "6" && bytes.Equal(read(h.Binary), candidate), fmt.Sprintf("a newer run must install: %+v", reply))
	fmt.Println("ok fence: older run stale; damaged fence refuses every run and stays; newer run installs")
}

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

func run(ctx context.Context, binary string) {
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
	go func() { rollbackCases(ctx, data); close(probationDone) }()
	for i, mode := range []string{"refuse", "noise", "cannot-execute", "hang"} {
		candidate := stamped(data, strings.Repeat("b", 40), mode)
		if mode == "cannot-execute" {
			candidate = []byte("invalid executable")
		}
		must(os.WriteFile(filepath.Join(work, "asset"), candidate, 0o755))
		start := time.Now()
		reply := installRequest(ctx, h, conn, work, strings.Repeat("b", 40), fmt.Sprint(i+2))
		require(reply.State == "rejected" && reply.Refusal != nil && reply.Refusal.Kind == releasepush.RefusalHost && reply.Refusal.Preflight, "candidate preflight failure must be a structured host refusal")
		require(reply.Refusal.SHA256 == digest(candidate) && reply.Refusal.RunAttempt == "1", "refusal must name candidate digest and attempt")
		current, err := os.ReadFile(h.Binary)
		must(err)
		require(bytes.Equal(current, original) && active(h.TrialFile, original) == nil, "preflight refusal must preserve binary and installed records")
		require(active(h.RunIDFile, original)["run_id"] == "1", "refusal must preserve installed run fence")
		require(request(ctx, conn, releasepush.SubjectVersion, nil).Refusal == nil, "diagnostic naming another binary must be inert")
		require(len(reply.Refusal.Reason) <= secretpreflight.MaxOutputBytes && utf8.ValidString(reply.Refusal.Reason) && !strings.ContainsFunc(reply.Refusal.Reason, unicode.IsControl), "diagnostic must be bounded valid text")
		if mode == "hang" {
			require(time.Since(start) >= 70*time.Second && time.Since(start) < 75*time.Second, "preflight must keep its 70-second bound")
		}
		fmt.Println("ok preflight", mode, ": refused; binary, fence and probation unchanged; abandoned diagnostic inert")
	}
	for _, content := range []string{"", "{"} {
		for _, path := range []string{h.TrialFile, h.RollbackFile, h.RefusalFile} {
			write(path, content)
		}
		command := exec.CommandContext(ctx, h.Binary, "corrupt-start", work)
		output, err := command.CombinedOutput()
		require(err == nil && strings.Contains(string(output), "corrupt startup accepted"), fmt.Sprintf("damaged records must permit real startup: %v %s", err, output))
	}
	fmt.Println("ok records: empty and truncated records permit Probe -> NewHandler -> Served")
	fenceCase(ctx, data)
	networkCases(ctx, work, h, conn, data)
	rolloutCases(ctx, data)
	<-probationDone
	crossFilesystem(ctx)
	selfExitCase(ctx, data)
	fmt.Println("updater-preflight e2e: PASS")
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
	must(os.WriteFile(filepath.Join(work, "asset"), stamped(data, strings.Repeat("b", 40), "refuse"), 0o755))
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
	founder.Binary, founder.Revision, founder.Verifier = worker.Binary, release.SHA, verifier
	later.Binary, later.Revision, later.Verifier = worker.Binary, release.SHA, verifier
	founder.Health = func(context.Context) error { return nil }
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
	for _, mode := range []string{"worker-integrity", "first-integrity", "unknown-kind", "absent-kind", "host-refusal", "all-preflight", "silence"} {
		visited.Store(false)
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
			case "silence":
				return releasepush.RelayWorkers(ctx, workerConn, "lane.no-worker", payload, nodes)
			}
			return releasepush.RelayWorkers(ctx, workerConn, "lane.workers", payload, nodes)
		}
		if mode == "first-integrity" || mode == "all-preflight" {
			founder.Revision = strings.Repeat("a", 40)
			if mode == "first-integrity" {
				founder.Client = &http.Client{Transport: corruptTransport{client.Transport}}
			}
		}
		var output bytes.Buffer
		err := releasepush.Push(ctx, []string{"--sha", release.SHA, "--dir", assets, "--regions", filepath.Join(work, "regions.json")}, &output)
		results := []releasepush.Result{}
		scanner := bufio.NewScanner(&output)
		for scanner.Scan() {
			var result releasepush.Result
			must(json.Unmarshal(scanner.Bytes(), &result))
			results = append(results, result)
		}
		require(len(results) == 2, fmt.Sprintf("both regional outcomes must be reported: %s", output.String()))
		fatal := mode != "host-refusal" && mode != "silence"
		if fatal {
			require(err != nil && !visited.Load() && results[1].State == "skipped", "fatal refusal must stop later regions: "+mode)
			if mode == "all-preflight" {
				require(strings.Contains(results[0].Error, "every host in the first region"), "uniform preflight must explain rollout stop")
			}
		} else {
			require(visited.Load() && results[1].Error == "", "host condition must allow next region")
			require((err == nil) == (mode == "silence"), "host refusal fails at end; silence remains informational")
		}
		fmt.Println("ok rollout", mode, ": regional outcomes verified")
	}
}

func rollbackCases(ctx context.Context, data []byte) {
	for _, mode := range []string{"missing-previous", "wrong-previous", "rolled-back", "slow"} {
		work, cleanup := temporary("probation-preflight-")
		h, _, candidate := preparedHost(work)
		conn, closeListener := listener(h)
		if mode == "slow" {
			_, err := conn.Subscribe("lane.probation.silent", func(*nats.Msg) {})
			must(err)
			must(conn.Flush())
			h.Relay = func(ctx context.Context, payload []byte) []releasepush.HostVersion {
				return releasepush.RelayWorkers(ctx, conn, "lane.probation.silent", payload, []*api.Node{{ID: "silent", Role: api.NodeRoleWorker}})
			}
		}
		start := time.Now()
		reply := installRequest(ctx, h, conn, work, strings.Repeat("b", 40), "2")
		require(reply.State == "installed", "probation scenario must install")
		if mode == "slow" {
			require(time.Since(start) >= releasepush.WorkerReplyWait, "silent workers must consume full reply budget")
		}

		select {
		case <-h.Installed:
		case <-ctx.Done():
			panic("restart request missing")
		}
		records := rows(h.TrialFile)
		for _, record := range records {
			if record["sha256"] != digest(candidate) {
				continue
			}
			record["requested"] = time.Now().Add(-10 * time.Minute).UTC().Format(time.RFC3339Nano)
			if mode != "slow" {
				record["starts"] = 2
			}
			if mode == "missing-previous" || mode == "wrong-previous" {
				previous := record["previous"].(map[string]any)
				path := h.Binary + ".prev-" + previous["sha"].(string) + "-" + previous["sha256"].(string)
				if mode == "missing-previous" {
					must(os.Remove(path))
				} else {
					must(os.WriteFile(path, stamped(data, strings.Repeat("d", 40), "pass"), 0o755))
				}
			}
		}
		encoded, err := json.Marshal(records)
		must(err)
		must(os.WriteFile(h.TrialFile, encoded, 0o600))
		recovery := mode
		if recovery == "wrong-previous" {
			recovery = "missing-previous"
		}
		command := exec.CommandContext(ctx, h.Binary, "recover-state", work, recovery)
		output, err := command.CombinedOutput()
		require(err == nil, fmt.Sprintf("probation %s: %v: %s", mode, err, output))
		if mode == "missing-previous" {
			require(strings.Contains(string(output), "candidate unconfirmed"), "missing previous must stay unconfirmed")
		}
		if mode == "rolled-back" {
			current, err := os.ReadFile(h.Binary)
			must(err)
			require(!bytes.Equal(current, candidate), "valid previous must be restored")
		}
		fmt.Println("ok probation", mode, ":", strings.TrimSpace(string(output)))
		closeListener()
		cleanup()
	}
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

func unconfirmedPush(ctx context.Context, work string, h *releasepush.Handler, data []byte) {
	release, verifier, client, closeProvider := signedRelease(ctx, h.Binary, h.Revision, "2", "1")
	defer closeProvider()
	h.Verifier = verifier
	options, err := releasepush.Options(work, nil)
	must(err)
	options.Host, options.Port, options.CustomClientAuthentication = "127.0.0.1", -1, nil
	srv, err := server.NewServer(options)
	must(err)
	go srv.Start()
	require(srv.ReadyForConnections(5*time.Second), "unconfirmed listener must listen")
	defer srv.Shutdown()
	conn, err := nats.Connect(srv.ClientURL(), nats.Secure(&tls.Config{InsecureSkipVerify: true}))
	must(err)
	defer conn.Close()
	must(h.Serve(conn))
	certificate, err := x509.ParseCertificate(options.TLSConfig.Certificates[0].Certificate[0])
	must(err)
	pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	regions, err := json.Marshal([]releasepush.Region{{Region: "sjc", NATS: srv.ClientURL(), SPKISHA256: hex.EncodeToString(pin[:])}})
	must(err)
	write(filepath.Join(work, "unconfirmed-regions.json"), string(regions))
	assets := filepath.Join(work, "unconfirmed-assets")
	must(os.Mkdir(assets, 0o700))
	must(os.WriteFile(filepath.Join(assets, "terrascale-orchestrator-linux-"+runtime.GOARCH), data, 0o755))
	endpoint := strings.TrimSuffix(client.Transport.(providerTransport).url, "/binary") + "/token?"
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", endpoint))
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "lane"))
	var output bytes.Buffer
	err = releasepush.Push(ctx, []string{"--sha", release.SHA, "--dir", assets, "--regions", filepath.Join(work, "unconfirmed-regions.json")}, &output)
	require(err != nil && strings.Contains(err.Error(), "unconfirmed"), "release must fail when rollback is unavailable: "+output.String())
	var result releasepush.Result
	must(json.Unmarshal(bytes.TrimSpace(output.Bytes()), &result))
	require(result.State == "unconfirmed", "rollout must report unconfirmed candidate")
}

func fenceCase(ctx context.Context, data []byte) {
	work, cleanup := temporary("fence-preflight-")
	defer cleanup()
	h, original, candidate := preparedHost(work)
	conn, closeListener := listener(h)
	defer closeListener()
	trialPath := h.TrialFile
	h.TrialFile = filepath.Join(work, "blocked-trial")
	must(os.Mkdir(h.TrialFile, 0o700))
	reply := installRequest(ctx, h, conn, work, strings.Repeat("b", 40), "100")
	require(reply.State == "rejected" && active(h.RunIDFile, original)["run_id"] == "1", "abandoned high run must not advance installed fence")
	h.TrialFile = trialPath
	reply = installRequest(ctx, h, conn, work, strings.Repeat("b", 40), "2")
	require(reply.State == "installed" && active(h.RunIDFile, candidate)["run_id"] == "2", "lower run than abandoned attempt must install above installed fence")
	must(os.WriteFile(filepath.Join(work, "asset"), stamped(data, strings.Repeat("c", 40), "pass"), 0o755))
	reply = installRequest(ctx, h, conn, work, strings.Repeat("c", 40), "2")
	require(reply.State == "stale", "replayed installed run must be refused")
	reply = installRequest(ctx, h, conn, work, strings.Repeat("c", 40), "1")
	require(reply.State == "stale", "older installed run must be refused")
	fmt.Println("ok fence: abandoned run 100; run 2 installed; equal/older runs refused")
}

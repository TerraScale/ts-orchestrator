package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/TerraScale/ts-orchestrator/internal/secretpreflight"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
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
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func require(ok bool, message string) {
	if !ok {
		panic(message)
	}
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func write(path, value string) {
	must(os.MkdirAll(filepath.Dir(path), 0o750))
	must(os.WriteFile(path, []byte(value), 0o640))
}

func stop(cmd *exec.Cmd) {
	_ = cmd.Process.Kill()
	_ = cmd.Wait()
}

func ready(cmd *exec.Cmd, marker string) {
	pipe, err := cmd.StdoutPipe()
	must(err)
	cmd.Stderr = cmd.Stdout
	must(cmd.Start())
	scanner := bufio.NewScanner(pipe)
	last := ""
	for scanner.Scan() {
		last = scanner.Text()
		if strings.Contains(scanner.Text(), marker) {
			go io.Copy(io.Discard, pipe)
			return
		}
	}
	panic("process did not announce " + marker + ": " + last)
}

type providerTransport struct{ url string }

func (p providerTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	local, err := http.NewRequestWithContext(request.Context(), request.Method, p.url, nil)
	if err != nil {
		return nil, err
	}
	clone.URL, clone.Host = local.URL, local.Host
	return http.DefaultTransport.RoundTrip(clone)
}

func signedRelease(ctx context.Context, binary, sha, run, attempt string) (releasepush.OrchRelease, *releasepush.Verifier, *http.Client, func()) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	data, err := os.ReadFile(binary)
	must(err)
	sum := sha256.Sum256(data)
	issuedToken := ""
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			json.NewEncoder(w).Encode(map[string]string{"value": issuedToken})
			return
		}
		if r.URL.Path == "/jwks" {
			must(json.NewEncoder(w).Encode(map[string]any{"keys": []any{map[string]string{
				"kty": "RSA", "kid": "e2e", "alg": "RS256", "use": "sig",
				"n": base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
				"e": base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
			}}}))
			return
		}
		_, _ = w.Write(data)
	}))
	claims, err := json.Marshal(map[string]any{
		"iss": "https://token.actions.githubusercontent.com", "aud": "ts-orch", "exp": time.Now().Add(time.Hour).Unix(),
		"repository": "TerraScale/ts-orchestrator", "repository_owner": "TerraScale", "ref": "refs/heads/main",
		"sha": sha, "run_id": run, "run_attempt": attempt, "event_name": "push", "workflow_ref": "TerraScale/ts-orchestrator/.github/workflows/ci.yml@refs/heads/main",
	})
	must(err)
	unsigned := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"RS256","kid":"e2e"}`)) + "." + base64.RawURLEncoding.EncodeToString(claims)
	digest := sha256.Sum256([]byte(unsigned))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	must(err)
	issuedToken = unsigned + "." + base64.RawURLEncoding.EncodeToString(signature)
	release := releasepush.OrchRelease{SHA: sha, Token: unsigned + "." + base64.RawURLEncoding.EncodeToString(signature), Binaries: map[string]releasepush.Binary{
		runtime.GOARCH: {URL: releasepush.ReleaseURL(sha, run, runtime.GOARCH), SHA256: hex.EncodeToString(sum[:])},
	}}
	verifier := releasepush.NewVerifier()
	verifier.JWKSURL = provider.URL + "/jwks"
	_, err = verifier.Verify(ctx, release.Token)
	must(err)
	return release, verifier, &http.Client{Transport: providerTransport{provider.URL + "/binary"}}, provider.Close
}

func request(ctx context.Context, conn *nats.Conn, subject string, payload []byte) releasepush.Reply {
	message, err := conn.RequestWithContext(ctx, subject, payload)
	must(err)
	var reply releasepush.Reply
	must(json.Unmarshal(message.Data, &reply))
	return reply
}

func run(ctx context.Context, binary string) {
	must(exec.CommandContext(ctx, binary, "release", "preflight").Run())
	work, err := os.MkdirTemp("", "updater-preflight-")
	must(err)
	defer os.RemoveAll(work)
	must(os.MkdirAll(filepath.Join(work, "nats"), 0o700))
	helper, err := os.Executable()
	must(err)
	helperBytes, err := os.ReadFile(helper)
	must(err)
	installed := filepath.Join(work, "ts-orch")
	original := append(append([]byte{}, helperBytes...), []byte("\nCANDIDATE:original")...)
	must(os.WriteFile(installed, original, 0o755))
	process := exec.CommandContext(ctx, installed, "hold")
	ready(process, "holding")
	defer stop(process)
	pid := process.Process.Pid
	unit := filepath.Join(work, "ts-orch.service")
	write(unit, "[Service]\nExecStart="+installed+"\n")
	unitBytes, err := os.ReadFile(unit)
	must(err)
	prev, trial := installed+".prev", filepath.Join(work, "nats/release-trial")
	write(prev, "previous sentinel")
	write(trial, "trial sentinel")
	meshServer, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: mesh.LocalPort, ServerName: "gru.preflight", NoSigs: true, NoLog: true})
	must(err)
	go meshServer.Start()
	require(meshServer.ReadyForConnections(5*time.Second), "mesh must listen")
	defer meshServer.Shutdown()
	conn, err := nats.Connect(meshServer.ClientURL())
	must(err)
	defer conn.Close()
	must(os.MkdirAll(filepath.Join(work, "mesh"), 0o700))
	write(filepath.Join(work, "mesh/client.token"), "lane")
	write(filepath.Join(work, "nats/release-attempt.json"), "{")
	h, err := releasepush.NewHandler(work)
	must(err)
	h.Binary, h.Revision = installed, strings.Repeat("a", 40)
	must(h.Serve(conn))
	for i, content := range []string{"", "{"} {
		write(filepath.Join(work, "nats/release-attempt.json"), content)
		write(filepath.Join(work, "nats/release-trial"), content)
		write(filepath.Join(work, "nats/release-rolled-back"), content)
		probation, err := releasepush.Probe(work, io.Discard)
		must(err)
		require(probation == nil, "corrupt trial must permit startup")

		damaged, err := releasepush.NewHandler(work)
		must(err)
		damaged.Binary, damaged.Revision = installed, h.Revision
		candidate := filepath.Join(work, fmt.Sprintf("damaged-%d", i))
		must(os.WriteFile(candidate, append(append([]byte{}, helperBytes...), []byte("\nCANDIDATE:refuse")...), 0o755))
		release, verifier, client, closeProvider := signedRelease(ctx, candidate, strings.Repeat("b", 40), "1", "1")
		damaged.Verifier, damaged.Client = verifier, client
		subject := fmt.Sprintf("lane.damaged.%d", i)
		must(damaged.ServeWorker(conn, subject, "damaged"))
		payload, err := json.Marshal(release)
		must(err)
		reply := request(ctx, conn, subject, payload)
		require(reply.State == "rejected" && reply.Refusal != nil, "corrupt record must not block startup or next refusal")
		record, err := os.ReadFile(damaged.RefusalFile)
		must(err)
		require(json.Valid(record), "next refusal atomically replaces corrupt record")
		closeProvider()
	}
	fmt.Println("ok records: empty and truncated records permit startup and next refusal")

	must(h.ServeHostVersion(conn, "gru", "node-one"))
	must(regionhealth.Serve(conn, func() regionhealth.Report {
		hosts := releasepush.ReadHostVersions(ctx, conn, "gru", []*api.Node{{ID: "node-one", Description: &api.NodeDescription{Hostname: "lane-host"}}})
		return regionhealth.Report{State: regionhealth.StateOK, Hosts: hosts}
	}))
	options, err := releasepush.Options(work, nil)
	must(err)
	options.Host, options.Port, options.CustomClientAuthentication = "127.0.0.1", -1, nil
	tlsServer, err := server.NewServer(options)
	must(err)
	go tlsServer.Start()
	require(tlsServer.ReadyForConnections(5*time.Second), "release listener must listen")
	defer tlsServer.Shutdown()
	certificate, err := x509.ParseCertificate(options.TLSConfig.Certificates[0].Certificate[0])
	must(err)
	pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	regions := filepath.Join(work, "regions.json")
	regionBytes, err := json.Marshal([]releasepush.Region{{Region: "gru", NATS: tlsServer.ClientURL(), SPKISHA256: hex.EncodeToString(pin[:])}})
	must(err)
	must(os.WriteFile(regions, regionBytes, 0o600))
	var lastRelease releasepush.OrchRelease
	for i, mode := range []string{"refuse", "noise", "cannot-execute", "hang", "pass"} {
		candidate := filepath.Join(work, fmt.Sprintf("candidate-%d", i))
		candidateBytes := append(append([]byte{}, helperBytes...), []byte("\nCANDIDATE:"+mode)...)
		if mode == "cannot-execute" {
			candidateBytes = []byte("invalid executable")
		}
		must(os.WriteFile(candidate, candidateBytes, 0o755))
		sha := strings.Repeat(fmt.Sprintf("%x", i+11), 40)
		release, verifier, client, closeProvider := signedRelease(ctx, candidate, sha, fmt.Sprint(i+1), "1")
		h.Verifier, h.Client = verifier, client
		payload, err := json.Marshal(release)
		must(err)
		before, err := os.ReadFile(installed)
		must(err)
		beforePrev, err := os.ReadFile(prev)
		must(err)
		beforeTrial, err := os.ReadFile(trial)
		must(err)
		start := time.Now()
		var reply releasepush.Reply
		if mode == "pass" {
			reply = request(ctx, conn, releasepush.SubjectOrch, payload)
		} else {
			tlsConn, err := releasepush.Dial(releasepush.Region{NATS: tlsServer.ClientURL(), SPKISHA256: hex.EncodeToString(pin[:])}, release.Token)
			must(err)
			must(h.Serve(tlsConn))
			endpoint := strings.TrimSuffix(client.Transport.(providerTransport).url, "/binary") + "/token?"
			must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", endpoint))
			must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "lane"))
			dir := filepath.Join(work, fmt.Sprintf("assets-%d", i))
			must(os.Mkdir(dir, 0o700))
			must(os.Link(candidate, filepath.Join(dir, "terrascale-orchestrator-linux-"+runtime.GOARCH)))
			var output bytes.Buffer
			err = releasepush.Push(ctx, []string{"--sha", sha, "--dir", dir, "--regions", regions}, &output)
			require(err != nil, "release run must fail on refusal")
			var result releasepush.Result
			must(json.Unmarshal(bytes.TrimSpace(output.Bytes()), &result))
			status := request(ctx, conn, releasepush.SubjectVersion, nil)
			reply = releasepush.Reply{State: result.State, Error: result.Error, Refusal: status.Refusal}
			if len(result.Refusals) != 0 {
				reply.Error = result.Refusals[0].Refusal.Reason
			}
			tlsConn.Close()
		}
		elapsed := time.Since(start)
		closeProvider()
		lastRelease = release
		if mode == "pass" {
			require(reply.State == "installed" && reply.Refusal == nil, "passing preflight installs and clears refusal")
			current, err := os.ReadFile(installed)
			must(err)
			require(bytes.Equal(current, candidateBytes), "passing candidate bytes must install")
			restored, err := releasepush.NewHandler(work)
			must(err)
			require(restored != nil, "successful attempt record must survive restart")
		} else {
			require(strings.HasPrefix(reply.State, "refused on ") && reply.Refusal != nil, "preflight must refuse")
			message := "candidate refuses this release"
			if mode == "noise" {
				message = "[truncated]"
				require(len(reply.Refusal.Reason) <= secretpreflight.MaxOutputBytes && utf8.ValidString(reply.Refusal.Reason), "noisy record must be capped valid UTF-8")
				require(!strings.ContainsFunc(reply.Refusal.Reason, unicode.IsControl), "noisy record must contain no control characters")
			}
			if mode == "cannot-execute" {
				message = "exec format error"
			}
			if mode == "hang" {
				message = "signal: killed"
				require(elapsed >= 70*time.Second && elapsed < 75*time.Second, "hung preflight must be cut at the 70-second bound")
			}
			require(strings.Contains(reply.Error, message), "release output must include candidate failure")
			require(reply.Refusal.SHA == sha && reply.Refusal.RunID == fmt.Sprint(i+1) && reply.Refusal.RunAttempt == "1", "refusal must identify candidate and attempt")
			current, err := os.ReadFile(installed)
			must(err)
			require(bytes.Equal(current, before), "refusal changes no installed bytes")
			current, err = os.ReadFile(prev)
			must(err)
			require(bytes.Equal(current, beforePrev), "refusal changes no previous binary")
			current, err = os.ReadFile(trial)
			must(err)
			require(bytes.Equal(current, beforeTrial), "refusal changes no trial record")
			current, err = os.ReadFile(unit)
			must(err)
			require(bytes.Equal(current, unitBytes), "refusal changes no unit")
			require(process.Process.Pid == pid && process.Process.Signal(syscall.Signal(0)) == nil, "refusal must preserve the running pid")
			_, err = os.Stat(installed + ".next")
			require(errors.Is(err, os.ErrNotExist), "refusal removes staged candidate")
			status := request(ctx, conn, releasepush.SubjectVersion, nil)
			require(status.Refusal != nil && status.Refusal.SHA == sha && strings.Contains(status.Refusal.Reason, message), "version reply must show current refusal")
			reloaded, err := releasepush.NewHandler(work)
			must(err)
			probe, err := nats.Connect(meshServer.ClientURL())
			must(err)
			must(reloaded.ServeHostVersion(probe, "gru", "reloaded"))
			status = request(ctx, conn, releasepush.SubjectVersion+".gru.reloaded", nil)
			require(status.Refusal != nil && status.Refusal.SHA == sha, "refusal survives handler restart")
			probe.Close()
			var output bytes.Buffer
			_ = regionhealth.RunCLI(ctx, nil, work, &output)
			require(strings.Contains(output.String(), "host lane-host: revision") && strings.Contains(output.String(), sha) && strings.Contains(output.String(), message), "status CLI must display host and refusal")
			fmt.Printf("ok %s: release refused with message; binary, previous binary, trial, unit and pid unchanged; status names candidate and attempt\n", mode)
		}
		if mode == "pass" {
			status := request(ctx, conn, releasepush.SubjectVersion, nil)
			require(status.Refusal == nil, "good release clears old refusal")
			fmt.Println("ok pass: candidate installed; refusal cleared")
		}
	}
	require(lastRelease.SHA != "", "release sequence completed")
	relayLane(ctx, conn)

	fmt.Println("updater-preflight e2e: PASS")
}

func relayLane(ctx context.Context, conn *nats.Conn) {
	workerState, err := os.MkdirTemp("", "worker-preflight-")
	must(err)
	defer os.RemoveAll(workerState)
	must(os.MkdirAll(filepath.Join(workerState, "nats"), 0o700))
	helper, err := os.Executable()
	must(err)
	helperBytes, err := os.ReadFile(helper)
	must(err)
	candidate := filepath.Join(workerState, "candidate")
	must(os.WriteFile(candidate, append(helperBytes, []byte("\nCANDIDATE:refuse")...), 0o755))
	sha := strings.Repeat("e", 40)
	_, verifier, client, closeProvider := signedRelease(ctx, candidate, sha, "100", "1")
	defer closeProvider()
	worker, err := releasepush.NewHandler(workerState)
	must(err)
	worker.Binary, worker.Revision, worker.Verifier, worker.Client = filepath.Join(workerState, "installed"), strings.Repeat("a", 40), verifier, client
	must(os.WriteFile(worker.Binary, helperBytes, 0o755))
	must(worker.ServeWorker(conn, "lane.workers", "worker-one"))
	_, err = conn.Subscribe("lane.no-worker", func(*nats.Msg) {})
	must(err)
	must(conn.Flush())
	nodes := []*api.Node{{ID: "worker-one", Role: api.NodeRoleWorker, Description: &api.NodeDescription{Hostname: "worker-one"}}}
	founder, err := releasepush.NewHandler(workerState)
	must(err)
	founder.Revision, founder.Verifier = sha, verifier
	founder.Health = func(context.Context) error { return nil }
	later, err := releasepush.NewHandler(workerState)
	must(err)
	later.Revision, later.Verifier = sha, verifier
	visited := false
	later.Health = func(context.Context) error { visited = true; return nil }
	regions := []releasepush.Region{}
	for i, handler := range []*releasepush.Handler{founder, later} {
		options, err := releasepush.Options(workerState, nil)
		must(err)
		options.Host, options.Port, options.CustomClientAuthentication = "127.0.0.1", -1, nil
		listener, err := server.NewServer(options)
		must(err)
		go listener.Start()
		require(listener.ReadyForConnections(5*time.Second), "regional listener must listen")
		defer listener.Shutdown()
		tlsConn, err := nats.Connect(listener.ClientURL(), nats.Secure(&tls.Config{InsecureSkipVerify: true}))
		must(err)
		defer tlsConn.Close()
		must(handler.Serve(tlsConn))
		certificate, err := x509.ParseCertificate(options.TLSConfig.Certificates[0].Certificate[0])
		must(err)
		pin := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
		regions = append(regions, releasepush.Region{Region: []string{"sjc", "gru"}[i], NATS: listener.ClientURL(), SPKISHA256: hex.EncodeToString(pin[:])})
	}
	regionBytes, err := json.Marshal(regions)
	must(err)
	regionFile := filepath.Join(workerState, "regions.json")
	must(os.WriteFile(regionFile, regionBytes, 0o600))
	assets := filepath.Join(workerState, "assets")
	must(os.Mkdir(assets, 0o700))
	must(os.Link(candidate, filepath.Join(assets, "terrascale-orchestrator-linux-"+runtime.GOARCH)))
	endpoint := strings.TrimSuffix(client.Transport.(providerTransport).url, "/binary") + "/token?"
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", endpoint))
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "lane"))
	for _, subject := range []string{"lane.workers", "lane.no-worker"} {
		founder.Relay = func(ctx context.Context, payload []byte) []releasepush.HostVersion {
			return releasepush.RelayWorkers(ctx, conn, subject, payload, nodes)
		}
		visited = false
		var output bytes.Buffer
		err := releasepush.Push(ctx, []string{"--sha", sha, "--dir", assets, "--regions", regionFile}, &output)
		scanner := bufio.NewScanner(&output)
		results := []releasepush.Result{}
		for scanner.Scan() {
			var result releasepush.Result
			must(json.Unmarshal(scanner.Bytes(), &result))
			results = append(results, result)
		}
		require(len(results) == 2 && visited && results[1].Error == "", "other region must release before run ends")
		require(len(results[0].Workers) == 1, "run must report worker reply")
		if subject == "lane.workers" {
			row := results[0].Workers[0]
			require(err != nil && results[0].State == "refused on worker-one" && row.Refusal != nil && row.Refusal.SHA == sha, "run must name worker and candidate and fail at end")
			fmt.Println("ok worker refusal: run names worker and candidate, releases later region, fails at end")
		} else {
			require(err == nil && results[0].Workers[0].Error == "no answer" && len(results[0].Refusals) == 0, "silence must be informational")
			fmt.Println("ok worker silence: no answer after 90 seconds; later region released; run succeeds")
		}
	}
	must(os.WriteFile(candidate, append(helperBytes, []byte("\nCANDIDATE:noise")...), 0o755))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	err = secretpreflight.Check(ctx, candidate)
	runtime.ReadMemStats(&after)
	require(err != nil && len(err.Error()) <= secretpreflight.MaxOutputBytes && strings.Contains(err.Error(), "[truncated]"), "10 MiB candidate output must be capped")
	require(after.TotalAlloc-before.TotalAlloc < 1<<20, "draining 10 MiB must allocate less than 1 MiB in updater")
	fmt.Println("ok output: 10 MiB drained with less than 1 MiB allocated; clean capped diagnostic")
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "release" && os.Args[2] == "preflight" {
		path, err := os.Executable()
		must(err)
		data, err := os.ReadFile(path)
		must(err)
		mode := string(data[bytes.LastIndex(data, []byte("\nCANDIDATE:"))+len("\nCANDIDATE:"):])
		switch mode {
		case "refuse":
			fmt.Fprintln(os.Stderr, "candidate refuses this release")
			os.Exit(17)
		case "noise":
			chunk := bytes.Repeat([]byte("abc\x00\x1b\n\xff"), 1024)
			for range (10<<20)/len(chunk) + 1 {
				_, _ = os.Stdout.Write(chunk)
			}
			os.Exit(17)
		case "hang":
			<-time.NewTimer(10 * time.Minute).C
		}
		return
	}
	if len(os.Args) == 2 && os.Args[1] == "hold" {
		fmt.Println("holding")
		<-time.NewTimer(10 * time.Minute).C
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	run(ctx, os.Args[1])
}

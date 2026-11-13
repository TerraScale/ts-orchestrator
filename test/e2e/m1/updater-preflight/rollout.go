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
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func rolloutCases(ctx context.Context) {
	work, cleanup := temporary("rollout-")
	defer cleanup()
	workerHost := newHost(filepath.Join(work, "worker"), false)
	worker := workerHost.handler()
	refusing := stamped(helperBytes(), shaB, "refuse")
	accepted := filepath.Join(work, "accepted")
	writeExecutable(accepted, refusing)
	p := newProvider(refusing)
	defer p.server.Close()
	release := p.release(shaB, "100", "e2e")
	verifier := p.verifier()
	worker.Verifier, worker.Client = verifier, p.client()
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
	founder.Health = func(context.Context) error {
		if broken.Load() {
			return errors.New("candidate health broken")
		}
		return nil
	}
	later.Health = func(context.Context) error {
		if laterBroken.Load() {
			return errors.New("services unreadable")
		}
		return nil
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
	writeExecutable(filepath.Join(assets, "terrascale-orchestrator-linux-"+runtime.GOARCH), refusing)
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", p.server.URL+"/token?"))
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "lane"))
	nodes := []*api.Node{{ID: "worker-one", Role: api.NodeRoleWorker}}
	for _, mode := range []string{"worker-integrity", "first-integrity", "unknown-kind", "absent-kind", "host-refusal", "all-preflight", "refusal-silence", "unhealthy-refusal", "unhealthy-fleet", "repair-unhealthy-fleet"} {
		visited.Store(false)
		broken.Store(strings.HasSuffix(mode, "unhealthy-fleet"))
		laterBroken.Store(strings.HasSuffix(mode, "unhealthy-fleet"))
		worker.Client = p.client()
		founder.Revision = release.SHA
		founder.Client = p.client()
		if mode == "worker-integrity" {
			worker.Client = &http.Client{Transport: corruptTransport{p.client().Transport}}
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
			founder.Revision = shaA
			if mode == "first-integrity" {
				founder.Client = &http.Client{Transport: corruptTransport{p.client().Transport}}
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
		printed := output.String()
		results, skipped := []releasepush.Result{}, []releasepush.Result{}
		scanner := bufio.NewScanner(&output)
		for scanner.Scan() {
			var result releasepush.Result
			must(json.Unmarshal(scanner.Bytes(), &result))
			if result.State == "repair_skipped_health" {
				require(len(results) == 0, "skipped hosts must be printed before any region is pushed: "+printed)
				skipped = append(skipped, result)
				continue
			}
			results = append(results, result)
		}
		require(len(results) == 2, fmt.Sprintf("both regional outcomes must be reported: %s", printed))
		require((len(skipped) == 2) == (mode == "repair-unhealthy-fleet"), "only a repair push skips the initial health check: "+printed)
		if mode == "unhealthy-fleet" {
			require(results[0].State == "failed" && strings.Contains(results[0].Error, "candidate health broken") && results[0].ConnectMS == 0, "an ordinary push refuses a fleet whose first host reports a health error: "+printed)
		}
		if mode == "repair-unhealthy-fleet" {
			require(skipped[0].Region == "sjc" && skipped[0].Health == `"candidate health broken"` && skipped[1].Region == "gru" && skipped[1].Health == `"services unreadable"`, "each skipped host is printed with its health: "+printed)
			require(results[0].State == "current" && results[0].Repair == `"candidate health broken"` && strings.Contains(results[0].Error, "health of") && results[0].Health == "candidate health broken", "a repair push reaches the unhealthy first host and still waits for its health: "+printed)
		}
		fatal := mode != "host-refusal" && mode != "refusal-silence"
		if fatal {
			require(err != nil && !visited.Load() && results[1].State == "skipped", "fatal refusal must stop later regions: "+mode+": "+printed)
			if mode == "all-preflight" {
				require(strings.Contains(results[0].Error, "every host in the first region"), "uniform preflight must explain rollout stop")
			}
			if mode == "unhealthy-refusal" {
				require(results[0].Health == "candidate health broken" && strings.Contains(results[0].Error, "health of") && strings.HasPrefix(results[0].State, "refused on"), "an accepted first host with broken health must stop the rollout despite a refusing worker: "+printed)
			}
		} else {
			require(visited.Load() && results[1].Error == "" && err != nil, "a host refusal fails at the end and allows the next region: "+mode+": "+printed)
			if mode == "host-refusal" {
				require(results[0].Health == "ok" && results[0].HealthyMS > 0, "an accepted first host is health-checked even when a worker refuses")
			}
			if mode == "refusal-silence" {
				require(!strings.Contains(results[0].Error, "every host") && len(results[0].Workers) == 1 && results[0].Workers[0].Error == "no answer" && results[0].Workers[0].Refusal == nil, "a silent worker is not a refusal: "+printed)
			}
		}
		fmt.Println("ok rollout", mode, ": regional outcomes verified")
	}
}

func rebuildCase(ctx context.Context) {
	work, cleanup := temporary("rebuild-")
	defer cleanup()
	must(os.Mkdir(filepath.Join(work, "nats"), 0o700))
	data := helperBytes()
	installed := filepath.Join(work, "installed")
	first := stamped(data, shaB, "original")
	writeExecutable(installed, first)
	port := freePort()
	regions := regionFile(work, "regions.json", fmt.Sprintf("nats://127.0.0.1:%d", port))
	push := func(mode, run string) (releasepush.Result, []byte, error) {
		build := stamped(data, shaB, mode)
		p := newProvider(build)
		defer p.server.Close()
		p.release(shaB, run, "e2e")
		stopRegion := keepServing(ctx, func() *exec.Cmd {
			return exec.CommandContext(ctx, installed, "serve-region", work, fmt.Sprint(port), p.server.URL+"/jwks", p.server.URL+"/binary")
		})
		defer stopRegion()
		result, err := pushOne(ctx, work, "assets-"+mode, build, shaB, p, regions)
		return result, build, err
	}
	crashed, _, err := push("crash", "10")
	require(err != nil && crashed.State == "rolled_back" && bytes.Equal(read(installed), first), fmt.Sprintf("a rebuild of the same commit that rolls back to the first build is not serving: %v %+v", err, crashed))
	fmt.Println("ok probation crash loop: a crash-looping candidate is rolled back to the exact previous bytes by main's probation")
	rebuilt, build, err := push("pass", "11")
	require(err == nil && rebuilt.State == "installed" && rebuilt.Health == "ok" && rebuilt.RevisionOnly == "" && bytes.Equal(read(installed), build), fmt.Sprintf("another build of the installed commit installs and serves: %v %+v", err, rebuilt))
	fmt.Println("ok rebuild: same commit, other digest installs; its rollback to the first build is reported rolled_back, not serving")
}

func oldHostCase(ctx context.Context) {
	work, cleanup := temporary("old-host-")
	defer cleanup()
	must(os.Mkdir(filepath.Join(work, "nats"), 0o700))
	build := stamped(helperBytes(), shaB, "pass")
	p := newProvider(build)
	defer p.server.Close()
	p.release(shaB, "5", "e2e")
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
	result, err := pushOne(ctx, work, "assets", build, shaB, p, regionFile(work, "regions.json", srv.ClientURL()))
	require(err == nil && result.State == "current" && result.Health == "ok" && strings.Contains(result.RevisionOnly, "revision only"), fmt.Sprintf("a host without a digest in its version answer is confirmed by revision and says so: %v %+v", err, result))
	fmt.Println("ok old host: no digest in the version answer; serving confirmed by revision only and reported")
}

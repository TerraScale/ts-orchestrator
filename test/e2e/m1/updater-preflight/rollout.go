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
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func rolloutCases(ctx context.Context) {
	work, cleanup := temporary("rollout-")
	defer cleanup()
	refusing := stamped(helperBytes(), shaB, "refuse")
	accepted := filepath.Join(work, "accepted")
	writeExecutable(accepted, refusing)
	p := newProvider(refusing)
	defer p.server.Close()
	release := p.release(shaB, "100", "e2e")
	verifier := p.verifier()
	founder, err := releasepush.NewHandler(ctx, work)
	must(err)
	later, err := releasepush.NewHandler(ctx, work)
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
	later.Health = func(context.Context) error {
		if broken.Load() {
			return errors.New("services unreadable")
		}
		return nil
	}
	var visited atomic.Bool
	later.Relay = func([]byte, nats.Header) { visited.Store(true) }
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
	for _, mode := range []string{"first-integrity", "host-refusal", "unhealthy-fleet", "repair-unhealthy-fleet"} {
		visited.Store(false)
		broken.Store(strings.HasSuffix(mode, "unhealthy-fleet"))
		founder.Revision, founder.Client = release.SHA, p.client()
		if mode == "first-integrity" || mode == "host-refusal" {
			founder.Revision = shaA
		}
		if mode == "first-integrity" {
			founder.Client = &http.Client{Transport: corruptTransport{p.client().Transport}}
		}
		var output bytes.Buffer
		pushCtx, cancelPush := context.WithCancel(ctx)
		args := []string{"--sha", release.SHA, "--dir", assets, "--regions", filepath.Join(work, "regions.json")}
		if mode == "repair-unhealthy-fleet" {
			pushCtx, cancelPush = context.WithTimeout(ctx, 20*time.Second)
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
		require(err != nil && !visited.Load() && results[1].State == "skipped", "a failed first region stops the later regions, as on main: "+mode+": "+printed)
		switch mode {
		case "first-integrity":
			refusal := results[0].Refusal
			require(results[0].State == "rejected" && refusal != nil && refusal.Kind == releasepush.RefusalIntegrity && results[0].Preflight == "preflight declared: yes, executed: no", "a digest mismatch is reported as release_integrity: "+printed)
		case "host-refusal":
			refusal := results[0].Refusal
			require(results[0].State == "rejected" && refusal != nil && refusal.Kind == releasepush.RefusalHost && results[0].Preflight == "preflight declared: yes, executed: yes" && strings.Contains(refusal.Reason, "candidate refuses"), "a preflight refusal is reported as host_prerequisite with its diagnostic: "+printed)
		case "unhealthy-fleet":
			require(results[0].State == "failed" && strings.Contains(results[0].Error, "candidate health broken") && results[0].ConnectMS == 0, "an ordinary push refuses a fleet whose first host reports a health error: "+printed)
		case "repair-unhealthy-fleet":
			require(skipped[0].Region == "sjc" && skipped[0].Health == `"candidate health broken"` && skipped[1].Region == "gru" && skipped[1].Health == `"services unreadable"`, "each skipped host is printed with its health: "+printed)
			require(results[0].State == "current" && results[0].Repair == `"candidate health broken"` && strings.Contains(results[0].Error, "health of") && results[0].Health == "candidate health broken", "a repair push reaches the unhealthy first host and still waits for its health: "+printed)
		}
		fmt.Println("ok rollout", mode, ": regional outcome verified")
	}
}

func relayCase(ctx context.Context) {
	work, cleanup := temporary("relay-")
	defer cleanup()
	mark := filepath.Join(work, "preflight-ran")
	asset := stamped(helperBytes(), shaB, "mark:"+mark)
	p := newProvider(asset)
	defer p.server.Close()
	founderHost, workerHost := newHost(filepath.Join(work, "founder"), false), newHost(filepath.Join(work, "worker"), false)
	founder, worker := founderHost.handler(), workerHost.handler()
	founder.Verifier, founder.Client = p.verifier(), p.client()
	worker.Verifier, worker.Client = p.verifier(), p.client()
	conn, closeListener := listener(founder)
	defer closeListener()
	must(worker.ServeWorker(conn, "lane.workers"))
	founder.Relay = func(request []byte, header nats.Header) {
		must(errors.Join(conn.PublishMsg(&nats.Msg{Subject: "lane.workers", Data: request, Header: header}), conn.Flush()))
	}
	reply := send(ctx, conn, p.release(shaB, "2", "e2e"), p.declaration())
	select {
	case <-worker.Installed:
	case <-ctx.Done():
		panic("the worker never installed the relayed release")
	}
	require(reply.State == "installed" && len(marks(mark)) == 2 && bytes.Equal(read(founderHost.binary), asset) && bytes.Equal(read(workerHost.binary), asset), fmt.Sprintf("the relayed request keeps its declaration, so the worker runs the preflight too: %+v, %d preflights", reply, len(marks(mark))))
	fmt.Println("ok relay: the founder relays the request with its declaration as it receives it; the worker runs the preflight and installs")
}

func regionHost(work string, installedBytes []byte) (string, string, string) {
	must(os.Mkdir(filepath.Join(work, "nats"), 0o700))
	installed := filepath.Join(work, "installed")
	writeExecutable(installed, installedBytes)
	port := freePort()
	regions := regionFile(work, "regions.json", fmt.Sprintf("nats://127.0.0.1:%d", port))
	return installed, regions, fmt.Sprint(port)
}

func serveFrom(ctx context.Context, work, installed, port string, p *provider) (func(), string) {
	return keepServing(ctx, func() *exec.Cmd {
		return exec.CommandContext(ctx, installed, "serve-region", work, port, p.server.URL+"/jwks", p.server.URL+"/binary")
	})
}

func rebuildCase(ctx context.Context) {
	work, cleanup := temporary("rebuild-")
	defer cleanup()
	data := helperBytes()
	first := stamped(data, shaB, "original")
	installed, regions, port := regionHost(work, first)
	push := func(sha, mode, run string) (releasepush.Result, error) {
		build := stamped(data, sha, mode)
		p := newProvider(build)
		defer p.server.Close()
		p.release(sha, run, "e2e")
		stopRegion, _ := serveFrom(ctx, work, installed, port, p)
		defer stopRegion()
		return pushOne(ctx, work, "assets-"+mode, build, sha, p, regions)
	}
	rebuilt, err := push(shaB, "pass", "10")
	require(err == nil && rebuilt.State == "current" && rebuilt.Health == "ok" && strings.Contains(rebuilt.RevisionOnly, "another build") && bytes.Equal(read(installed), first) && read(installed+".next") == nil && read(installed+".prev") == nil && read(filepath.Join(work, "nats/release-trial")) == nil, fmt.Sprintf("another build of the running commit is current and installs nothing: %v %+v", err, rebuilt))
	fmt.Println("ok rebuild: another build of the running commit is answered current and installs nothing, as on main; serving is confirmed by revision only")
	crashed, err := push(shaC, "crash", "11")
	require(err != nil && crashed.State == "rolled_back" && bytes.Equal(read(installed), first), fmt.Sprintf("a crash-looping candidate is rolled back: %v %+v", err, crashed))
	fmt.Println("ok probation crash loop: a crash-looping candidate is rolled back to the exact previous bytes by main's probation")
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
	require(err == nil && result.State == "current" && result.Health == "ok" && strings.Contains(result.RevisionOnly, "no binary digest") && result.Preflight == "not reported: the host's updater runs no preflight", fmt.Sprintf("a host without a digest in its version answer is confirmed by revision and says so: %v %+v", err, result))
	fmt.Println("ok old host: no digest in the version answer; serving confirmed by revision only and reported; pusher prints", result.Preflight)
}

func unreadableCase(ctx context.Context) {
	work, cleanup := temporary("unreadable-")
	defer cleanup()
	build := stamped(helperBytes(), shaB, "original")
	installed, regions, port := regionHost(work, build)
	must(os.Chmod(installed, 0o111))
	p := newProvider(build)
	defer p.server.Close()
	p.release(shaB, "6", "e2e")
	stopRegion, version := serveFrom(ctx, work, installed, port, p)
	defer stopRegion()
	var answer releasepush.Reply
	must(json.Unmarshal([]byte(version), &answer))
	require(answer.Version == shaB && answer.SHA256 == "" && strings.Contains(answer.SHA256Unavailable, "permission denied"), "an agent that cannot read its own executable starts, serves and says its digest is unavailable: "+version)
	result, err := pushOne(ctx, work, "assets", build, shaB, p, regions)
	require(err == nil && result.State == "current" && result.Health == "ok" && strings.Contains(result.RevisionOnly, "no binary digest"), fmt.Sprintf("the pusher confirms such a host by revision only: %v %+v", err, result))
	fmt.Println("ok unreadable executable: the agent starts and serves, its version answer says", answer.SHA256Unavailable, "; the pusher reports revision_only")
}

func slowCase(ctx context.Context) {
	work, cleanup := temporary("slow-this-pusher-")
	defer cleanup()
	mark := filepath.Join(work, "preflight-ran")
	build := stamped(helperBytes(), shaB, "slow:"+mark)
	installed, regions, port := regionHost(work, stamped(helperBytes(), shaA, "original"))
	p := newProvider(build)
	defer p.server.Close()
	p.release(shaB, "30", "e2e")
	stopRegion, _ := serveFrom(ctx, work, installed, port, p)
	defer stopRegion()
	result, err := pushOne(ctx, work, "assets", build, shaB, p, regions)
	accepted, serving := time.Duration(result.AcceptedMS)*time.Millisecond, time.Duration(result.ServingMS)*time.Millisecond
	require(err == nil && result.State == "installed" && result.Health == "ok" && result.RevisionOnly == "" && result.Preflight == "preflight declared: yes, executed: yes" && len(marks(mark)) == 1 && bytes.Equal(read(installed), build), fmt.Sprintf("a declared candidate with a 40-second preflight that needs 40 seconds to start is installed and served, not rolled back: %v %+v", err, result))
	require(accepted >= slowStep && accepted < 2*time.Minute && serving-accepted >= slowStep, fmt.Sprintf("the reply follows the preflight inside the pusher's 2-minute request timeout, and serving follows the slow start: accepted %s, serving %s", accepted, serving))
	fmt.Println("ok slow candidate, this pusher: preflight 40 s, start 40 s behind a silent worker; accepted after", accepted, "serving after", serving, "health ok, not rolled back; pusher prints", result.Preflight)
}

func mainPusherCase(ctx context.Context, previous string) {
	work, cleanup := temporary("slow-main-pusher-")
	defer cleanup()
	mark := filepath.Join(work, "preflight-ran")
	build := stamped(helperBytes(), shaB, "slow:"+mark)
	installed, regions, port := regionHost(work, stamped(helperBytes(), shaA, "original"))
	p := newProvider(build)
	defer p.server.Close()
	p.release(shaB, "31", "e2e")
	stopRegion, _ := serveFrom(ctx, work, installed, port, p)
	defer stopRegion()
	assets := filepath.Join(work, "assets")
	must(os.Mkdir(assets, 0o700))
	writeExecutable(filepath.Join(assets, "terrascale-orchestrator-linux-"+runtime.GOARCH), build)
	command := exec.CommandContext(ctx, previous, "push", "--sha", shaB, "--dir", assets, "--regions", regions)
	command.Env = append(os.Environ(), "ACTIONS_ID_TOKEN_REQUEST_URL="+p.server.URL+"/token?", "ACTIONS_ID_TOKEN_REQUEST_TOKEN=lane")
	output, err := command.CombinedOutput()
	lines := strings.Split(strings.TrimSpace(string(output)), "\n")
	var result releasepush.Result
	require(err == nil && json.Unmarshal([]byte(lines[len(lines)-1]), &result) == nil, fmt.Sprintf("main's pusher must succeed against this founder: %v: %s", err, output))
	accepted, serving := time.Duration(result.AcceptedMS)*time.Millisecond, time.Duration(result.ServingMS)*time.Millisecond
	require(result.State == "installed" && result.Health == "ok" && read(mark) == nil && bytes.Equal(read(installed), build), fmt.Sprintf("main's pusher sends no declaration: no preflight runs and the candidate is installed and served: %s", output))
	require(accepted < 10*time.Second && serving >= slowStep, fmt.Sprintf("main's pusher is answered without a preflight, well inside its 2-minute request timeout: accepted %s, serving %s", accepted, serving))
	fmt.Println("ok main's pusher: no declaration, no preflight; accepted after", accepted, "serving after", serving, "behind a 40-second start")
}

func strippedCase(ctx context.Context) {
	work, cleanup := temporary("stripped-")
	defer cleanup()
	mark := filepath.Join(work, "preflight-ran")
	build := stamped(helperBytes(), shaB, "mark:"+mark)
	installed, _, port := regionHost(work, stamped(helperBytes(), shaA, "original"))
	p := newProvider(build)
	defer p.server.Close()
	p.release(shaB, "32", "e2e")
	stopRegion, _ := serveFrom(ctx, work, installed, port, p)
	defer stopRegion()
	channel := filepath.Join(work, "channel")
	must(os.MkdirAll(filepath.Join(channel, "nats"), 0o700))
	options, err := releasepush.Options(channel, nil)
	must(err)
	options.Host, options.Port, options.CustomClientAuthentication = "127.0.0.1", -1, nil
	srv, err := server.NewServer(options)
	must(err)
	go srv.Start()
	require(srv.ReadyForConnections(5*time.Second), "the stripping channel must listen")
	defer srv.Shutdown()
	outer, err := nats.Connect(srv.ClientURL(), nats.Secure(&tls.Config{InsecureSkipVerify: true}))
	must(err)
	defer outer.Close()
	inner, err := nats.Connect("nats://127.0.0.1:"+port, nats.Secure(&tls.Config{InsecureSkipVerify: true}), nats.MaxReconnects(-1), nats.ReconnectWait(100*time.Millisecond))
	must(err)
	defer inner.Close()
	var stripped atomic.Bool
	for _, subject := range []string{releasepush.SubjectVersion, releasepush.SubjectHealth, releasepush.SubjectOrch} {
		_, err := outer.Subscribe(subject, func(m *nats.Msg) {
			go func() {
				if m.Header.Get(releasepush.PreflightHeader) != "" {
					stripped.Store(true)
				}
				forwardCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
				defer cancel()
				if answer, err := inner.RequestMsgWithContext(forwardCtx, &nats.Msg{Subject: m.Subject, Data: m.Data}); err == nil {
					_ = m.Respond(answer.Data)
				}
			}()
		})
		must(err)
	}
	must(outer.Flush())
	result, err := pushOne(ctx, work, "assets", build, shaB, p, regionFile(channel, "regions.json", srv.ClientURL()))
	require(err == nil && stripped.Load() && result.State == "installed" && result.Health == "ok" && bytes.Equal(read(installed), build), fmt.Sprintf("a release whose declaration was stripped on the way installs as an undeclared one: %v %+v", err, result))
	require(read(mark) == nil && result.Preflight == "preflight declared: no, executed: no; this pusher sent a declaration the host did not receive", fmt.Sprintf("no preflight runs and the pusher prints that its declaration did not arrive: %+v", result))
	fmt.Println("ok stripped declaration: installed without a preflight; pusher prints", result.Preflight)
}

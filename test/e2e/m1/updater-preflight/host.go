package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

type host struct {
	work, binary string
	original     []byte
}

func newHost(work string, probation bool) host {
	must(os.MkdirAll(filepath.Join(work, "nats"), 0o700))
	h := host{work: work, binary: filepath.Join(work, "installed"), original: stamped(helperBytes(), shaA, "original")}
	writeExecutable(h.binary, h.original)
	write(h.binary+".prev", "superseded")
	write(filepath.Join(work, "nats/release-run-id"), "1")
	write(filepath.Join(work, "nats/release-rolled-back"), `{"sha":"`+shaC+`","run_id":"0","reason":"earlier rollback"}`)
	if probation {
		write(filepath.Join(work, "nats/release-trial"), `{"sha":"`+shaA+`","run_id":"1","installed":"`+time.Now().UTC().Format(time.RFC3339Nano)+`","starts":1}`)
	}
	return h
}

func (h host) handler() *releasepush.Handler {
	handler, err := releasepush.NewHandler(context.Background(), h.work)
	must(err)
	handler.Binary, handler.Revision = h.binary, shaA
	return handler
}

func (h host) trial() map[string]any { return record(filepath.Join(h.work, "nats/release-trial")) }

type started struct {
	Revision   string `json:"revision"`
	Digest     string `json:"digest"`
	RolledBack string `json:"rolled_back"`
	Probation  bool   `json:"probation"`
	Starts     int    `json:"starts"`
	Served     bool   `json:"served"`
	TrialLeft  bool   `json:"trial_left"`
}

func startState(ctx context.Context, work, mode string) {
	probation, err := releasepush.Probe(work, os.Stdout)
	if err != nil {
		require(strings.Contains(err.Error(), "rolled back"), "a failed start must be a rollback: "+err.Error())
		fmt.Println("START rolled-back")
		return
	}
	h, err := releasepush.NewHandler(ctx, work)
	must(err)
	conn, closeListener := listener(h)
	defer closeListener()
	version := settled(ctx, conn)
	result := started{Revision: h.Revision, Digest: version.SHA256, RolledBack: version.RolledBack, Probation: probation != nil, Starts: -1}
	if trial := record(filepath.Join(work, "nats/release-trial")); trial != nil {
		result.Starts = int(trial["starts"].(float64))
	}
	if mode == "serve" {
		result.Served = probation.Served()
		result.TrialLeft = read(filepath.Join(work, "nats/release-trial")) != nil
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

func startParsed(ctx context.Context, work, mode string) started {
	last := startOnce(ctx, work, mode)
	var result started
	require(json.Unmarshal([]byte(last), &result) == nil, "start must report its state: "+last)
	return result
}

func freePort() int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	must(err)
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func serveRegion(ctx context.Context, args []string) {
	work, port, jwks, binaryURL := args[0], args[1], args[2], args[3]
	mode, _, _ := strings.Cut(candidateMode(), ":")
	probation, err := releasepush.Probe(work, os.Stdout)
	if err != nil {
		fmt.Println("START", err)
		return
	}
	if mode == "crash" {
		os.Exit(3)
	}
	if mode == "slow" {
		<-time.NewTimer(slowStep).C
	}
	h, err := releasepush.NewHandler(ctx, work)
	must(err)
	private, closePrivate := listener(h)
	settled(ctx, private)
	closePrivate()
	h.Verifier.JWKSURL = jwks
	h.Client = &http.Client{Transport: redirect{binaryURL}}
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
	h.Relay = func(request []byte, header nats.Header) {
		must(errors.Join(conn.PublishMsg(&nats.Msg{Subject: "lane.silent-workers", Data: request, Header: header}), conn.Flush()))
	}
	must(h.Serve(conn))
	version, err := json.Marshal(settled(ctx, conn))
	must(err)
	fmt.Println("VERSION", string(version))
	fmt.Println("SERVING", probation.Served())
	select {
	case <-h.Installed:
		conn.Close()
		srv.Shutdown()
		srv.WaitForShutdown()
	case <-ctx.Done():
	}
}

func keepServing(ctx context.Context, start func() *exec.Cmd) (func(), string) {
	var mu sync.Mutex
	var current *exec.Cmd
	stopped := false
	up, done := make(chan struct{}), make(chan struct{})
	var version string
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
				for _, line := range ready(current, "SERVING true") {
					if after, ok := strings.CutPrefix(line, "VERSION "); ok {
						version = after
					}
				}
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
	}, version
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

func pushOne(ctx context.Context, work, name string, asset []byte, sha string, p *provider, regions string) (releasepush.Result, error) {
	assets := filepath.Join(work, name)
	must(os.Mkdir(assets, 0o700))
	writeExecutable(filepath.Join(assets, "terrascale-orchestrator-linux-"+runtime.GOARCH), asset)
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_URL", p.server.URL+"/token?"))
	must(os.Setenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN", "lane"))
	var output bytes.Buffer
	err := releasepush.Push(ctx, []string{"--sha", sha, "--dir", assets, "--regions", regions}, &output)
	var result releasepush.Result
	must(json.Unmarshal(bytes.TrimSpace(output.Bytes()), &result))
	return result, err
}

type digestStart struct {
	Served           bool   `json:"served"`
	TrialLeft        bool   `json:"trial_left"`
	ReadyMS          int64  `json:"ready_ms"`
	FirstSHA256      string `json:"first_sha256"`
	FirstUnavailable string `json:"first_unavailable"`
	SHA256           string `json:"sha256"`
	DigestMS         int64  `json:"digest_ms"`
}

func startDigest(ctx context.Context, work string) {
	began := time.Now()
	probation, err := releasepush.Probe(work, os.Stdout)
	must(err)
	h, err := releasepush.NewHandler(ctx, work)
	must(err)
	conn, closeListener := listener(h)
	defer closeListener()
	first := request(ctx, conn, releasepush.SubjectVersion, nil, "")
	result := digestStart{Served: probation != nil && probation.Served(), FirstSHA256: first.SHA256, FirstUnavailable: first.SHA256Unavailable}
	result.ReadyMS = time.Since(began).Milliseconds()
	result.TrialLeft = read(filepath.Join(work, "nats/release-trial")) != nil
	result.SHA256 = settled(ctx, conn).SHA256
	result.DigestMS = time.Since(began).Milliseconds()
	data, err := json.Marshal(result)
	must(err)
	fmt.Println(string(data))
}

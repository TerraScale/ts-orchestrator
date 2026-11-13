package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

type redirect struct{ url string }

func (r redirect) RoundTrip(request *http.Request) (*http.Response, error) {
	clone := request.Clone(request.Context())
	local, err := http.NewRequestWithContext(request.Context(), request.Method, r.url, nil)
	if err != nil {
		return nil, err
	}
	clone.URL, clone.Host = local.URL, local.Host
	return http.DefaultTransport.RoundTrip(clone)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

func ask(ctx context.Context, h *releasepush.Handler, subject, payloadFile, jwks string) releasepush.Reply {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, NoLog: true})
	must(err)
	go srv.Start()
	defer srv.Shutdown()
	if !srv.ReadyForConnections(5 * time.Second) {
		panic("listener did not start")
	}
	conn, err := nats.Connect(srv.ClientURL())
	must(err)
	defer conn.Close()
	must(h.Serve(conn))
	var payload []byte
	if payloadFile != "" {
		payload, err = os.ReadFile(payloadFile)
		must(err)
		h.Verifier = releasepush.NewVerifier()
		h.Verifier.JWKSURL = jwks
	}
	message, err := conn.RequestWithContext(ctx, subject, payload)
	must(err)
	var reply releasepush.Reply
	must(json.Unmarshal(message.Data, &reply))
	return reply
}

func signal(ctx context.Context, work string) int64 {
	h, err := releasepush.NewHandler(work)
	must(err)
	h.Binary, h.Revision = filepath.Join(work, "installed"), os.Args[5]
	h.Client = &http.Client{Transport: redirect{os.Args[4]}}
	h.Verifier = releasepush.NewVerifier()
	h.Verifier.JWKSURL = os.Args[6]
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, NoLog: true})
	must(err)
	go srv.Start()
	defer srv.Shutdown()
	if !srv.ReadyForConnections(5 * time.Second) {
		panic("listener did not start")
	}
	conn, err := nats.Connect(srv.ClientURL())
	must(err)
	defer conn.Close()
	h.Relay = func(request []byte) { must(errors.Join(conn.Publish("lane.silent-workers", request), conn.Flush())) }
	must(h.Serve(conn))
	payload, err := os.ReadFile(os.Args[3])
	must(err)
	go func() { _, _ = conn.RequestWithContext(ctx, releasepush.SubjectOrch, payload) }()
	<-h.Installed
	signalled := time.Now()
	data, err := os.ReadFile(filepath.Join(work, "nats", "release-trial"))
	must(err)
	var trial struct {
		Installed time.Time `json:"installed"`
	}
	must(json.Unmarshal(data, &trial))
	return signalled.Sub(trial.Installed).Nanoseconds()
}

func main() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	switch os.Args[1] {
	case "release":
		if mark := os.Getenv("UPDATER_PREFLIGHT_MARK"); mark != "" {
			must(os.WriteFile(mark, []byte("main's build was run as a preflight\n"), 0o600))
		}
		fmt.Fprintln(os.Stderr, "usage: ts-orch release push")
		os.Exit(2)
	case "push":
		must(releasepush.Push(ctx, os.Args[2:], os.Stdout))
		return
	}
	work := os.Args[2]
	result := map[string]any{}
	switch os.Args[1] {
	case "install":
		h, err := releasepush.NewHandler(work)
		must(err)
		h.Binary, h.Revision = filepath.Join(work, "installed"), os.Args[5]
		h.Client = &http.Client{Transport: redirect{os.Args[4]}}
		result["install"] = ask(ctx, h, releasepush.SubjectOrch, os.Args[3], os.Args[6]).State
	case "start":
		probation, err := releasepush.Probe(work, os.Stdout)
		if err != nil {
			result["restart"] = err.Error()
			break
		}
		h, err := releasepush.NewHandler(work)
		must(err)
		result["served"] = probation.Served()
		result["revision"] = h.Revision
		result["rolled_back"] = ask(ctx, h, releasepush.SubjectVersion, "", "").RolledBack
		result["replay"] = ask(ctx, h, releasepush.SubjectOrch, os.Args[3], os.Args[4]).State
		result["older"] = ask(ctx, h, releasepush.SubjectOrch, os.Args[5], os.Args[6]).State
	case "probe":
		probation, err := releasepush.Probe(work, os.Stdout)
		must(err)
		data, err := os.ReadFile(filepath.Join(work, "nats", "release-trial"))
		must(err)
		var trial struct {
			Starts int `json:"starts"`
		}
		must(json.Unmarshal(data, &trial))
		result["revision"] = releasepush.Revision()
		result["probation"] = probation != nil
		result["starts"] = trial.Starts
		result["served"] = probation.Served()
	case "signal":
		result["signal_ns"] = signal(ctx, work)
	}
	data, err := json.Marshal(result)
	must(err)
	fmt.Println(string(data))
}

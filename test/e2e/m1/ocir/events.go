package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/apppull"
	"github.com/TerraScale/ts-orchestrator/internal/cli"
	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const opaqueCredential = "journeyOpaqueRegistryCredential938428"
const opaqueSignature = "journeyOpaqueRequestSignature328492"

func observeRefusals(ctx context.Context, source apppull.Source, image string) {
	directory, err := os.MkdirTemp("", "app-pull-events-")
	must(err)
	defer os.RemoveAll(directory)
	broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: filepath.Join(directory, "nats")})
	must(err)
	broker.Start()
	defer broker.Shutdown()
	require(broker.ReadyForConnections(5*time.Second), "regional event fabric did not start")
	connect := func() *nats.Conn {
		conn, err := nats.Connect(broker.ClientURL())
		must(err)
		return conn
	}
	reader, holder := connect(), connect()
	defer reader.Close()
	defer holder.Close()
	regional := observability.NewEventBus(observability.DefaultEventCapacity)
	receiver := apppull.NewEvents("stg", regional)
	detach, err := receiver.Attach(ctx, reader)
	must(err)
	defer detach()
	local := observability.NewEventBus(observability.DefaultEventCapacity)
	var journal bytes.Buffer
	logger, err := observability.NewLogger(&journal, observability.LogConfig{}, local)
	must(err)
	previous := slog.Default()
	observability.ConfigureDefault(logger)
	defer observability.ConfigureDefault(previous)
	reporter := apppull.NewEvents("stg", local)
	detachHolder, err := reporter.Attach(ctx, holder)
	must(err)
	defer detachHolder()
	updates, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	stream := regional.Subscribe(updates, 16)
	updater := apppull.Updater{Region: "stg", Source: source, Events: reporter, Apply: mesh.Release(filepath.Join(directory, "absent-node"))}
	must(updater.Cycle(ctx))
	for range apppull.Targets {
		select {
		case _, ok := <-stream:
			require(ok, "lease-holder refusal did not reach the regional dashboard")
		case <-updates.Done():
			panic("lease-holder refusal did not reach the regional dashboard")
		}
	}
	js, err := jetstream.New(holder)
	must(err)
	kv, err := js.KeyValue(ctx, apppull.EventBucket)
	must(err)
	before, err := kv.Get(ctx, "stg.terrabase.release-attestation")
	must(err)
	must(updater.Cycle(ctx))
	takeover := apppull.NewEvents("stg", local)
	detachTakeover, err := takeover.Attach(ctx, holder)
	must(err)
	defer detachTakeover()
	updater.Events = takeover
	must(updater.Cycle(ctx))
	after, err := kv.Get(ctx, "stg.terrabase.release-attestation")
	must(err)
	require(before.Revision() == after.Revision(), "continuous refusal emitted again across sweeps or lease takeover")
	expected := []observability.Event{
		{Message: "app release refused", Attrs: map[string]string{"service": "terrabase", "region": "stg", "release": image, "reason": "release attestation: authorized build provenance and selection required"}},
		{Message: "app release refused", Attrs: map[string]string{"service": "ts-auth", "region": "stg", "release": "ts-auth:release", "reason": "release manifest: HTTP 404"}},
		{Message: "app release refused", Attrs: map[string]string{"service": "ts-dashboard", "region": "stg", "release": "terrascale-dashboard:release", "reason": "release manifest: HTTP 400"}},
	}
	checkEventRecords(regional.Recent(0), expected)
	token := strings.Repeat("journey-events-", 4)
	listener, err := observability.NewTokenServer(observability.Config{ListenAddress: "127.0.0.1:9463"}, token,
		observability.ServerDeps{Registry: observability.NewRegistry(true), Health: new(observability.Health), Events: regional, LocalSessions: true})
	must(err)
	defer listener.Close()
	dashboard.New(dashboard.Options{Events: regional}).Mount(listener)
	endpoint := httptest.NewServer(listener)
	defer endpoint.Close()
	tokenFile := filepath.Join(directory, "token")
	must(os.WriteFile(tokenFile, []byte(token), 0600))
	var output bytes.Buffer
	must(cli.Run(ctx, []string{"observe", "events", "--url", endpoint.URL, "--token-file", tokenFile, "--format", "json"}, &output))
	var document struct{ Data []observability.Event }
	must(json.Unmarshal(output.Bytes(), &document))
	checkEventRecords(document.Data, expected)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL+"/events?component=apppull", nil)
	must(err)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := endpoint.Client().Do(request)
	must(err)
	body, err := io.ReadAll(response.Body)
	must(err)
	must(response.Body.Close())
	require(response.StatusCode == http.StatusOK, "dashboard events failed")
	rows := regexp.MustCompile(`(?s)<tr\b[^>]*>.*?</tr>`).FindAllString(html.UnescapeString(string(body)), -1)
	for _, want := range expected {
		found := false
		for _, row := range rows {
			matches := strings.Contains(row, want.Message)
			for key, value := range want.Attrs {
				matches = matches && strings.Contains(row, key+"="+value)
			}
			found = found || matches
		}
		require(found, "dashboard has no complete refusal row for "+want.Attrs["service"])
	}
	for _, content := range []string{journal.String(), output.String(), string(body)} {
		require(!strings.Contains(content, opaqueCredential) && !strings.Contains(content, opaqueSignature), "registry diagnostic leaked credentials to operators")
	}
	fmt.Println("ok: lease-holder refusals reach regional observe events and complete dashboard rows without opaque credentials; continuous refusals survive takeover without repeats")
}

func checkEventRecords(events, expected []observability.Event) {
	for _, want := range expected {
		found := 0
		for _, event := range events {
			matches := event.Component == "apppull" && event.Message == want.Message
			for key, value := range want.Attrs {
				matches = matches && event.Attrs[key] == value
			}
			if matches {
				found++
			}
		}
		require(found == 1, "observe events has no unique complete refusal record for "+want.Attrs["service"])
	}
}

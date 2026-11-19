package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/apppull"
	"github.com/TerraScale/ts-orchestrator/internal/cli"
	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
)

func observeRefusals(ctx context.Context, source apppull.Source, image string) {
	events := observability.NewEventBus(observability.DefaultEventCapacity)
	logger, err := observability.NewLogger(io.Discard, observability.LogConfig{}, events, observability.Identity("node", "stg")...)
	must(err)
	previous := slog.Default()
	observability.ConfigureDefault(logger)
	defer observability.ConfigureDefault(previous)
	must((apppull.Updater{Region: "stg", Source: source, Apply: func(context.Context, string, string, releasepush.Claims, releasepush.Progress) (json.RawMessage, error) {
		panic("unsigned release reached apply")
	}}).Cycle(ctx))
	var refused, missing bool
	for _, event := range events.Recent(0) {
		require(event.Component == "apppull" && event.Message == "app release refused" && event.Attrs["region"] == "stg" && event.Attrs["reason"] != "", "app-pull refusal lacks its operator context")
		refused = refused || event.Attrs["service"] == "terrabase" && event.Attrs["release"] == image
		missing = missing || event.Attrs["service"] == "ts-auth" && event.Attrs["release"] == "ts-auth:release"
	}
	require(refused && missing, "unsigned image or missing release tag has no event")
	token := strings.Repeat("journey-events-", 4)
	server, err := observability.NewTokenServer(observability.Config{ListenAddress: "127.0.0.1:9463"}, token,
		observability.ServerDeps{Registry: observability.NewRegistry(true), Health: new(observability.Health), Events: events, LocalSessions: true})
	must(err)
	defer server.Close()
	dashboard.New(dashboard.Options{Events: events}).Mount(server)
	endpoint := httptest.NewServer(server)
	defer endpoint.Close()
	directory, err := os.MkdirTemp("", "app-pull-events-")
	must(err)
	defer os.RemoveAll(directory)
	tokenFile := filepath.Join(directory, "token")
	must(os.WriteFile(tokenFile, []byte(token), 0600))
	var output bytes.Buffer
	must(cli.Run(ctx, []string{"observe", "events", "--url", endpoint.URL, "--token-file", tokenFile, "--format", "json"}, &output))
	for _, value := range []string{"app release refused", "stg", "terrabase", image, "reason", "ts-auth:release"} {
		require(strings.Contains(output.String(), value), "observe events omitted "+value)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint.URL+"/events?component=apppull", nil)
	must(err)
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := endpoint.Client().Do(request)
	must(err)
	body, err := io.ReadAll(response.Body)
	must(err)
	must(response.Body.Close())
	require(response.StatusCode == http.StatusOK, "dashboard events failed")
	for _, value := range []string{"app release refused", "stg", "terrabase", image, "reason", "ts-auth:release"} {
		require(strings.Contains(string(body), value), "dashboard events omitted "+value)
	}
	fmt.Println("ok: unsigned and missing app releases are events in observe events and the dashboard")
}

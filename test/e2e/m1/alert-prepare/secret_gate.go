package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"

	"github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/cli"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"golang.org/x/sys/unix"
)

func secretGate(values map[string]string, seen *map[string]bool, denied *string) {
	ctx := context.Background()
	if os.Getpid() == 1 {
		socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		must(err)
		request, err := unix.NewIfreq("lo:1")
		must(err)
		must(request.SetInet4Addr([]byte{169, 254, 169, 254}))
		must(unix.IoctlIfreq(socket, unix.SIOCSIFADDR, request))
		must(unix.Close(socket))
		must(os.MkdirAll("/sys/class/dmi/id", 0o755))
		must(os.WriteFile("/sys/class/dmi/id/chassis_asset_tag", []byte("OracleCloud.com\n"), 0o644))
	}
	entries, err := m1.Files.ReadDir("services")
	must(err)
	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		data, err := m1.Files.ReadFile("services/" + entry.Name())
		must(err)
		var manifest struct{ Secrets map[string]vaultsecret.Ref }
		must(json.Unmarshal(data, &manifest))
		for _, ref := range manifest.Secrets {
			if _, exists := values[ref.Name]; !exists {
				values[ref.Name] = rand.Text()
			}
		}
	}
	region := "sa-saopaulo-1"
	listener, err := net.Listen("tcp", "169.254.169.254:80")
	must(err)
	metadata := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require(r.URL.Path == "/opc/v2/instance/", "preflight must use host instance metadata")
		must(json.NewEncoder(w).Encode(map[string]string{"canonicalRegionName": region, "compartmentId": "ocid1.compartment.oc1..lane"}))
	})}
	go metadata.Serve(listener)
	defer metadata.Close()
	*denied = ""
	*seen = map[string]bool{}
	must(cli.Run(ctx, []string{"release", "preflight", "secrets"}, io.Discard))
	require((*seen)["gru-1-cloudflare-account-id"] && (*seen)["gru-1-cloudflare-email-token"] && (*seen)["gru-1-ts-alerts-ntfy-topic"] && (*seen)["gru-1-ts-auth-master-key"], "manual gate must read auth shared references and all relay references")
	manual := *seen
	*seen = map[string]bool{}
	must(cli.Run(ctx, []string{"release", "preflight"}, io.Discard))
	require(len(manual) == len(*seen), "manual and activation preflight must read the same references")
	for name := range manual {
		require((*seen)[name], "activation preflight must match manual reference reads")
	}
	region = "us-sanjose-1"
	*seen = map[string]bool{}
	must(cli.Run(ctx, []string{"release", "preflight", "secrets"}, io.Discard))
	require(!(*seen)["gru-1-ts-auth-master-key"] && !(*seen)["gru-1-ts-alerts-ntfy-topic"], "manual gate must use only the host region's requirements")
	region = "sa-saopaulo-1"
	*denied = "gru-1-ts-alerts-ntfy-topic"
	gateCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	original := http.DefaultTransport
	http.DefaultTransport = gateTransport{original, *denied, cancel}
	defer func() { http.DefaultTransport = original }()
	err = cli.Run(gateCtx, []string{"release", "preflight", "secrets"}, io.Discard)
	require(err != nil && strings.Contains(err.Error(), *denied), fmt.Sprintf("manual gate must fail naming the unreadable reference: %v", err))
	for _, value := range values {
		require(!strings.Contains(err.Error(), value), "manual gate must not expose values")
	}
	fmt.Println("ok secret gate: shared auth and relay references; identical activation reads; regional scope; value-free named refusal")
}

type gateTransport struct {
	transport http.RoundTripper
	denied    string
	cancel    context.CancelFunc
}

func (t gateTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	response, err := t.transport.RoundTrip(request)
	if request.URL.Query().Get("secretName") == t.denied {
		t.cancel()
	}
	return response, err
}

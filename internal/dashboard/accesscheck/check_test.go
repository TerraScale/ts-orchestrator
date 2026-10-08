package accesscheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/sshlogin"
)

func TestFleetCheckRequiresEveryAddressEndpointAndRegionToken(t *testing.T) {
	peers := map[string]sshlogin.PeerAddress{}
	for i, region := range []string{"gru", "sfo"} {
		for n := 1; n <= 3; n++ {
			peers[fmt.Sprintf("ts-%s-%d", region, n)] = sshlogin.PeerAddress{IP: fmt.Sprintf("10.200.%d.%d", i, n), IPv6: fmt.Sprintf("fd9c:200::%d:%d", i, n)}
		}
	}
	tokens := map[string]string{"gru": "gru-secret", "sfo": "sfo-secret"}
	for _, failure := range []string{"", "ipv6", "missing", "dns", "unauthorized", "redirect", "wrong-address", "wrong-ipv6", "missing-ipv6"} {
		t.Run(failure, func(t *testing.T) {
			inventory := map[string]sshlogin.PeerAddress{}
			for name, ip := range peers {
				inventory[name] = ip
			}
			if failure == "missing" {
				delete(inventory, "ts-sfo-3")
			}
			if failure == "missing-ipv6" {
				peer := inventory["ts-sfo-3"]
				peer.IPv6 = ""
				inventory["ts-sfo-3"] = peer
			}
			calls := 0
			get := func(_ context.Context, url, token string, timeout time.Duration) (string, string, error) {
				calls++
				region := "gru"
				if strings.Contains(url, "sfo") || strings.Contains(url, "10.200.1.") {
					region = "sfo"
				}
				if token != tokens[region] || timeout != 5*time.Second {
					t.Fatalf("wrong region token or timeout for %s", url)
				}
				ip := ""
				for name, address := range inventory {
					if strings.Contains(url, name+".") || strings.Contains(url, address.IP+":") {
						ip = address.IP
						if failure == "ipv6" && strings.Contains(url, name+".") {
							ip = address.IPv6
						}
					}
				}
				if strings.Contains(url, "ts-sfo-3.nb.ts.internal:9463/topology") {
					switch failure {
					case "dns":
						return "000", "", errors.New("exit status 6")
					case "unauthorized":
						return "401", ip, nil
					case "redirect":
						return "302", ip, nil
					case "wrong-address":
						return "200", "10.200.1.2", nil
					case "wrong-ipv6":
						return "200", "fd9c:200::1:2", nil
					case "missing-ipv6":
						return "200", "fd9c:200::1:3", nil
					}
				}
				return "200", ip, nil
			}
			var out bytes.Buffer
			err := check(t.Context(), &out, inventory, tokens, 5*time.Second, get)
			if (err != nil) != (failure != "" && failure != "ipv6") {
				t.Fatalf("check error = %v", err)
			}
			if failure == "wrong-address" || failure == "wrong-ipv6" {
				if !strings.Contains(err.Error(), "expected 10.200.1.3 or fd9c:200::1:3") {
					t.Fatalf("failure omitted an accepted peer address: %v", err)
				}
			}
			if failure == "missing-ipv6" && strings.Contains(err.Error(), " or ") {
				t.Fatalf("failure advertised an unavailable IPv6 address: %v", err)
			}
			wantCalls := 24
			if failure == "missing" {
				wantCalls = 20
			}
			if calls != wantCalls || strings.Contains(out.String(), "secret") {
				t.Fatalf("calls = %d; output = %s", calls, out.String())
			}
		})
	}
}

func TestCurlSendsTokenAndDoesNotFollowRedirectsOrUseProxy(t *testing.T) {
	if _, err := exec.LookPath("curl"); err != nil {
		t.Fatal("curl is required to verify the live-check command")
	}
	t.Setenv("http_proxy", "http://127.0.0.1:1")
	t.Setenv("ALL_PROXY", "http://127.0.0.1:1")
	token := `secret-"-\`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+token {
			t.Error("curl did not receive the token through its config stdin")
		}
		if r.URL.Path == "/topology" {
			w.Header().Set("Location", "/wrong-controller")
			w.WriteHeader(http.StatusFound)
			return
		}
		if r.URL.Path != "/healthz" {
			t.Error("curl followed a redirect")
		}
	}))
	defer server.Close()
	for path, want := range map[string]string{"/healthz": "200", "/topology": "302"} {
		status, ip, err := curl(t.Context(), server.URL+path, token, 5*time.Second)
		if err != nil || status != want || ip != "127.0.0.1" {
			t.Fatalf("curl %s: status=%s IP=%s err=%v", path, status, ip, err)
		}
	}
}

package accesscheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os/exec"
	"strings"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/dashboard"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/sshlogin"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/observability"
)

func TestFleetCheckRequiresEveryAddressEndpointAndRegionToken(t *testing.T) {
	peers := map[string]sshlogin.PeerAddress{}
	for i, region := range []string{"gru", "sfo"} {
		for n := 1; n <= 3; n++ {
			peers[fmt.Sprintf("ts-%s-%d", region, n)] = sshlogin.PeerAddress{IP: fmt.Sprintf("10.200.%d.%d", i, n), IPv6: fmt.Sprintf("fd9c:200::%d:%d", i, n)}
		}
	}
	tokens := map[string]string{"gru": "gru-secret", "sfo": "sfo-secret"}
	for _, failure := range []string{"", "ipv6", "missing", "dns", "unauthorized", "redirect", "wrong-address", "wrong-ipv6", "missing-ipv6", "empty", "local-only"} {
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
			get := func(_ context.Context, url, token string, timeout time.Duration) (string, string, string, error) {
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
						return "000", "", "", errors.New("exit status 6")
					case "unauthorized":
						return "401", ip, "", nil
					case "redirect":
						return "302", ip, "", nil
					case "wrong-address":
						return "200", "10.200.1.2", "", nil
					case "wrong-ipv6":
						return "200", "fd9c:200::1:2", "", nil
					case "missing-ipv6":
						return "200", "fd9c:200::1:3", "", nil
					}
				}
				body := `<div id="content"><h1>Live dashboard</h1><svg><g data-node="one"></g><g data-node="two"></g><g data-node="three"></g></svg><table><tbody><tr><td><a href="/members/one">one</a></td><td><a href="/members/two">two</a></td><td><a href="/members/three">three</a></td></tr></tbody></table></div>`
				if failure == "empty" && strings.HasSuffix(url, "/storage") {
					body = `<div id="content"></div>`
				}
				if failure == "local-only" && strings.HasSuffix(url, "/members") {
					body = `<div id="content"><h1>Members</h1><table><tbody><tr><td><a href="/members/one">one</a></td></tr></tbody></table></div>`
				}
				return "200", ip, body, nil
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
			wantCalls := 180
			if failure == "missing" {
				wantCalls = 150
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
		status, ip, _, err := curl(t.Context(), server.URL+path, token, 5*time.Second)
		if err != nil || status != want || ip != "127.0.0.1" {
			t.Fatalf("curl %s: status=%s IP=%s err=%v", path, status, ip, err)
		}
	}
}

func TestRenderedRejectsEmptyAndDuplicateTelemetry(t *testing.T) {
	for _, test := range []struct {
		name, path, body string
	}{
		{"blank", "/", ""},
		{"login", "/", `<form><input name="token"></form>`},
		{"empty content", "/storage", `<div id="content"> </div>`},
		{"title only", "/storage", `<div id="content"><h1>Storage</h1></div>`},
		{"header only", "/", `<div id="content"><div class="page-head"><h1>All regions</h1><small>updated now</small></div><h2>Regions</h2></div>`},
		{"empty topology", "/topology", `<div id="content"><h1>Topology</h1><svg></svg></div>`},
		{"duplicate nodes", "/topology", `<div id="content"><h1>Topology</h1><svg><g data-node="one"></g><g data-node="one"></g><g data-node="one"></g></svg></div>`},
		{"navigation links", "/members", `<div id="content"><h1>Members</h1><a href="/members/one">one</a><a href="/members/two">two</a><a href="/members/three">three</a></div>`},
		{"duplicate members", "/members", `<div id="content"><table><tbody><tr><td><a href="/members/one">one</a><a href="/members/one">one</a><a href="/members/one">one</a></td></tr></tbody></table></div>`},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := rendered(test.path, test.body); err == nil {
				t.Fatal("empty dashboard passed")
			}
		})
	}
}

func TestRenderedProductionDashboardRequiresCellWideReports(t *testing.T) {
	now := time.Now().UTC()
	var members []observability.MemberSnapshot
	for _, member := range []string{"one", "two", "three"} {
		members = append(members, observability.MemberSnapshot{Version: 1, Cell: "gru", Member: member,
			Role: "controller", Ready: true, BuildVersion: "live-build", StartedAt: now.Add(-time.Hour), ObservedAt: now})
	}
	for _, count := range []int{1, 3} {
		t.Run(fmt.Sprintf("%d controllers", count), func(t *testing.T) {
			source := probeSource{members: members[:count], now: now}
			board := dashboard.New(dashboard.Options{Snapshots: source, Cluster: source})
			for _, path := range []string{"/members", "/topology"} {
				response := httptest.NewRecorder()
				board.Handler().ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
				if response.Code != http.StatusOK {
					t.Fatalf("%s: HTTP %d", path, response.Code)
				}
				if err := rendered(path, response.Body.String()); (err != nil) != (count < 3) {
					t.Fatalf("%s with %d controllers: %v", path, count, err)
				}
			}
		})
	}
}

type probeSource struct {
	members []observability.MemberSnapshot
	now     time.Time
}

func (source probeSource) Snapshot(context.Context, bool) (observability.MemberSnapshot, error) {
	return source.members[0], nil
}

func (source probeSource) Cluster(context.Context, bool) (observability.ClusterSnapshot, error) {
	return observability.ClusterSnapshot{Cell: "gru", ObservedAt: source.now, Members: source.members}, nil
}

func TestCurlReturnsBodyAndBoundsResponseSize(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/large" {
			_, _ = io.WriteString(w, strings.Repeat("x", 3<<20))
			return
		}
		_, _ = io.WriteString(w, "body with newlines\n200 10.200.0.1\n")
	}))
	defer server.Close()
	status, ip, body, err := curl(t.Context(), server.URL, "secret", 5*time.Second)
	if err != nil || status != "200" || ip != "127.0.0.1" || body != "body with newlines\n200 10.200.0.1\n" {
		t.Fatalf("curl body/status split: %q %q %q %v", status, ip, body, err)
	}
	if _, _, _, err := curl(t.Context(), server.URL+"/large", "secret", 5*time.Second); err == nil {
		t.Fatal("oversized response passed")
	}
}

package accesscheck

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/dashboard"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/sshlogin"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

func TestFleetCheckRequiresEveryAddressEndpointAndRegionToken(t *testing.T) {
	for _, failure := range []string{"", "ipv6", "missing", "dns", "unauthorized", "redirect", "wrong-address", "wrong-ipv6", "missing-ipv6", "empty", "local-only", "duplicate-nodes", "duplicate-members"} {
		t.Run(failure, func(t *testing.T) {
			peers := map[string]sshlogin.PeerAddress{}
			for i, region := range []string{"gru", "sjc"} {
				for n := 1; n <= 3; n++ {
					peers[fmt.Sprintf("ts-%s-%d", region, n)] = sshlogin.PeerAddress{IP: fmt.Sprintf("10.200.%d.%d", i, n), IPv6: fmt.Sprintf("fd9c:200::%d:%d", i, n)}
				}
			}
			if failure == "missing" {
				delete(peers, "ts-sjc-3")
			}
			if failure == "missing-ipv6" {
				peer := peers["ts-sjc-3"]
				peer.IPv6 = ""
				peers["ts-sjc-3"] = peer
			}
			tokens := map[string]string{"gru": "gru-secret", "sjc": "sjc-secret"}
			calls := 0
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls++
				region := "gru"
				if strings.Contains(r.Host, "sjc") || strings.Contains(r.Host, "10.200.1.") {
					region = "sjc"
				}
				if r.Header.Get("Authorization") != "Bearer "+tokens[region] {
					t.Error("wrong region token at HTTP boundary")
					w.WriteHeader(http.StatusUnauthorized)
					return
				}
				if r.Host == "ts-sjc-3.nb.ts.internal:9463" && r.URL.Path == "/topology" {
					if failure == "unauthorized" {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
					if failure == "redirect" {
						w.Header().Set("Location", "/wrong-controller")
						w.WriteHeader(http.StatusFound)
						return
					}
				}
				if r.URL.Path == "/wrong-controller" {
					t.Error("check followed a redirect")
				}
				body := `<div id="content"><h1>Live dashboard</h1><p>Observed</p><svg><g data-node="one"></g><g data-node="two"></g><g data-node="three"></g></svg><table><tbody><tr><td><a href="/members/one">one</a><a href="/members/two">two</a><a href="/members/three">three</a></td></tr></tbody></table></div>`
				if failure == "empty" && r.URL.Path == "/storage" {
					body = `<div id="content"><h1>Storage</h1></div>`
				}
				if failure == "local-only" && r.URL.Path == "/members" {
					body = `<div id="content"><p>Observed</p><table><tbody><tr><td><a href="/members/one">one</a></td></tr></tbody></table></div>`
				}
				if failure == "duplicate-nodes" {
					body = strings.ReplaceAll(strings.ReplaceAll(body, `data-node="two"`, `data-node="one"`), `data-node="three"`, `data-node="one"`)
				}
				if failure == "duplicate-members" {
					body = strings.ReplaceAll(strings.ReplaceAll(body, `/members/two`, `/members/one`), `/members/three`, `/members/one`)
				}
				_, _ = io.WriteString(w, body)
			}))
			defer server.Close()
			client := server.Client()
			client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
			// The fixture supplies NetBird's address mapping; every fetch still crosses an HTTP socket.
			fetch := func(ctx context.Context, target, token string, timeout time.Duration) (string, string, string, error) {
				parsed, err := url.Parse(target)
				if err != nil {
					return "", "", "", err
				}
				if timeout != 5*time.Second {
					t.Error("check lost request timeout")
				}
				request, err := http.NewRequestWithContext(ctx, http.MethodGet, server.URL+parsed.Path, nil)
				if err != nil {
					return "", "", "", err
				}
				request.Host = parsed.Host
				request.Header.Set("Authorization", "Bearer "+token)
				response, err := client.Do(request)
				if err != nil {
					return "", "", "", err
				}
				defer response.Body.Close()
				body, err := io.ReadAll(response.Body)
				if err != nil {
					return "", "", "", err
				}
				address := ""
				for name, peer := range peers {
					if parsed.Hostname() == peer.IP || parsed.Hostname() == name+".nb.ts.internal" {
						address = peer.IP
						if failure == "ipv6" && strings.HasSuffix(parsed.Hostname(), ".internal") {
							address = peer.IPv6
						}
					}
				}
				if parsed.Hostname() == "ts-sjc-3.nb.ts.internal" && parsed.Path == "/topology" {
					switch failure {
					case "dns":
						return "000", "", "", errors.New("DNS lookup failed")
					case "wrong-address":
						address = "10.200.1.2"
					case "wrong-ipv6":
						address = "fd9c:200::1:2"
					case "missing-ipv6":
						address = "fd9c:200::1:3"
					}
				}
				return strconv.Itoa(response.StatusCode), address, string(body), nil
			}
			var out bytes.Buffer
			err := check(t.Context(), &out, peers, tokens, 5*time.Second, fetch)
			wantFailure := failure != "" && failure != "ipv6"
			if (err != nil) != wantFailure {
				t.Fatalf("fleet check %s: %v", failure, err)
			}
			wantCalls := 180
			if failure == "missing" {
				wantCalls = 150
			}
			if calls != wantCalls || strings.Contains(out.String(), "secret") {
				t.Fatalf("calls=%d; output=%s", calls, &out)
			}
			if failure == "wrong-address" || failure == "wrong-ipv6" {
				if !strings.Contains(err.Error(), "expected 10.200.1.3 or fd9c:200::1:3") {
					t.Fatal("wrong-address error lost accepted addresses")
				}
			}
			if failure == "missing-ipv6" && strings.Contains(err.Error(), " or ") {
				t.Fatal("error advertised absent IPv6")
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
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, test.body) }))
			defer server.Close()
			status, _, body, err := curl(t.Context(), server.URL, "token", 5*time.Second)
			if err != nil || status != "200" {
				t.Fatalf("read response: %s %v", status, err)
			}
			if err := rendered(test.path, body); err == nil {
				t.Fatal("empty dashboard passed after HTTP fetch")
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
	getLarge := func(ctx context.Context, _ string, token string, timeout time.Duration) (string, string, string, error) {
		return curl(ctx, server.URL+"/large", token, timeout)
	}
	var out bytes.Buffer
	err = check(t.Context(), &out, map[string]sshlogin.PeerAddress{"ts-gru-1": {IP: "10.200.0.1"}},
		map[string]string{"gru": "secret", "sjc": "secret"}, 5*time.Second, getLarge)
	if exit, ok := errors.AsType[*exec.ExitError](err); !ok || exit.ExitCode() != 63 ||
		!strings.Contains(out.String(), "FAIL dashboard response exceeds 2 MiB") || strings.Contains(out.String(), "secret") {
		t.Fatalf("oversized response diagnostic: %v; output: %s", err, &out)
	}
}

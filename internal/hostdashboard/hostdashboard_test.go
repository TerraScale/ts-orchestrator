package hostdashboard

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
)

func TestSecretNameFollowsTheCellSpec(t *testing.T) {
	if got := SecretName("gru"); got != "gru-1-orch-dashboard-token" {
		t.Fatalf("SecretName(gru) = %q", got)
	}
}

// Every region's host is a member: this host's own snapshot, the others from
// their mesh health reports, and a silent region as missing.
func TestMeshClusterListsEveryRegion(t *testing.T) {
	at := time.Date(2026, 10, 26, 12, 0, 0, 0, time.UTC)
	cluster := &meshCluster{region: "gru", local: fixedSnapshot{Cell: "gru", Member: "ts-gru-2", Role: Role, Ready: true},
		regions: func() []string { return []string{"gru", "sjc", "fra", "iad"} },
		ask: func(context.Context) (map[string]regionhealth.Report, error) {
			return map[string]regionhealth.Report{
				"gru": {Region: "gru", Server: "ts-gru-2", State: regionhealth.StateOK, At: at},
				"sjc": {Region: "sjc", Server: "ts-sjc-1", State: regionhealth.StateOK, At: at},
				"fra": {Region: "fra", Server: "ts-fra-1", State: regionhealth.StateDegraded, Reasons: []string{"memory low"}, At: at},
			}, nil
		}}
	snapshot, err := cluster.Cluster(t.Context(), false)
	if err != nil {
		t.Fatal(err)
	}
	var members []string
	for _, member := range snapshot.Members {
		members = append(members, member.Cell+"/"+member.Member)
	}
	if got := strings.Join(members, ","); got != "fra/ts-fra-1,gru/ts-gru-2,sjc/ts-sjc-1" {
		t.Fatalf("members = %s", got)
	}
	if fra := snapshot.Members[0]; fra.Ready || fra.Checks[0].Detail != "degraded: memory low" {
		t.Fatalf("fra = %+v", fra)
	}
	if strings.Join(snapshot.Missing, ",") != "iad" {
		t.Fatalf("missing = %v", snapshot.Missing)
	}
}

// The loop serves once it has an address and a token, signs a browser in
// with the token, renders every region's host, follows a rotated token, and
// keeps the token read last while Vault is down.
func TestServeFollowsTheToken(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := probe.Addr().(*net.TCPAddr).Port
	_ = probe.Close()
	checkEvery, tokenEvery, tokenRetry = 10*time.Millisecond, 10*time.Millisecond, 10*time.Millisecond
	t.Cleanup(func() { checkEvery, tokenEvery, tokenRetry = 5*time.Second, 5*time.Minute, 30*time.Second })

	var mu sync.Mutex
	token, vaultDown := strings.Repeat("a", 64), false
	from := sources{port: port, address: func() (string, error) { return "127.0.0.1", nil },
		token: func(context.Context) (string, error) {
			mu.Lock()
			defer mu.Unlock()
			if vaultDown {
				return "", errors.New("vault unavailable")
			}
			return token, nil
		}}
	health := new(observability.Health)
	local := fixedSnapshot{Cell: "gru", Member: "ts-gru-2", Role: Role, Ready: true}
	deps := observability.ServerDeps{Registry: observability.NewRegistry(true), Health: health, Snapshots: local,
		Cluster: &meshCluster{region: "gru", local: local, regions: func() []string { return []string{"gru", "sjc", "fra"} },
			ask: func(context.Context) (map[string]regionhealth.Report, error) {
				return map[string]regionhealth.Report{
					"sjc": {Region: "sjc", Server: "ts-sjc-1", State: regionhealth.StateOK},
					"fra": {Region: "fra", Server: "ts-fra-1", State: regionhealth.StateOK},
				}, nil
			}},
		Events: observability.NewEventBus(16), LocalSessions: true}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan struct{})
	go func() { serve(ctx, deps, from); close(done) }()
	t.Cleanup(func() { cancel(); <-done })

	base := "http://127.0.0.1:" + strconv.Itoa(port)
	waitStatus(t, base+"/members", strings.Repeat("a", 64), http.StatusOK)
	for _, page := range []string{"/members", "/topology"} {
		body := get(t, base+page, strings.Repeat("a", 64))
		for _, host := range []string{"ts-gru-2", "ts-sjc-1", "ts-fra-1"} {
			if !strings.Contains(body, host) {
				t.Fatalf("%s does not show %s", page, host)
			}
		}
	}
	if status := status(t, base+"/login", ""); status != http.StatusOK {
		t.Fatalf("/login = %d", status)
	}
	if cookie := login(t, base, strings.Repeat("a", 64)); cookie == nil {
		t.Fatal("login with the token issued no session")
	}

	mu.Lock()
	token = strings.Repeat("b", 64)
	mu.Unlock()
	waitStatus(t, base+"/members", strings.Repeat("b", 64), http.StatusOK)
	if got := status(t, base+"/members", strings.Repeat("a", 64)); got != http.StatusUnauthorized {
		t.Fatalf("old token = %d", got)
	}

	mu.Lock()
	vaultDown = true
	mu.Unlock()
	time.Sleep(50 * time.Millisecond)
	if got := status(t, base+"/members", strings.Repeat("b", 64)); got != http.StatusOK {
		t.Fatalf("token read last while Vault is down = %d", got)
	}
}

type fixedSnapshot observability.MemberSnapshot

func (snapshot fixedSnapshot) Snapshot(context.Context, bool) (observability.MemberSnapshot, error) {
	return observability.MemberSnapshot(snapshot), nil
}

func request(t *testing.T, target, token string) *http.Response {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return nil
	}
	return response
}

func status(t *testing.T, target, token string) int {
	t.Helper()
	response := request(t, target, token)
	if response == nil {
		return 0
	}
	_ = response.Body.Close()
	return response.StatusCode
}

func get(t *testing.T, target, token string) string {
	t.Helper()
	response := request(t, target, token)
	if response == nil {
		t.Fatalf("GET %s failed", target)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil || response.StatusCode != http.StatusOK {
		t.Fatalf("GET %s = %d %v", target, response.StatusCode, err)
	}
	return string(body)
}

func waitStatus(t *testing.T, target, token string, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for status(t, target, token) != want {
		if time.Now().After(deadline) {
			t.Fatalf("%s never answered %d", target, want)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// login posts the sign-in form as a same-origin browser and returns the
// session cookie.
func login(t *testing.T, base, token string) *http.Cookie {
	t.Helper()
	form := url.Values{"token": {token}}
	req, err := http.NewRequestWithContext(t.Context(), http.MethodPost, base+"/login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", base)
	req.Header.Set("Sec-Fetch-Site", "same-origin")
	client := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	for _, cookie := range response.Cookies() {
		if cookie.Value != "" {
			return cookie
		}
	}
	return nil
}

package foundation

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// This exercises the loopback protocol against actual HTTP and persistent SQLite.
// It does not substitute fixture proofs for the public account authority or qualify upstream Dex.
func TestAccountLoopbackSQLiteIdentityAndPerWireFence(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	directory := t.TempDir()
	database := filepath.Join(directory, "identity.db")
	query := func(script string, args ...string) string {
		t.Helper()
		argv := append([]string{"-c", script, database}, args...)
		command := exec.CommandContext(ctx, "python3", argv...)
		wire, err := command.CombinedOutput()
		if err != nil {
			t.Fatalf("SQLite protocol fixture: %v", err)
		}
		return strings.TrimSpace(string(wire))
	}
	query(`import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
 db.execute('CREATE TABLE account (owner TEXT, service TEXT)')
 db.execute("INSERT INTO account VALUES ('owner-original','service-original')")
 db.execute('CREATE TABLE tokens (id TEXT PRIMARY KEY, name TEXT)')
 db.execute("INSERT INTO tokens VALUES ('pat-original','ts-orchestrator')")
`)
	var state, challenge string
	var received, checks atomic.Int64
	var admitted atomic.Bool
	admitted.Store(true)
	fixturePAT := "nbp_" + strings.Repeat("a", 40)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		switch r.URL.Path {
		case "/api/instance":
			fmt.Fprint(w, `{"setup_required":false}`)
		case "/oauth2/auth":
			state = r.URL.Query().Get("state")
			challenge = r.URL.Query().Get("code_challenge")
			if state == "" || challenge == "" || r.URL.Query().Get("code_challenge_method") != "S256" {
				http.Error(w, "invalid", 400)
				return
			}
			http.SetCookie(w, &http.Cookie{Name: "dex", Value: "retained", Path: "/oauth2", HttpOnly: true})
			fmt.Fprint(w, `<form method="post" action="/oauth2/auth/local/login"></form>`)
		case "/oauth2/auth/local/login":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid", 400)
				return
			}
			cookie, err := r.Cookie("dex")
			if err != nil || cookie.Value != "retained" || r.Form.Get("login") != accountOwnerEmail || r.Form.Get("password") != "vault-generated-password" {
				http.Error(w, "invalid", 401)
				return
			}
			w.Header().Set("Location", accountPublicOrigin+"/nb-auth?"+url.Values{"state": {state}, "code": {"one-use-code"}}.Encode())
			w.WriteHeader(302)
		case "/oauth2/token":
			if err := r.ParseForm(); err != nil {
				http.Error(w, "invalid", 400)
				return
			}
			sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
			if base64.RawURLEncoding.EncodeToString(sum[:]) != challenge || r.Form.Get("code") != "one-use-code" || r.Form.Get("redirect_uri") != accountPublicOrigin+"/nb-auth" {
				http.Error(w, "invalid", 401)
				return
			}
			fmt.Fprint(w, `{"id_token":"owner-authenticated-jwt"}`)
		case "/api/users":
			if r.Header.Get("Authorization") != "Token "+fixturePAT {
				http.Error(w, "invalid", 401)
				return
			}
			ids := strings.Split(query(`import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
 row=db.execute('SELECT owner,service FROM account').fetchone()
 print(row[0]+','+row[1])
`), ",")
			if len(ids) != 2 {
				http.Error(w, "invalid", 500)
				return
			}
			fmt.Fprintf(w, `[{"id":%q,"email":"netbird-owner@terrascale.tech","role":"owner","is_service_user":false,"is_current":false},{"id":%q,"name":"ts-orchestrator","role":"admin","is_service_user":true,"is_current":true}]`, ids[0], ids[1])
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, target.Host)
	}}
	defer transport.CloseIdleConnections()
	jar, _ := cookiejar.New(nil)
	c := &accountClient{http: &http.Client{Transport: accountTransport{base: transport, check: func(context.Context) error {
		checks.Add(1)
		if !admitted.Load() {
			return errors.New("fixture authority withdrawn")
		}
		return nil
	}}, Jar: jar, Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	jwt, err := c.login(ctx, "vault-generated-password")
	if err != nil || jwt != "owner-authenticated-jwt" {
		t.Fatalf("embedded login: %v", err)
	}
	if checks.Load() != 3 || received.Load() != 3 {
		t.Fatalf("login wire fence checks=%d requests=%d", checks.Load(), received.Load())
	}
	j := accountJournal{Binding: storeBinding{StoreGeneration: "original:1"}, SetupState: "verified", OwnerID: "owner-original", ServiceID: "service-original", PublishedPATID: "pat-original"}
	if err = c.verifyPAT(ctx, fixturePAT, j); err != nil {
		t.Fatal(err)
	}
	// The identity journal and database survive a new client/process observation.
	wire, err := json.Marshal(j)
	if err != nil {
		t.Fatal(err)
	}
	escrow := filepath.Join(directory, "account.json")
	if err = os.WriteFile(escrow, wire, 0o600); err != nil {
		t.Fatal(err)
	}
	wire, err = os.ReadFile(escrow)
	if err != nil {
		t.Fatal(err)
	}
	var retained accountJournal
	if err = json.Unmarshal(wire, &retained); err != nil {
		t.Fatal(err)
	}
	if err = retained.validate(j.Binding); err != nil {
		t.Fatal(err)
	}
	if err = c.verifyPAT(ctx, fixturePAT, retained); err != nil {
		t.Fatal(err)
	}
	query(`import sqlite3,sys
with sqlite3.connect(sys.argv[1]) as db:
 db.execute("UPDATE account SET service='service-foreign'")
`)
	if err = c.verifyPAT(ctx, fixturePAT, retained); err == nil {
		t.Fatal("foreign service replaced the retained PAT subject")
	}
	before := received.Load()
	admitted.Store(false)
	if _, err = c.setupRequired(ctx); err == nil {
		t.Fatal("withdrawn authority reached loopback")
	}
	if received.Load() != before {
		t.Fatal("withdrawn authority sent a wire request")
	}
	admitted.Store(true)
	req, err := http.NewRequestWithContext(ctx, "GET", "http://foreign.invalid/api/instance", nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = c.http.Do(req); err == nil {
		t.Fatal("account transport accepted a foreign origin")
	}
	if received.Load() != before {
		t.Fatal("foreign origin reached fixture")
	}
}

func TestAccountDexRefusesForeignFormWithoutSendingPassword(t *testing.T) {
	ctx := t.Context()
	var received atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		received.Add(1)
		fmt.Fprint(w, `<form action="//foreign.invalid/oauth2/auth/local/login"></form>`)
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	transport := &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, target.Host)
	}}
	defer transport.CloseIdleConnections()
	c := &accountClient{http: &http.Client{Transport: accountTransport{base: transport, check: func(context.Context) error { return nil }}, Timeout: 5 * time.Second}}
	if _, err = c.login(ctx, "must-never-be-sent"); err == nil {
		t.Fatal("foreign form accepted")
	}
	if received.Load() != 1 {
		t.Fatal("password sent after foreign form")
	}
}

package natscell

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func TestStartupControllerPrivateTLSAndInProcessAuthentication(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	region, root := startupControllerBroker(t, ctx)
	for _, name := range []string{"valid", "wrong-account", "same-account-other-user", "same-user-broader-jwt", "system", "membership", "wrong-connection-type", "wrong-tls"} {
		t.Run(name, func(t *testing.T) {
			cfg := region.cfg
			cfg.URL = "tls://unrelated.invalid:4222,tls://another.invalid:4222"
			switch name {
			case "wrong-account":
				account, err := nkeys.CreateAccount()
				if err != nil {
					t.Fatal(err)
				}
				defer account.Wipe()
				cfg.CredentialsFile = startupControllerCredentials(t, t.TempDir(), account, jwt.ConnectionTypeInProcess)
			case "wrong-connection-type":
				cfg.CredentialsFile = startupControllerCredentials(t, t.TempDir(), region.cell, jwt.ConnectionTypeStandard)
			case "same-account-other-user":
				cfg.CredentialsFile = startupControllerCredentials(t, t.TempDir(), region.cell, jwt.ConnectionTypeInProcess)
			case "same-user-broader-jwt":
				cfg.CredentialsFile = broaderStartupControllerCredentials(t, region)
			case "system":
				cfg.CredentialsFile = region.cfg.Embedded.SystemCredentialsFile
			case "membership":
				cfg.CredentialsFile = startupMembershipCredentials(t, region)
			case "wrong-tls":
				cfg.TLS = testBridgeTLS(t, t.TempDir())
			}
			admitted, initial := net.Pipe()
			session, stop := context.WithCancel(ctx)
			defer stop()
			done := make(chan error, 1)
			go func() { done <- root.ServeStartupController(session, admitted, time.Now().Add(5*time.Second)) }()
			client, err := StartControllerClient(ctx, cfg, initial)
			if name != "valid" {
				if err == nil {
					_ = client.Close()
					t.Fatal("private transport accepted invalid controller authentication")
				}
				if name != "wrong-tls" && !errors.Is(err, nats.ErrAuthorization) {
					t.Fatalf("credential was not rejected by native authentication: %v", err)
				}
			} else {
				if err != nil {
					t.Fatal(err)
				}
				if client.server != nil || client.Bridge() != nil {
					t.Fatal("ordinary controller started another embedded broker")
				}
				if err := client.Conn().FlushWithContext(ctx); err != nil {
					t.Fatal(err)
				}
				_ = client.Close()
			}
			stop()
			select {
			case <-done:
			case <-ctx.Done():
				t.Fatal("private startup did not close with its session")
			}
			if status := root.Bridge().Status(); status.Open || status.ActiveSessions != 0 {
				t.Fatalf("private startup altered the public gate: %+v", status)
			}
		})
	}
}

func TestPrivateAndPublicBridgeRejectSecondConnectAccountSwitch(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	region, root := startupControllerBroker(t, ctx)
	claim := root.InitialCellJWT()
	if err := root.ApplyCellClaim(ctx, 1, claim); err != nil {
		t.Fatal(err)
	}
	if err := root.Bridge().OpenUntil(1, claim, time.Now().Add(15*time.Second)); err != nil {
		t.Fatal(err)
	}
	other := startupControllerCredentials(t, t.TempDir(), region.cell, jwt.ConnectionTypeInProcess)
	membership := startupMembershipCredentials(t, region)
	broader := broaderStartupControllerCredentials(t, region)
	for _, transport := range []string{"private", "public"} {
		for _, next := range []struct {
			name, path string
		}{
			{"original", region.cfg.CredentialsFile},
			{"same-account-other-user", other}, {"same-user-broader-jwt", broader},
			{"system", region.cfg.Embedded.SystemCredentialsFile}, {"membership", membership},
		} {
			t.Run(transport+"/"+next.name, func(t *testing.T) {
				secured, reader, nonce := startupProtocolConnection(t, ctx, region, root, transport)
				writeStartupConnect(t, secured, region.cfg.CredentialsFile, nonce)
				if line, err := reader.ReadString('\n'); err != nil || line != "PONG\r\n" {
					t.Fatalf("original controller authentication: %q %v", line, err)
				}
				writeStartupConnect(t, secured, next.path, nonce)
				line, err := reader.ReadString('\n')
				if next.name == "original" || transport == "public" && (next.name == "same-account-other-user" || next.name == "same-user-broader-jwt") {
					if err != nil || line != "PONG\r\n" {
						t.Fatalf("bridge rejected its allowed repeated authentication: %q %v", line, err)
					}
					return
				}
				if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
					t.Fatal("identity switch was not rejected before the protocol deadline")
				}
				if err == nil && !strings.HasPrefix(line, "-ERR ") {
					t.Fatalf("identity switch was not rejected: %q %v", line, err)
				}
			})
		}
	}
}

func TestPublicBridgeRejectsInitialPrivilegedAccount(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	region, root := startupControllerBroker(t, ctx)
	claim := root.InitialCellJWT()
	if err := root.ApplyCellClaim(ctx, 1, claim); err != nil {
		t.Fatal(err)
	}
	if err := root.Bridge().OpenUntil(1, claim, time.Now().Add(15*time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{region.cfg.Embedded.SystemCredentialsFile, startupMembershipCredentials(t, region)} {
		cfg := region.cfg
		cfg.Embedded, cfg.URL, cfg.CredentialsFile = nil, root.URL(), path
		if client, err := Start(ctx, cfg); err == nil {
			_ = client.Close()
			t.Fatal("public bridge admitted a privileged account")
		} else if !errors.Is(err, nats.ErrAuthorization) {
			t.Fatalf("privileged account was not rejected by native authentication: %v", err)
		}
	}
	admin, err := root.OpenMembershipAdmin(startupMembershipCredentials(t, region))
	if err != nil {
		t.Fatalf("root's internal scoped membership handle failed: %v", err)
	}
	admin.Close()
	if err := root.systemConn.FlushWithContext(ctx); err != nil {
		t.Fatalf("root's internal SYSTEM handle failed: %v", err)
	}
}

func startupProtocolConnection(t *testing.T, ctx context.Context, region *testRegion, root *Runtime, transport string) (*tls.Conn, *bufio.Reader, string) {
	t.Helper()
	config, err := loadTLS(region.cfg.TLS, false)
	if err != nil {
		t.Fatal(err)
	}
	var raw net.Conn
	if transport == "private" {
		admitted, initial := net.Pipe()
		session, stop := context.WithCancel(ctx)
		done := make(chan error, 1)
		go func() { done <- root.ServeStartupController(session, admitted, time.Now().Add(5*time.Second)) }()
		t.Cleanup(func() {
			stop()
			select {
			case <-done:
			case <-ctx.Done():
				t.Error("private protocol session did not terminate")
			}
		})
		raw = initial
	} else {
		raw, err = (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "tcp", root.ClientAddress().String())
		if err != nil {
			t.Fatal(err)
		}
	}
	secured := tls.Client(raw, config)
	t.Cleanup(func() { _ = secured.Close() })
	if err := secured.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	if err := secured.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(secured)
	line, err := reader.ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "INFO ") {
		t.Fatalf("native INFO: %q %v", line, err)
	}
	var info struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "INFO "))), &info); err != nil || info.Nonce == "" {
		t.Fatalf("native nonce: %v", err)
	}
	return secured, reader, info.Nonce
}

func writeStartupConnect(t *testing.T, conn net.Conn, path, nonce string) {
	t.Helper()
	wire, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	raw, err := jwt.ParseDecoratedJWT(wire)
	if err != nil {
		t.Fatal(err)
	}
	pair, err := nkeys.ParseDecoratedUserNKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	defer pair.Wipe()
	signature, err := pair.Sign([]byte(nonce))
	if err != nil {
		t.Fatal(err)
	}
	connect, err := json.Marshal(struct {
		JWT     string `json:"jwt"`
		Sig     string `json:"sig"`
		Verbose bool   `json:"verbose"`
	}{JWT: raw, Sig: base64.RawURLEncoding.EncodeToString(signature)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := fmt.Fprintf(conn, "CONNECT %s\r\nPING\r\n", connect); err != nil {
		t.Fatal(err)
	}
}

func startupMembershipCredentials(t *testing.T, region *testRegion) string {
	t.Helper()
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	return testJWTUserCredentialsWithKey(t, t.TempDir(), "membership.creds", region.system, region.systemID, user,
		[]string{MembershipMetaStepdownSubject, MembershipServerRemoveSubject}, []string{inboxPrefix(region.cfg.Cell, public) + ".>"})
}

func broaderStartupControllerCredentials(t *testing.T, region *testRegion) string {
	t.Helper()
	wire, err := os.ReadFile(region.cfg.CredentialsFile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	user, err := nkeys.ParseDecoratedUserNKey(wire)
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	return testJWTUserCredentialsWithKey(t, t.TempDir(), "broader.creds", region.cell, region.cellID, user, []string{">"}, []string{">"})
}

func TestStartupControllerDeadlineClosesAuthenticatedConnection(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	region, root := startupControllerBroker(t, ctx)
	admitted, initial := net.Pipe()
	done := make(chan error, 1)
	deadline := time.Now().Add(2 * time.Second)
	go func() { done <- root.ServeStartupController(ctx, admitted, deadline) }()
	cfg := region.cfg
	cfg.URL = root.URL()
	client, err := StartControllerClient(ctx, cfg, initial)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	select {
	case err := <-done:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("private startup deadline: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("authenticated private connection outlived original deadline")
	}
	if err := client.Conn().FlushTimeout(100 * time.Millisecond); err == nil {
		t.Fatal("closed public gate admitted traffic after private startup expiry")
	}
	if root.Bridge().Status().Open {
		t.Fatal("private startup expiry opened the public gate")
	}
}

func TestStartupControllerSendsNoNATSBeforeTLSAndKeepsEarlierContextDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	_, root := startupControllerBroker(t, ctx)
	admitted, initial := net.Pipe()
	defer initial.Close()
	session, stop := context.WithTimeout(ctx, 100*time.Millisecond)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- root.ServeStartupController(session, admitted, time.Now().Add(10*time.Second)) }()
	if err := initial.SetReadDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	var first [1]byte
	if count, err := initial.Read(first[:]); count != 0 || err == nil {
		t.Fatal("private transport sent bytes before the client TLS handshake")
	} else if timeout, ok := errors.AsType[net.Error](err); ok && timeout.Timeout() {
		t.Fatal("private transport outlived the earlier original context deadline")
	}
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("private startup accepted a connection without TLS")
		}
	case <-ctx.Done():
		t.Fatal("earlier context expiry did not join the private handshake")
	}
}

func TestStartupControllerReconnectUsesExistingPublicGate(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	region, root := startupControllerBroker(t, ctx)
	admitted, initial := net.Pipe()
	session, stop := context.WithCancel(ctx)
	defer stop()
	done := make(chan error, 1)
	go func() { done <- root.ServeStartupController(session, admitted, time.Now().Add(10*time.Second)) }()
	cfg := region.cfg
	cfg.URL = root.URL()
	client, err := StartControllerClient(ctx, cfg, initial)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	conn, js := client.Conn(), client.JetStream()
	claim := root.InitialCellJWT()
	if err := root.ApplyCellClaim(ctx, 1, claim); err != nil {
		t.Fatal(err)
	}
	// This tests the native transport boundary; APP verifies the signed ticket.
	if err := root.Bridge().OpenUntil(1, claim, time.Now().Add(10*time.Second)); err != nil {
		t.Fatal(err)
	}
	stop()
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("initial private connection did not terminate")
	}
	for root.Bridge().Status().ActiveSessions != 1 || !conn.IsConnected() {
		select {
		case <-ctx.Done():
			t.Fatal("controller did not reconnect through the existing public bridge")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if client.Conn() != conn || client.JetStream() != js {
		t.Fatal("startup transition replaced the controller connection or JetStream handle")
	}
	if _, err := js.AccountInfo(ctx); err != nil {
		t.Fatalf("retained JetStream handle after gated reconnect: %v", err)
	}
}

func startupControllerBroker(t *testing.T, ctx context.Context) (*testRegion, *Runtime) {
	t.Helper()
	dir := t.TempDir()
	region := newTestRegion(t, dir, "gru", LeafTopology{Hub: "gru"})
	region.cfg.ClientRole = "controller"
	region.cfg.CredentialsFile = startupControllerCredentials(t, dir, region.cell, jwt.ConnectionTypeInProcess)
	root, err := Start(ctx, region.cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	return region, root
}

func startupControllerCredentials(t *testing.T, dir string, account nkeys.KeyPair, connectionType string) string {
	t.Helper()
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	public, _ := user.PublicKey()
	accountID, _ := account.PublicKey()
	claim := jwt.NewUserClaims(public)
	claim.IssuerAccount = accountID
	claim.AllowedConnectionTypes = jwt.StringList{connectionType}
	claim.Pub.Allow = ControllerPublishes("gru")
	claim.Pub.Deny = ControllerPublishDenials()
	claim.Sub.Allow = append(ControllerSubscriptions("gru"), inboxPrefix("gru", public)+".>")
	raw, err := claim.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	creds, err := jwt.FormatUserConfig(raw, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(creds)
	path := filepath.Join(dir, "startup-controller.creds")
	if err := os.WriteFile(path, creds, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

package natscell

import (
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func TestStartupControllerPrivateTLSAndInProcessAuthentication(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	region, root := startupControllerBroker(t, ctx)
	for _, name := range []string{"valid", "wrong-account", "wrong-connection-type", "wrong-tls"} {
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

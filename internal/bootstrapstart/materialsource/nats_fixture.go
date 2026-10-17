//go:build fixturetest

package materialsource

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

func assertSourceAuthenticatedNATS(t *testing.T, source *ColdStartMaterial, link *LinkSource, authority bootstrap.DerivedStartupAuthority) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	if err := authority.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	manifest := authority.Manifest()
	path := func(name string) string { return filepath.Join(source.directory, name) }
	files := natscell.TLSFiles{CAFile: path("ca.pem"), CertFile: path(manifest.Slot + "-tls-cert.pem"), KeyFile: path(manifest.Slot + "-tls-key.pem")}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	// One loopback broker isolates authentication; signed R3 configs stay unchanged.
	runtime, err := natscell.Start(ctx, natscell.Config{Cell: source.record.Config.Cell, Instance: manifest.Slot, Replicas: 1,
		ClientRole: "controller", CredentialsFile: path(manifest.Slot + ".creds"), TLS: files,
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: port, StoreDir: filepath.Join(t.TempDir(), "nats"),
			TLS: files, RouteTLS: files, OperatorJWTFile: path("operator.jwt"), SystemJWTFile: path("system.jwt"),
			CellJWTFile: filepath.Join(link.source.directory, "link-cell.jwt"), SystemCredentialsFile: path("system.creds"),
			TicketPublicKeyFile: path("ticket.pub"), BrokerIDs: []string{manifest.Slot}}})
	if err != nil {
		t.Fatalf("same-source embedded NATS: %v", err)
	}
	defer runtime.Close()
	if err := authority.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	closeTicket := assertSourceBrokerTicket(t, ctx, source, runtime, authority)
	defer closeTicket()
	pair, err := tls.LoadX509KeyPair(files.CertFile, files.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := os.ReadFile(files.CAFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		t.Fatal("same-source CA did not parse")
	}
	credentials, err := os.ReadFile(path(manifest.Slot + ".creds"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credentials)
	wire, err := nkeys.ParseDecoratedJWT(credentials)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := jwt.DecodeUserClaims(wire)
	if err != nil {
		t.Fatal(err)
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{Timeout: time.Second}, Config: &tls.Config{MinVersion: tls.VersionTLS13,
		RootCAs: roots, Certificates: []tls.Certificate{pair}, ServerName: manifest.Slot}}
	options := []nats.Option{nats.NoReconnect(), nats.Timeout(2 * time.Second), nats.SetCustomDialer(dialer),
		nats.CustomInboxPrefix(protocol.InboxPrefix(source.record.Config.Cell, claims.Subject))}
	client, err := nats.Connect(runtime.URL(), append(options, nats.UserCredentials(path(manifest.Slot+".creds")))...)
	if err != nil {
		t.Fatalf("same-source authenticated TCP connection: %v", err)
	}
	defer client.Close()
	subject := protocol.Regional(source.record.Config.Cell, "query", "source-boundary")
	subscription, err := runtime.Conn().Subscribe(subject, func(message *nats.Msg) { _ = message.Respond(message.Data) })
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Unsubscribe()
	if err := runtime.Conn().FlushWithContext(ctx); err != nil {
		t.Fatal(err)
	}
	payload := []byte("sealed-source-tcp")
	reply, err := client.RequestWithContext(ctx, subject, payload)
	if err != nil || !bytes.Equal(reply.Data, payload) {
		t.Fatalf("same-source NATS TCP request/reply: %v", err)
	}
	unauthenticated, err := nats.Connect(runtime.URL(), options...)
	if unauthenticated != nil {
		unauthenticated.Close()
	}
	if !errors.Is(err, nats.ErrAuthorization) {
		t.Fatalf("mutual TLS without source JWT was not denied: %v", err)
	}
}

func assertSourceBrokerTicket(t *testing.T, ctx context.Context, source *ColdStartMaterial, runtime *natscell.Runtime, startup bootstrap.DerivedStartupAuthority) func() {
	t.Helper()
	if err := source.verifySource(ctx); err != nil {
		t.Fatal(err)
	}
	wire, err := os.ReadFile(filepath.Join(source.directory, "ticket.key"))
	if err != nil {
		t.Fatal(err)
	}
	defer clear(wire)
	private, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(wire)))
	if err != nil || len(private) != ed25519.PrivateKeySize {
		t.Fatal("original source broker ticket key is invalid")
	}
	defer clear(private)
	public, err := base64.StdEncoding.DecodeString(source.record.Public.TicketSignerPublicKey)
	if err != nil || len(public) != ed25519.PublicKeySize || !bytes.Equal(ed25519.PrivateKey(private).Public().(ed25519.PublicKey), public) {
		t.Fatal("original broker ticket signer changed its signed public key")
	}
	clock := brokerauth.KernelClockProbe{}
	manifest := startup.Manifest()
	control, err := authority.Start(ctx, runtime.JetStream(), authority.Config{Scope: source.record.Config.Cell,
		DeploymentID: manifest.DeploymentID, CandidateID: entityid.New(), Replicas: 1,
		ClockCheck: func() error { _, err := brokerauth.MeasureHealthyClock(clock); return err }})
	if err != nil {
		t.Fatal(err)
	}
	store, err := brokerauth.OpenStore(ctx, runtime.JetStream(), source.record.Config.Cell, control)
	if err != nil {
		t.Fatal(err)
	}
	claim, err := store.Commit(ctx, control.Current().Epoch, runtime.CellAccount(), runtime.InitialCellJWT(), 0)
	if err != nil {
		t.Fatal(err)
	}
	// Ticket issuance requires a real renewed lease after the durable claim.
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for control.Current().Revision <= claim.Sequence {
		select {
		case <-ctx.Done():
			t.Fatal(ctx.Err())
		case <-ticker.C:
		}
	}
	issuer := brokerauth.Issuer{Store: store, Account: runtime.CellAccount(),
		Brokers: map[string]struct{}{manifest.Slot: {}}, Key: ed25519.PrivateKey(private), Clock: clock}
	subject := protocol.Broker(source.record.Config.Cell, "ticket", control.Current().CandidateID)
	subscription, err := runtime.Conn().Subscribe(subject, func(message *nats.Msg) {
		if len(message.Data) == 0 || len(message.Data) > 4096 || message.Reply == "" {
			return
		}
		var request brokerauth.TicketRequest
		if json.Unmarshal(message.Data, &request, json.RejectUnknownMembers(true)) != nil {
			return
		}
		signed, err := issuer.Issue(ctx, request)
		if err != nil {
			return
		}
		response, err := json.Marshal(signed)
		if err == nil {
			_ = message.Respond(response)
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer subscription.Unsubscribe()
	if err := runtime.Conn().FlushWithContext(ctx); err != nil {
		t.Fatal(err)
	}
	request, err := brokerauth.NewRequest(source.record.Config.Cell, manifest.Slot, runtime.CellAccount())
	if err != nil {
		t.Fatal(err)
	}
	requestWire, err := json.Marshal(request)
	if err != nil {
		t.Fatal(err)
	}
	requestCtx, cancel := context.WithTimeout(ctx, brokerauth.MaxTicketRoundTrip)
	defer cancel()
	started := time.Now()
	reply, err := runtime.Conn().RequestWithContext(requestCtx, subject, requestWire)
	finished := time.Now()
	if err != nil || len(reply.Data) == 0 || len(reply.Data) > brokerauth.MaxTicketWireBytes {
		t.Fatalf("original-source broker ticket request: %v", err)
	}
	var signed brokerauth.SignedTicket
	if err := json.Unmarshal(reply.Data, &signed, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	claim, err = store.Read(ctx, runtime.CellAccount())
	if err != nil {
		t.Fatal(err)
	}
	lease, err := authority.Observe(ctx, runtime.JetStream(), source.record.Config.Cell)
	if err != nil {
		t.Fatal(err)
	}
	if err := startup.VerifyCurrent(ctx, time.Now().UTC()); err != nil {
		t.Fatal(err)
	}
	bound, err := brokerauth.MeasureHealthyClock(clock)
	if err != nil {
		t.Fatal(err)
	}
	_, deadline, err := brokerauth.VerifyTicket(signed, ed25519.PublicKey(public), request, started, finished, bound, claim, lease)
	if err != nil {
		t.Fatal(err)
	}
	verifiedAt := time.Now()
	sourceDeadline := verifiedAt.Add(startup.ExpiresAt().Sub(verifiedAt.Add(bound.MaxError)))
	if sourceDeadline.Before(deadline) {
		deadline = sourceDeadline
	}
	if err := runtime.Bridge().OpenUntil(claim.Sequence, claim.JWT, deadline); err != nil {
		t.Fatal(err)
	}
	t.Log("original-source broker ticket issued over NATS, durable claim/lease verified and monotonic bridge deadline applied; one-broker fixture only")
	return func() { _ = control.Close() }
}

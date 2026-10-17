//go:build fixturetest

package materialsource

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
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
	if err := runtime.Bridge().OpenUntil(source.grant.Generation(), runtime.InitialCellJWT(), authority.ExpiresAt()); err != nil {
		t.Fatal(err)
	}
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

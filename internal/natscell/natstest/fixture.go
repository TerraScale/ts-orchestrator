// Package natstest supplies production JWT and mutual TLS brokers to integration tests.
package natstest

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// NATSFixture retains the issuer and CA across broker restarts and external clients.
type NATSFixture struct {
	root, cell, cellID, cellJWT                           string
	account                                               nkeys.KeyPair
	tls                                                   natscell.TLSFiles
	operatorFile, systemFile, cellFile, systemCredentials string
	ticketPublicFile, routePassword                       string
	brokers                                               []string
}

// NATS shares one issuer and CA across the named brokers and their clients.
func NATS(t *testing.T, cell string, brokers ...string) *NATSFixture {
	t.Helper()
	a := &NATSFixture{root: t.TempDir(), cell: cell, brokers: slices.Clone(brokers)}
	a.tls = fixtureTLS(t, a.root)
	operator, err := nkeys.CreateOperator()
	if err != nil {
		t.Fatal(err)
	}
	defer operator.Wipe()
	system, err := nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	defer system.Wipe()
	a.account, err = nkeys.CreateAccount()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(a.account.Wipe)
	operatorID, _ := operator.PublicKey()
	systemID, _ := system.PublicKey()
	a.cellID, _ = a.account.PublicKey()
	operatorClaim := jwt.NewOperatorClaims(operatorID)
	operatorClaim.SystemAccount = systemID
	operatorJWT, err := operatorClaim.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	systemJWT, err := jwt.NewAccountClaims(systemID).Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	cellClaim := jwt.NewAccountClaims(a.cellID)
	cellClaim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 256 << 20, DiskStorage: 8 << 30, Streams: 100, Consumer: 100}
	a.cellJWT, err = cellClaim.Encode(operator)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, raw string) string { return a.write(t, name, []byte(raw)) }
	a.operatorFile = write("operator.jwt", operatorJWT)
	a.systemFile = write("system.jwt", systemJWT)
	a.cellFile = write("cell.jwt", a.cellJWT)
	systemUser, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer systemUser.Wipe()
	systemPublic, err := systemUser.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	systemClaim := jwt.NewUserClaims(systemPublic)
	systemClaim.Pub.Allow = jwt.StringList{"$SYS.REQ.ACCOUNT." + a.cellID + ".CLAIMS.UPDATE"}
	systemClaim.Sub.Allow = jwt.StringList{protocol.InboxGrant(cell, systemPublic)}
	a.systemCredentials = a.credentials(t, "system.creds", system, systemUser, systemClaim)
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clear(private)
	a.ticketPublicFile = write("ticket.pub", base64.StdEncoding.EncodeToString(public))
	a.routePassword = write("route-password", rand.Text())
	return a
}

// Config retains the client identity and topology while issuing role-scoped credentials.
func (a *NATSFixture) Config(t *testing.T, cfg natscell.Config) natscell.Config {
	t.Helper()
	if cfg.Cell != "" && cfg.Cell != a.cell {
		t.Fatalf("fixture cell %q differs from client cell %q", a.cell, cfg.Cell)
	}
	cfg.Cell = a.cell
	if cfg.Instance == "" {
		cfg.Instance = "one"
	}
	if cfg.Replicas == 0 {
		cfg.Replicas = 1
	}
	role := cfg.ClientRole
	if role == "" {
		role = "controller"
	}
	var user nkeys.KeyPair
	var err error
	if cfg.NKeySeedFile != "" {
		seed, readErr := os.ReadFile(cfg.NKeySeedFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		user, err = nkeys.FromSeed(seed)
		clear(seed)
	} else if cfg.CredentialsFile != "" {
		credentials, readErr := os.ReadFile(cfg.CredentialsFile)
		if readErr != nil {
			t.Fatal(readErr)
		}
		user, err = nkeys.ParseDecoratedUserNKey(credentials)
		clear(credentials)
	} else {
		user, err = nkeys.CreateUser()
	}
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	claim := jwt.NewUserClaims(public)
	claim.IssuerAccount = a.cellID
	claim.Sub.Allow = jwt.StringList{protocol.InboxPrefix(a.cell, public) + ".>"}
	switch role {
	case "controller":
		claim.Pub.Allow = natscell.ControllerPublishes(a.cell)
		claim.Pub.Allow.Add("$JS.ACK.>")
		claim.Sub.Allow.Add(natscell.ControllerSubscriptions(a.cell)...)
		claim.Sub.Allow.Add(protocol.ObservabilityGrant(a.cell), protocol.Broker(a.cell, "ticket", ">"), protocol.Broker(a.cell, "fence", cfg.Instance))
		claim.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}
	case "operator":
		claim.Pub.Allow = natscell.BrokerOperatorPublishPermissions(a.cell)
	case "host":
		claim.Pub.Allow = jwt.StringList{protocol.AgentObservation(a.cell, public, "*")}
	default:
		t.Fatalf("unsupported authenticated fixture role %q", role)
	}
	cfg.CredentialsFile = a.credentials(t, cfg.Instance+"-"+public+".creds", a.account, user, claim)
	cfg.NKeySeedFile = ""
	cfg.TLS = a.tls
	cfg.URL = strings.ReplaceAll(cfg.URL, "nats://", "tls://")
	if cfg.Embedded != nil {
		embedded := *cfg.Embedded
		cfg.Embedded = &embedded
		embedded.Users = nil
		embedded.TLS, embedded.RouteTLS = a.tls, a.tls
		embedded.RouteUser, embedded.RoutePasswordFile = "integration-route", a.routePassword
		embedded.OperatorJWTFile, embedded.SystemJWTFile, embedded.CellJWTFile = a.operatorFile, a.systemFile, a.cellFile
		embedded.SystemCredentialsFile, embedded.TicketPublicKeyFile = a.systemCredentials, a.ticketPublicFile
		embedded.BrokerIDs = slices.Clone(a.brokers)
		if len(embedded.BrokerIDs) == 0 {
			embedded.BrokerIDs = []string{cfg.Instance}
		}
		if embedded.StoreDir == "" {
			embedded.StoreDir = filepath.Join(a.root, cfg.Instance)
		}
		if embedded.Host == "" {
			embedded.Host = "127.0.0.1"
		}
		if embedded.Port == 0 {
			embedded.Port = -1
		}
		if err := natscell.ValidateProductionCredentials(cfg); err != nil {
			t.Fatalf("fixture production credentials: %v", err)
		}
	}
	return cfg
}

// Start opens a real broker bridge with its signed account claim.
func (a *NATSFixture) Start(t *testing.T, ctx context.Context, cfg natscell.Config) (*natscell.Runtime, error) {
	t.Helper()
	runtime, err := natscell.Start(ctx, a.Config(t, cfg))
	if err != nil {
		return nil, err
	}
	t.Cleanup(func() { _ = runtime.Close() })
	if cfg.Embedded != nil {
		if err := runtime.ApplyCellClaim(ctx, 1, a.cellJWT); err != nil {
			return nil, fmt.Errorf("apply fixture claim: %w", err)
		}
		if err := runtime.Bridge().OpenUntil(1, a.cellJWT, time.Now().Add(5*time.Minute)); err != nil {
			return nil, fmt.Errorf("open fixture bridge: %w", err)
		}
	}
	return runtime, nil
}

// Observer can receive only the named subjects and its private inbox; it cannot publish.
func (a *NATSFixture) Observer(t *testing.T, endpoint string, subjects ...string) *nats.Conn {
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
	claim := jwt.NewUserClaims(public)
	claim.IssuerAccount = a.cellID
	claim.Pub.Deny = jwt.StringList{">"}
	claim.Sub.Allow = append(jwt.StringList{protocol.InboxGrant(a.cell, public)}, subjects...)
	credentials := a.credentials(t, public+".creds", a.account, user, claim)
	connection, err := nats.Connect(strings.ReplaceAll(endpoint, "nats://", "tls://"),
		nats.UserCredentials(credentials), nats.RootCAs(a.tls.CAFile), nats.ClientCert(a.tls.CertFile, a.tls.KeyFile),
		nats.CustomInboxPrefix(protocol.InboxPrefix(a.cell, public)), nats.TLSHandshakeFirst(), nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	return connection
}

func (a *NATSFixture) credentials(t *testing.T, name string, account, user nkeys.KeyPair, claim *jwt.UserClaims) string {
	t.Helper()
	raw, err := claim.Encode(account)
	if err != nil {
		t.Fatal(err)
	}
	seed, err := user.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(seed)
	credentials, err := jwt.FormatUserConfig(raw, seed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(credentials)
	return a.write(t, name, credentials)
}

func (a *NATSFixture) write(t *testing.T, name string, raw []byte) string {
	t.Helper()
	path := filepath.Join(a.root, name)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func fixtureTLS(t *testing.T, root string) natscell.TLSFiles {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "integration CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "integration broker"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), DNSNames: []string{"localhost"},
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	write := func(name, kind string, raw []byte) string {
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: kind, Bytes: raw}), 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	return natscell.TLSFiles{CAFile: write("ca.pem", "CERTIFICATE", caDER),
		CertFile: write("client.pem", "CERTIFICATE", leafDER), KeyFile: write("client-key.pem", "EC PRIVATE KEY", keyDER)}
}

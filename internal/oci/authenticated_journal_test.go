package oci

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
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func authenticatedJournalConfig(t *testing.T, instance string) natscell.Config {
	t.Helper()
	const cell = "lab"
	root := t.TempDir()
	write := func(name string, wire []byte) string {
		t.Helper()
		path := filepath.Join(root, name)
		if err := os.WriteFile(path, wire, 0o600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	key := func(kind nkeys.PrefixByte) (nkeys.KeyPair, string) {
		t.Helper()
		pair, err := nkeys.CreatePair(kind)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(pair.Wipe)
		public, err := pair.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		return pair, public
	}
	operator, operatorID := key(nkeys.PrefixByteOperator)
	system, systemID := key(nkeys.PrefixByteAccount)
	account, accountID := key(nkeys.PrefixByteAccount)
	claimFile := func(name string, claim jwt.Claims, signer nkeys.KeyPair) string {
		t.Helper()
		wire, err := claim.Encode(signer)
		if err != nil {
			t.Fatal(err)
		}
		return write(name, []byte(wire))
	}
	credentials := func(name string, user, signer nkeys.KeyPair, claim *jwt.UserClaims) string {
		t.Helper()
		wire, err := claim.Encode(signer)
		if err != nil {
			t.Fatal(err)
		}
		seed, err := user.Seed()
		if err != nil {
			t.Fatal(err)
		}
		defer clear(seed)
		creds, err := jwt.FormatUserConfig(wire, seed)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(creds)
		return write(name, creds)
	}
	operatorClaim := jwt.NewOperatorClaims(operatorID)
	operatorClaim.SystemAccount = systemID
	accountClaim := jwt.NewAccountClaims(accountID)
	accountClaim.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: 64 << 20, DiskStorage: 256 << 20, Streams: 10, Consumer: 10}
	systemUser, systemUserID := key(nkeys.PrefixByteUser)
	systemClaim := jwt.NewUserClaims(systemUserID)
	systemClaim.IssuerAccount = systemID
	systemClaim.Pub.Allow = jwt.StringList{"$SYS.REQ.ACCOUNT." + accountID + ".CLAIMS.UPDATE"}
	systemClaim.Sub.Allow = jwt.StringList{protocol.InboxPrefix(cell, systemUserID) + ".>"}
	controller, controllerID := key(nkeys.PrefixByteUser)
	controllerClaim := jwt.NewUserClaims(controllerID)
	controllerClaim.IssuerAccount = accountID
	controllerClaim.Pub.Allow = natscell.ControllerPublishes(cell)
	controllerClaim.Pub.Allow.Add("$JS.ACK.>")
	controllerClaim.Sub.Allow = jwt.StringList{protocol.InboxPrefix(cell, controllerID) + ".>"}
	controllerClaim.Sub.Allow.Add(natscell.ControllerSubscriptions(cell)...)
	controllerClaim.Sub.Allow.Add(protocol.Broker(cell, "ticket", ">"), protocol.Broker(cell, "fence", instance))
	controllerClaim.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "OCI journal test CA"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	peerKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer := &x509.Certificate{SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "OCI journal test peer"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	peerDER, err := x509.CreateCertificate(rand.Reader, peer, ca, &peerKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(peerKey)
	if err != nil {
		t.Fatal(err)
	}
	tlsFiles := natscell.TLSFiles{
		CAFile:   write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		CertFile: write("peer.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: peerDER})),
		KeyFile:  write("peer-key.pem", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
	}
	ticketPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	cfg := natscell.Config{Cell: cell, Instance: instance, Replicas: 1, TLS: tlsFiles,
		CredentialsFile: credentials("controller.creds", controller, account, controllerClaim),
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: port, StoreDir: filepath.Join(root, "jetstream"),
			TLS: tlsFiles, RouteTLS: tlsFiles, OperatorJWTFile: claimFile("operator.jwt", operatorClaim, operator),
			SystemJWTFile:         claimFile("system.jwt", jwt.NewAccountClaims(systemID), operator),
			CellJWTFile:           claimFile("cell.jwt", accountClaim, operator),
			SystemCredentialsFile: credentials("system.creds", systemUser, system, systemClaim),
			TicketPublicKeyFile:   write("ticket.pub", []byte(base64.StdEncoding.EncodeToString(ticketPublic))), BrokerIDs: []string{instance}}}
	if err := natscell.ValidateProductionCredentials(cfg); err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Journal traffic crosses the production JWT/mutual-TLS bridge, including after disk restart.
type authenticatedJournalRuntime struct {
	*natscell.Runtime
	broker *natscell.Runtime
}

func (r *authenticatedJournalRuntime) Close() error {
	return errors.Join(r.Runtime.Close(), r.broker.Close())
}

func startAuthenticatedJournal(ctx context.Context, cfg natscell.Config) (_ *authenticatedJournalRuntime, err error) {
	broker, err := natscell.Start(ctx, cfg)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err != nil {
			_ = broker.Close()
		}
	}()
	claim := broker.InitialCellJWT()
	if err = broker.ApplyCellClaim(ctx, 1, claim); err != nil {
		return nil, err
	}
	if err = broker.Bridge().OpenUntil(1, claim, time.Now().Add(5*time.Minute)); err != nil {
		return nil, err
	}
	cfg.URL, cfg.Embedded = broker.URL(), nil
	client, err := natscell.Start(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &authenticatedJournalRuntime{Runtime: client, broker: broker}, nil
}

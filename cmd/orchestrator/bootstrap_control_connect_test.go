package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrap"
)

func TestBootstrapAuthorityStoreConnectsAfterConstructionContextEnds(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}, IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(cert)
	stores := map[string]bootstrap.ControlNATSStore{}
	for _, name := range []string{"hosts", "authority"} {
		broker, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}}}})
		if err != nil {
			t.Fatal(err)
		}
		go broker.Start()
		t.Cleanup(broker.Shutdown)
		if !broker.ReadyForConnections(5 * time.Second) {
			t.Fatal("broker startup timeout")
		}
		stores[name] = bootstrap.ControlNATSStore{URL: broker.ClientURL(), Options: []nats.Option{nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots})}}
	}
	owner := &bootstrapControlProvider{}
	defer owner.Close()
	connections := map[string]*nats.Conn{}
	connect := newBootstrapStoreConnector(stores, connections, owner)
	construction, finishConstruction := context.WithCancel(context.Background())
	host, err := connect(construction, "hosts")
	if err != nil {
		t.Fatal(err)
	}
	finishConstruction()
	operation, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	authority, err := connect(operation, "authority")
	if err != nil {
		t.Fatalf("lazy authority connection inherited canceled construction: %v", err)
	}
	if host == authority {
		t.Fatal("distinct stores reused host connection")
	}
	if err := authority.Flush(); err != nil {
		t.Fatal(err)
	}
}

func TestBootstrapStoreConnectionCancelsProtocolHandshake(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		connection, err := listener.Accept()
		if err == nil {
			accepted <- connection
		}
	}()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := dialBootstrapStore(ctx, bootstrap.ControlNATSStore{URL: "nats://" + listener.Addr().String()})
		result <- err
	}()
	select {
	case connection := <-accepted:
		defer connection.Close()
	case <-time.After(time.Second):
		t.Fatal("dial not attempted")
	}
	cancel()
	select {
	case err := <-result:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("protocol handshake ignored caller cancellation")
	}
}

package placement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

// Placement scenarios use signed regional accounts and verified TLS material.
func placementTestBrokerConfig(t *testing.T, instance string) natscell.Config {
	t.Helper()
	now := time.Now().UTC()
	directory := t.TempDir()
	path := func(name string) string { return filepath.Join(directory, name) }
	write := func(name string, data []byte) string {
		t.Helper()
		if err := os.WriteFile(path(name), data, 0o600); err != nil {
			t.Fatal(err)
		}
		return path(name)
	}
	newKey := func(create func() (nkeys.KeyPair, error)) (nkeys.KeyPair, string) {
		t.Helper()
		key, err := create()
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(key.Wipe)
		public, err := key.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		return key, public
	}
	operatorKey, operatorID := newKey(nkeys.CreateOperator)
	systemKey, systemID := newKey(nkeys.CreateAccount)
	cellKey, cellID := newKey(nkeys.CreateAccount)
	encode := func(name string, claim interface {
		Encode(nkeys.KeyPair) (string, error)
	}, signer nkeys.KeyPair) string {
		t.Helper()
		raw, err := claim.Encode(signer)
		if err != nil {
			t.Fatal(err)
		}
		return write(name, []byte(raw))
	}
	operator := jwt.NewOperatorClaims(operatorID)
	operator.SystemAccount = systemID
	operator.Expires = now.Add(time.Hour).Unix()
	system := jwt.NewAccountClaims(systemID)
	system.Expires = operator.Expires
	cell := jwt.NewAccountClaims(cellID)
	cell.Expires = operator.Expires
	cell.Limits.JetStreamLimits = jwt.JetStreamLimits{MemoryStorage: jwt.NoLimit, DiskStorage: jwt.NoLimit,
		Streams: jwt.NoLimit, Consumer: jwt.NoLimit}
	credentials := func(name string, account nkeys.KeyPair, controller bool) string {
		t.Helper()
		user, public := newKey(nkeys.CreateUser)
		claim := jwt.NewUserClaims(public)
		claim.Expires = operator.Expires
		claim.Sub.Allow = jwt.StringList{protocol.InboxGrant("gru", public)}
		if controller {
			claim.Pub.Allow = natscell.ControllerPublishes("gru")
			claim.Pub.Allow.Add(natscell.GlobalControllerPublishes()...)
			claim.Sub.Allow.Add(protocol.Broker("gru", "ticket", ">"), protocol.Broker("gru", "fence", instance))
			claim.Sub.Allow.Add(natscell.ControllerSubscriptions("gru")...)
			claim.Sub.Allow.Add(protocol.ObservabilityGrant("gru"))
			claim.Resp = &jwt.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}
		} else {
			claim.Pub.Allow = jwt.StringList{"$SYS.REQ.ACCOUNT." + cellID + ".CLAIMS.UPDATE"}
		}
		raw, err := claim.Encode(account)
		if err != nil {
			t.Fatal(err)
		}
		seed, err := user.Seed()
		if err != nil {
			t.Fatal(err)
		}
		defer clear(seed)
		data, err := jwt.FormatUserConfig(raw, seed)
		if err != nil {
			t.Fatal(err)
		}
		defer clear(data)
		return write(name, data)
	}
	observerKey, observerID := newKey(nkeys.CreateUser)
	observer := jwt.NewUserClaims(observerID)
	observer.Expires = operator.Expires
	observer.Pub.Deny = jwt.StringList{">"}
	for _, prefix := range []string{"$JS.API", "$JS.gru.API"} {
		observer.Sub.Allow.Add(prefix+".STREAM.MSG.GET.KV_"+stateBucketName, prefix+".DIRECT.GET.>")
	}
	observerJWT, err := observer.Encode(cellKey)
	if err != nil {
		t.Fatal(err)
	}
	observerSeed, err := observerKey.Seed()
	if err != nil {
		t.Fatal(err)
	}
	defer clear(observerSeed)
	observerCredentials, err := jwt.FormatUserConfig(observerJWT, observerSeed)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(observerCredentials)
	write("observer.creds", observerCredentials)
	caPublic, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(caKey)
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign}
	caDER, err := x509.CreateCertificate(rand.Reader, ca, ca, caPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	leafPublic, leafKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(leafKey)
	leaf := &x509.Certificate{SerialNumber: big.NewInt(2), NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, leafPublic, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyDER)
	tls := natscell.TLSFiles{
		CAFile:   write("ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})),
		CertFile: write("broker-cert.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})),
		KeyFile:  write("broker-key.pem", pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})),
	}
	public, ticketKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clear(ticketKey)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	config := natscell.Config{Cell: "gru", Instance: instance, Replicas: 1, TLS: tls, CredentialsFile: credentials("controller.creds", cellKey, true),
		Embedded: &natscell.Embedded{Host: "127.0.0.1", Port: port, StoreDir: path("nats"), TLS: tls, RouteTLS: tls,
			OperatorJWTFile: encode("operator.jwt", operator, operatorKey), SystemJWTFile: encode("system.jwt", system, operatorKey),
			CellJWTFile: encode("cell.jwt", cell, operatorKey), SystemCredentialsFile: credentials("system.creds", systemKey, false),
			TicketPublicKeyFile: write("ticket.pub", []byte(base64.StdEncoding.EncodeToString(public))), BrokerIDs: []string{instance}}}
	if err := natscell.ValidateProductionCredentials(config); err != nil {
		t.Fatal(err)
	}
	return config
}

func TestListMembersReadsOnlyRequestedPartitionSeats(t *testing.T) {
	state := validMemberStateForPins(t)
	data, err := protocol.EncodeJSON(state)
	if err != nil {
		t.Fatal(err)
	}
	key := memberStateKey(state.DatabaseID, state.PartitionID, state.MemberID)
	kv := &partitionLookupKV{entry: fixedMemberEntry{key: key, value: data, revision: 9}}
	store := &jetStreamStore{state: kv}
	members, err := store.ListMembers(t.Context(), state.DatabaseID, state.PartitionID)
	if err != nil || len(members) != 1 || !reflect.DeepEqual(members[0].State, state) {
		t.Fatalf("partition members = %+v, %v", members, err)
	}
	if kv.reads != len(regionsInOrder)*SeatsPerRegion {
		t.Fatalf("partition lookup made %d reads", kv.reads)
	}
}

type partitionLookupKV struct {
	jetstream.KeyValue
	entry fixedMemberEntry
	reads int
}

func (kv *partitionLookupKV) Get(_ context.Context, key string) (jetstream.KeyValueEntry, error) {
	kv.reads++
	if key != kv.entry.key {
		return nil, jetstream.ErrKeyNotFound
	}
	return kv.entry, nil
}

type fixedMemberEntry struct {
	key      string
	value    []byte
	revision uint64
}

func (entry fixedMemberEntry) Bucket() string                  { return stateBucketName }
func (entry fixedMemberEntry) Key() string                     { return entry.key }
func (entry fixedMemberEntry) Value() []byte                   { return entry.value }
func (entry fixedMemberEntry) Revision() uint64                { return entry.revision }
func (entry fixedMemberEntry) Created() time.Time              { return time.Unix(1, 0).UTC() }
func (entry fixedMemberEntry) Delta() uint64                   { return 0 }
func (entry fixedMemberEntry) Operation() jetstream.KeyValueOp { return jetstream.KeyValuePut }

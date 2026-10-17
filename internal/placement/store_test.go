package placement

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
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

// A separate read-only user observes requests the production controller cannot subscribe to.
func placementTestObserver(t *testing.T, runtime *natscell.Runtime, config natscell.Config) *nats.Conn {
	t.Helper()
	read := func(path string) []byte {
		t.Helper()
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	certificate, err := tls.LoadX509KeyPair(config.TLS.CertFile, config.TLS.KeyFile)
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(read(config.TLS.CAFile)) {
		t.Fatal("observer CA is invalid")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	t.Cleanup(cancel)
	deadline, _ := ctx.Deadline()
	if err := runtime.Bridge().OpenUntil(1, string(read(config.Embedded.CellJWTFile)), deadline); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(runtime.Bridge().Fence)
	credentials := read(filepath.Join(filepath.Dir(config.CredentialsFile), "observer.creds"))
	defer clear(credentials)
	connection, err := natscell.ConnectMemory(ctx, "gru", runtime.ClientAddress().String(), credentials,
		&tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, Certificates: []tls.Certificate{certificate}})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(connection.Close)
	return connection
}

func TestMemberPinReaderOpensExistingDurableStateWithoutWrites(t *testing.T) {
	config := placementTestBrokerConfig(t, "member-reader")
	runtime, err := natscell.Start(t.Context(), config)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = runtime.Close() })
	observer := placementTestObserver(t, runtime, config)
	js := runtime.JetStream()
	options := js.Options()
	prefix := strings.TrimSuffix(options.APIPrefix, ".")
	if options.Domain != "" {
		prefix = "$JS." + options.Domain + ".API"
	} else if prefix == "" {
		prefix = "$JS.API"
	}
	leader, err := observer.SubscribeSync(prefix + ".STREAM.MSG.GET.KV_" + stateBucketName)
	if err != nil {
		t.Fatal(err)
	}
	defer leader.Unsubscribe()
	direct, err := observer.SubscribeSync(prefix + ".DIRECT.GET.>")
	if err != nil {
		t.Fatal(err)
	}
	defer direct.Unsubscribe()
	if err := observer.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMemberPinReader(t.Context(), js, "gru", 1); err == nil {
		t.Fatal("member reader opened an absent bucket")
	}
	if _, err := js.KeyValue(t.Context(), stateBucketName); err == nil {
		t.Fatal("member reader created an absent bucket")
	}
	kv, err := js.CreateKeyValue(t.Context(), jetstream.KeyValueConfig{Bucket: stateBucketName, History: 2,
		MaxValueSize: maxStateBytes, Storage: jetstream.FileStorage, Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	state := validMemberStateForPins(t)
	wire, err := protocol.EncodeJSON(state)
	if err != nil {
		t.Fatal(err)
	}
	revision, err := kv.Put(t.Context(), memberStateKey(state.DatabaseID, state.PartitionID, state.MemberID), wire)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := OpenMemberPinReader(t.Context(), js, "gru", 1)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := reader.(Store); ok {
		t.Fatal("member pin reader exposes placement mutations")
	}
	member, err := reader.ReadMember(t.Context(), state.DatabaseID, state.PartitionID, state.MemberID)
	if err != nil || member.Revision != revision || !reflect.DeepEqual(member.State, state) {
		t.Fatalf("read existing durable member = %+v, %v", member, err)
	}
	before, err := kv.Status(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenMemberPinReader(t.Context(), js, "gru", 2); err == nil {
		t.Fatal("member reader accepted weaker regional replicas")
	}
	after, err := kv.Status(t.Context())
	if err != nil || !reflect.DeepEqual(before.Config(), after.Config()) || before.Values() != after.Values() {
		t.Fatalf("member reader changed bucket configuration or values: %v", err)
	}
	state.HostAttempt++
	wire, err = protocol.EncodeJSON(state)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kv.Put(t.Context(), memberStateKey(state.DatabaseID, state.PartitionID, state.MemberID), wire); err != nil {
		t.Fatal(err)
	}
	member, err = reader.ReadMember(t.Context(), state.DatabaseID, state.PartitionID, state.MemberID)
	if err != nil || member.Revision <= revision || member.State.HostAttempt != state.HostAttempt {
		t.Fatalf("ordered member reader retained an old attempt: %+v, %v", member, err)
	}
	if err := kv.Delete(t.Context(), memberStateKey(state.DatabaseID, state.PartitionID, state.MemberID)); err != nil {
		t.Fatal(err)
	}
	if _, err := reader.ReadMember(t.Context(), state.DatabaseID, state.PartitionID, state.MemberID); !errors.Is(err, ErrStoreCorrupt) {
		t.Fatalf("ordered member reader accepted a tombstone: %v", err)
	}
	if err := observer.Flush(); err != nil {
		t.Fatal(err)
	}
	reads, _, err := leader.Pending()
	if err != nil {
		t.Fatal(err)
	}
	if count, _, err := direct.Pending(); err != nil || count != 0 || reads != 3 {
		t.Fatalf("member reader bypassed leader: leader=%d, direct=%d, error=%v", reads, count, err)
	}

	lookupIntent := validIntent(oci.RegionGRU)
	lookupIntent.PartitionID = "00000000001WFHC56Q8NB0X6T8"
	lookupState := testMemberState(t, committedTestIntent(t, lookupIntent), Seat{
		MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU,
		FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent,
	}, StagePreparedHost)
	lookupKey := memberStateKey(lookupState.DatabaseID, lookupState.PartitionID, lookupState.MemberID)
	if lookupKey == memberStateKey(state.DatabaseID, state.PartitionID, state.MemberID) {
		t.Fatal("fresh partition lookup reused the written member key")
	}
	if _, err := kv.Get(t.Context(), lookupKey); !errors.Is(err, jetstream.ErrKeyNotFound) {
		t.Fatalf("never-written native member key = %v, want ErrKeyNotFound", err)
	}
	lookupStore := &jetStreamStore{state: kv}
	if _, err := lookupStore.ReadMember(t.Context(), lookupState.DatabaseID, lookupState.PartitionID, lookupState.MemberID); !errors.Is(err, ErrMemberNotFound) {
		t.Fatalf("never-written exact member lookup = %v, want ErrMemberNotFound", err)
	}
	lookupWire, err := protocol.EncodeJSON(lookupState)
	if err != nil {
		t.Fatal(err)
	}
	lookupRevision, err := kv.Put(t.Context(), lookupKey, lookupWire)
	if err != nil {
		t.Fatal(err)
	}
	member, err = lookupStore.ReadMember(t.Context(), lookupState.DatabaseID, lookupState.PartitionID, lookupState.MemberID)
	if err != nil || member.Revision != lookupRevision || !reflect.DeepEqual(member.State, lookupState) {
		t.Fatalf("native exact member lookup = %+v, %v; want revision %d and original state", member, err, lookupRevision)
	}
	if err := observer.Flush(); err != nil {
		t.Fatal(err)
	}
	if count, _, err := direct.Pending(); err != nil || count != 3 {
		t.Fatalf("native exact member lookup requests = %d, %v; want 3", count, err)
	}
	wantSubject := prefix + ".DIRECT.GET.KV_" + stateBucketName + ".$KV." + stateBucketName + "." + lookupKey
	for range 3 {
		request, err := direct.NextMsgWithContext(t.Context())
		if err != nil || request.Subject != wantSubject {
			t.Fatalf("native exact member request = %+v, %v; want subject %q", request, err, wantSubject)
		}
	}
}

func TestMemberStateKeyIncludesPartitionIdentity(t *testing.T) {
	first := memberStateKey("0000000000JJVVW9EMWY1PE1VX", "0000000000Z3WK359G2W66CVT8", "000000000082AXF7GZQT1D126Y")
	second := memberStateKey("0000000000JJVVW9EMWY1PE1VX", "00000000001WFHC56Q8NB0X6T8", "000000000082AXF7GZQT1D126Y")
	if first == second {
		t.Fatalf("partition member keys collide: %q", first)
	}
	if !entityid.Valid(first) || !entityid.Valid(second) {
		t.Fatal("member keys must be plain ULIDs")
	}
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

func TestIntentListAllowsDifferentPartitionsButRejectsDuplicateCompositeIdentity(t *testing.T) {
	first := validIntent(oci.RegionGRU)
	first.PartitionID = "00000000001WFHC56Q8NB0X6T8"
	second := validIntent(oci.RegionGRU)
	second.PartitionID = "0000000000Z3WK359G2W66CVT8"
	first = committedIntentForTest(t, first)
	second = committedIntentForTest(t, second)
	reader := intentReaderFunc(func(context.Context, string) ([]Intent, error) {
		return []Intent{first, second}, nil
	})
	store := &jetStreamStore{cell: "gru", intents: reader}
	intents, err := store.ListIntents(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	want := []Intent{first, second}
	if !reflect.DeepEqual(intents, want) {
		t.Fatalf("partition intents = %#v, want %#v", intents, want)
	}

	store.intents = intentReaderFunc(func(context.Context, string) ([]Intent, error) {
		return []Intent{want[0], want[0]}, nil
	})
	if _, err := store.ListIntents(context.Background()); !errors.Is(err, ErrInvalidIntent) {
		t.Fatalf("duplicate composite identity error = %v, want ErrInvalidIntent", err)
	}
}

func TestIntentListRejectsUncommittedOrMalformedPayloadDigests(t *testing.T) {
	legacy := Intent{
		SchemaVersion: 1, DatabaseID: "0000000000AJ79CD84K5P2YR0E", PartitionID: "0000000000Z3WK359G2W66CVT8",
		ActiveRegions: []oci.Region{oci.RegionGRU}, Generation: 1,
	}
	managed := validIntent(oci.RegionGRU)
	malformedLegacy := legacy
	malformedLegacy.committedPayloadSHA = "not-a-digest"
	malformedManaged := managed
	malformedManaged.committedPayloadSHA = "not-a-digest"
	for _, test := range []struct {
		name   string
		intent Intent
	}{
		{name: "legacy missing digest", intent: legacy},
		{name: "managed missing digest", intent: managed},
		{name: "legacy malformed digest", intent: malformedLegacy},
		{name: "managed malformed digest", intent: malformedManaged},
	} {
		t.Run(test.name, func(t *testing.T) {
			store := &jetStreamStore{cell: "gru", intents: intentReaderFunc(func(context.Context, string) ([]Intent, error) {
				return []Intent{test.intent}, nil
			})}
			if _, err := store.ListIntents(context.Background()); !errors.Is(err, ErrInvalidIntent) {
				t.Fatalf("uncommitted placement intent list error = %v, want invalid intent", err)
			}
		})
	}
}

func committedIntentForTest(t *testing.T, intent Intent) Intent {
	t.Helper()
	payload, err := protocol.EncodeJSON(intent)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := DecodeCommittedIntent(payload)
	if err != nil {
		t.Fatal(err)
	}
	return committed
}

func (reader intentReaderFunc) ListPlacementIntents(ctx context.Context, cell string) ([]Intent, error) {
	return reader(ctx, cell)
}

func (intentReaderFunc) ReadTerminalIntent(context.Context, string, string) (authority.LogEntry, error) {
	return authority.LogEntry{}, authority.ErrNotFound
}

type intentReaderFunc func(context.Context, string) ([]Intent, error)

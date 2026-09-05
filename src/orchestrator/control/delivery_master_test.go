package control

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net"
	"os"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/contracts"
	"terrascale.tech/orchestrator/src/orchestrator/control/authority"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/estate"
	"terrascale.tech/orchestrator/src/orchestrator/natspolicy"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type masterMirrorFixture struct {
	mu         sync.Mutex
	body       []byte
	objects    map[string][]byte
	failRegion string
	beforePut  func() error
	puts       int
}

func (s *masterMirrorFixture) Put(context.Context, string, string, string, []byte) error {
	panic("unfenced mirror")
}
func (s *masterMirrorFixture) PutFenced(_ context.Context, region, _, _ string, body []byte, _ delivery.OperationFence) error {
	if s.beforePut != nil {
		if err := s.beforePut(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failRegion == region {
		return errors.New("fixture region unavailable")
	}
	if s.objects == nil {
		s.objects = map[string][]byte{}
	}
	s.objects[region] = append([]byte(nil), body...)
	s.body = append([]byte(nil), body...)
	s.puts++
	return nil
}
func (s *masterMirrorFixture) Get(ctx context.Context, region, bucket, object string) (io.ReadCloser, delivery.ObjectIdentity, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	body, ok := s.objects[region]
	if !ok {
		return nil, delivery.ObjectIdentity{}, errors.New("fixture object missing")
	}
	return io.NopCloser(bytes.NewReader(body)), delivery.ObjectIdentity{Digest: delivery.SHA256Digest(body), Size: int64(len(body))}, nil
}

func masterTestNATS(t *testing.T) (context.Context, *nats.Conn, jetstream.JetStream) {
	t.Helper()
	_, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "master-delivery-test"}, NotBefore: time.Now().Add(-time.Minute), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	if err != nil {
		t.Fatal(err)
	}
	private, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private}))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	roots.AddCert(parsed)
	identity, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	public, err := identity.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	instance, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoSigs: true, JetStream: true, StoreDir: t.TempDir(), MaxPayload: messaging.DeliveryOperationMaxMessageBytes, TLSConfig: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, ClientCAs: roots, ClientAuth: tls.RequireAndVerifyClientCert}, Nkeys: []*server.NkeyUser{{Nkey: public}}})
	if err != nil {
		t.Fatal(err)
	}
	instance.Start()
	t.Cleanup(func() { instance.Shutdown(); instance.WaitForShutdown() })
	if !instance.ReadyForConnections(time.Second) {
		t.Fatal("NATS not ready")
	}
	nc, err := nats.Connect(instance.ClientURL(), nats.Secure(&tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: roots}), nats.Nkey(public, identity.Sign), nats.NoReconnect())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(nc.Close)
	js, err := jetstream.New(nc)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	return ctx, nc, js
}
func masterTestKV(t *testing.T, ctx context.Context, js jetstream.JetStream, name string) jetstream.KeyValue {
	t.Helper()
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: name, Storage: jetstream.FileStorage, MaxValueSize: messaging.DeliveryOperationMaxValueBytes})
	if err != nil {
		t.Fatal(err)
	}
	return kv
}
func masterTestSigner(t *testing.T) (*security.CommandSignatureSigner, *security.CommandSignatureVerifier) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := security.NewCommandSignatureVerifierFromKeys([]security.CommandSignatureTrustKey{{KeyID: signer.PublicKeyID(), Algorithm: security.CommandSignatureAlgorithm, PublicKeySPKI: mustIngressSPKI(t, &key.PublicKey)}})
	if err != nil {
		t.Fatal(err)
	}
	return signer, verifier
}

func TestMasterDeliveryPreparesAndRecoversSignedRegionalFanout(t *testing.T) {
	for _, loss := range []string{"during-fetch", "after-regional-commit"} {
		t.Run(loss, func(t *testing.T) { runMasterRecoveryFixture(t, loss) })
	}
}

func runMasterRecoveryFixture(t *testing.T, loss string) {
	ctx, nc, js := masterTestNATS(t)
	leaders := masterTestKV(t, ctx, js, "global_leaders")
	journalKV := masterTestKV(t, ctx, js, "master_journal")
	global, err := authority.RegionalAuthorityCoordinatorStartGlobalAsync(ctx, leaders, "gru", "master")
	if err != nil {
		t.Fatal(err)
	}
	defer global.Dispose()
	intentSigner, intentVerifier := masterTestSigner(t)
	masterSigner, masterVerifier := masterTestSigner(t)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	trust, err := delivery.NewTrustSet(map[string]ed25519.PublicKey{"release": pub})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte("globally mirrored regional release")
	fetcher := &ingressReleaseFetcher{body: body, signature: ed25519.Sign(priv, body)}
	mirrors := &masterMirrorFixture{}
	mirror, err := delivery.NewArtifactMirror(estate.Default(), mirrors)
	if err != nil {
		t.Fatal(err)
	}
	cfg := MasterDeliveryConfig{Cell: "gru", Instance: "master", Connection: nc, Leaders: leaders, Journal: journalKV, Authority: global.Snapshot, Fetcher: fetcher, Trust: func() *delivery.TrustSet { return trust }, Mirror: mirror, Signer: masterSigner, IntentVerifier: intentVerifier, Regions: map[string]RegionalDeliveryRoute{}, RequestTimeout: 500 * time.Millisecond}
	regionalJournals := map[string]*delivery.Journal{}
	effects := map[string]*ingressDeliveryEffects{}
	releaseReply := make(chan struct{})
	var delayed atomic.Bool
	var loseAfterCommit atomic.Bool
	replaceGlobal := func() error {
		entry, err := leaders.Get(ctx, "authority.global")
		if err != nil {
			return err
		}
		lease, err := decodeMasterLease(entry.Value())
		if err != nil {
			return err
		}
		lease.Epoch++
		lease.CandidateId = "global-controller-gru-replacement"
		value, _ := json.Marshal(lease)
		_, err = leaders.Update(ctx, "authority.global", value, entry.Revision())
		return err
	}
	for _, region := range []string{"gru", "sfo"} {
		cellName := region
		regionalLeaders := masterTestKV(t, ctx, js, "leaders_"+region)
		regionalKV := masterTestKV(t, ctx, js, "delivery_"+region)
		local, err := authority.RegionalAuthorityCoordinatorStartAsync(ctx, regionalLeaders, region, "regional")
		if err != nil {
			t.Fatal(err)
		}
		defer local.Dispose()
		store, err := newNatsDeliveryStore(ctx, regionalKV, nc)
		if err != nil {
			t.Fatal(err)
		}
		journal, err := delivery.NewDurableJournal(store)
		if err != nil {
			t.Fatal(err)
		}
		regionalJournals[region] = journal
		d := &signedDeliveryDispatcher{delegation: &MasterDeliveryAdmissionConfig{Connection: nc, Leaders: leaders, MasterVerifier: masterVerifier, IntentVerifier: intentVerifier}, cell: region, instance: "regional", connection: nc, authority: local, leaders: regionalLeaders, store: regionalKV}
		effect := &ingressDeliveryEffects{artifact: body}
		effects[region] = effect
		executor, err := delivery.NewExecutor(delivery.ExecutorConfig{MirrorMode: delivery.MirrorModeVerifyAll, OwnerID: region + "-regional", Trust: func() *delivery.TrustSet { return trust }, Mirror: mirror, Rollout: effect, Journal: journal, Authority: d.checkAuthority})
		if err != nil {
			t.Fatal(err)
		}
		d.executor = executor
		replay, err := NewNatsCommandReplayStore(masterTestKV(t, ctx, js, "replay_"+region))
		if err != nil {
			t.Fatal(err)
		}
		boundary, err := security.NewCommandSecurityBoundary(masterVerifier, replay, 0)
		if err != nil {
			t.Fatal(err)
		}
		cell, _ := contracts.CellIdTryCreate(region)
		aggregate, _ := contracts.AggregateIdTryCreate("delivery")
		generation, _ := protocol.DesiredGenerationTryCreate(1)
		epoch, _ := protocol.WriterEpochTryCreate(1)
		version, _ := protocol.ProtocolRevisionTryCreate(int64(protocol.ProtocolVersion.Current()))
		subject, _ := natspolicy.NatsSubjectTaxonomy.DirectDeliverySubject(region)
		ingress, err := NewNatsCommandIngress(NatsCommandIngressConfiguration{Connection: nc, Subject: subject, Boundary: boundary, Replay: replay, MultiInstance: true, ExpectedCell: cell, ExpectedAggregateID: aggregate, MinimumDesiredGeneration: generation, MinimumWriterEpoch: epoch, AcceptedProtocolVersions: []protocol.ProtocolRevision{version}, PayloadDigestVerifier: masterDeliveryDigestVerifier{}, Dispatch: func(callCtx context.Context, envelope protocol.CommandEnvelope) error {
			err := d.dispatch(callCtx, envelope)
			if err == nil && cellName == "gru" && loseAfterCommit.CompareAndSwap(true, false) {
				if err := replaceGlobal(); err != nil {
					return err
				}
			}
			if err == nil && cellName == "sfo" && delayed.CompareAndSwap(false, true) {
				<-releaseReply
			}
			return err
		}})
		if err != nil {
			t.Fatal(err)
		}
		if err := ingress.Start(ctx); err != nil {
			t.Fatal(err)
		}
		defer ingress.Close()
		cfg.Regions[region] = RegionalDeliveryRoute{Connection: nc, Leaders: regionalLeaders, MasterSignerKeyID: masterSigner.PublicKeyID()}
	}
	raw, err := os.ReadFile("../delivery/testdata/request-v1.json")
	if err != nil {
		t.Fatal(err)
	}
	request, err := delivery.ParseRequest(string(raw))
	if err != nil {
		t.Fatal(err)
	}
	request.OperationID = "master-release"
	request.Target.Regions = []string{"gru", "sfo"}
	request.Artifact.Digest = delivery.SHA256Digest(body)
	cell, _ := contracts.CellIdTryCreate("gru")
	aggregate, _ := contracts.AggregateIdTryCreate("delivery-master")
	wire := signedDeliveryTestWire(t, intentSigner, cell, aggregate, request, global.Snapshot().Epoch)
	ingress, err := startMasterDeliveryRuntime(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ingress.Close() }()
	master := ingress.master
	oversized := append(bytes.Repeat([]byte(" "), MasterDeliveryMaximumEnvelopeBytes), wire...)
	if _, err := submitMasterNATS(ctx, nc, oversized); err == nil {
		t.Fatal("oversized original wire admitted")
	}
	mirrors.mu.Lock()
	before := mirrors.puts
	mirrors.mu.Unlock()
	if before != 0 {
		t.Fatal("oversized wire reached mirror PUT")
	}
	// Fail one region after other mirror copies have succeeded. Every PUT
	// independently proves that the signature was persisted before dispatch.
	mirrors.failRegion = "fra"
	mirrors.beforePut = func() error {
		saved, err := master.store.Get(masterRecordKey(request.OperationID))
		if err != nil {
			return err
		}
		var record masterDeliveryRecord
		if json.Unmarshal(saved.Value, &record) != nil || !bytes.Equal(record.ReleaseSignature, fetcher.signature) || record.Prepared {
			return errors.New("signature was not durably saved before first PUT")
		}
		return nil
	}
	interrupted, err := submitMasterNATS(ctx, nc, wire)
	if err == nil || interrupted == nil || interrupted.Complete {
		t.Fatalf("partial preparation was accepted: %+v %v", interrupted, err)
	}
	saved, err := master.store.Get(masterRecordKey(request.OperationID))
	if err != nil {
		t.Fatal(err)
	}
	var interruptedRecord masterDeliveryRecord
	if json.Unmarshal(saved.Value, &interruptedRecord) != nil || interruptedRecord.Prepared || !bytes.Equal(interruptedRecord.ReleaseSignature, fetcher.signature) {
		t.Fatal("partial preparation lost signature or claimed readiness")
	}
	mirrors.failRegion = ""
	mirrors.beforePut = nil
	var outageFetches atomic.Int64
	fetcher.before = func() error { outageFetches.Add(1); return errors.New("Forgejo unavailable") }
	if err := ingress.Close(); err != nil {
		t.Fatal(err)
	}
	ingress, err = startMasterDeliveryRuntime(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	partial, err := submitMasterNATS(ctx, nc, wire)
	close(releaseReply)
	if err == nil || partial == nil || partial.Complete || !partial.Regions[0].Accepted || partial.Regions[1].Accepted {
		t.Fatalf("lost reply must retain partial acceptance: %+v %v", partial, err)
	}
	// A newer intent cannot replace a partially acknowledged parent.
	nextPayload, _ := json.Marshal(request)
	nextRequest, err := delivery.ParseRequest(string(nextPayload))
	if err != nil {
		t.Fatal(err)
	}
	nextRequest.OperationID = "next-master-release"
	nextWire := masterGenerationWire(t, intentSigner, nextRequest, global.Snapshot().Epoch, 2)
	if _, err := submitMasterNATS(ctx, nc, nextWire); err == nil {
		t.Fatal("new generation stranded incomplete regional fanout")
	}
	// Construct a fresh, unconsumed old-master command before replacing global
	// authority. Its regional epoch remains unchanged across the transition.
	parentEnvelope, err := protocol.DecodeCommandEnvelope(wire)
	if err != nil {
		t.Fatal(err)
	}
	oldLease, err := master.readGlobal(ctx, global.Snapshot().Epoch)
	if err != nil {
		t.Fatal(err)
	}
	child := masterDeliveryChild{Cell: partial.Regions[1].Cell, OperationID: partial.Regions[1].OperationID, PayloadDigest: partial.Regions[1].PayloadDigest, Attempt: 999}
	delayedWire, err := master.childEnvelope(parentEnvelope, request, child, 1, oldLease, fetcher.signature)
	if err != nil {
		t.Fatal(err)
	}
	global.Dispose()
	oldEntry, err := leaders.Get(ctx, "authority.global")
	if err != nil {
		t.Fatal(err)
	}
	expired := oldLease
	expired.IssuedAt = time.Now().Add(-time.Hour)
	expiredBody, _ := json.Marshal(expired)
	if _, err := leaders.Update(ctx, "authority.global", expiredBody, oldEntry.Revision()); err != nil {
		t.Fatal(err)
	}
	successor, err := authority.RegionalAuthorityCoordinatorStartGlobalAsync(ctx, leaders, "gru", "recovered")
	if err != nil {
		t.Fatal(err)
	}
	defer successor.Dispose()
	if successor.Snapshot().Epoch <= oldLease.Epoch {
		t.Fatal("global takeover did not advance epoch")
	}
	staleSubject, _ := natspolicy.NatsSubjectTaxonomy.DirectDeliverySubject("sfo")
	staleReply, err := nc.Request(staleSubject, delayedWire, time.Second)
	if err != nil || string(staleReply.Data) != string(CommandIngressCodeDispatchFailed) {
		t.Fatalf("delayed old master passed unchanged regional lease: reply=%v err=%v", staleReply, err)
	}
	cfg.Instance = "recovered"
	cfg.Authority = successor.Snapshot
	recoveryWire := masterGenerationWire(t, intentSigner, request, successor.Snapshot().Epoch, 1)
	nextWire = masterGenerationWire(t, intentSigner, nextRequest, successor.Snapshot().Epoch, 2)
	if err := ingress.Close(); err != nil {
		t.Fatal(err)
	}
	ingress, err = startMasterDeliveryRuntime(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	recovered := ingress.master
	complete, err := submitMasterNATS(ctx, nc, recoveryWire)
	if err != nil || complete == nil || !complete.Complete {
		t.Fatalf("resume: %+v %v", complete, err)
	}
	mirrors.mu.Lock()
	puts := mirrors.puts
	mirrors.mu.Unlock()
	if puts != 2*len(estate.Default().Regions)-1 {
		t.Fatalf("recovery repeated global writes: %d", puts)
	}
	for _, child := range complete.Regions {
		operation, exists, err := regionalJournals[child.Cell].GetWithError(child.OperationID)
		if err != nil || !exists || operation.Receipt == nil || operation.Receipt.Status != delivery.StatusSucceeded {
			t.Fatalf("regional durable receipt absent: %+v %v", operation, err)
		}
		expectedPayload, err := masterChildPayload(request, child.Cell, child.OperationID)
		if err != nil {
			t.Fatal(err)
		}
		actualPayload, _ := json.Marshal(operation.Request)
		if !bytes.Equal(actualPayload, expectedPayload) {
			t.Fatal("regional child changed original request fields")
		}
		effects[child.Cell].mu.Lock()
		targets := append([]string(nil), effects[child.Cell].targets...)
		effects[child.Cell].mu.Unlock()
		if !reflect.DeepEqual(targets, []string{child.Cell}) {
			t.Fatalf("lost reply repeated rollout or crossed scope: %v", targets)
		}
	}
	stored, err := recovered.store.Get(masterRecordKey(request.OperationID))
	if err != nil {
		t.Fatal(err)
	}
	var record masterDeliveryRecord
	if json.Unmarshal(stored.Value, &record) != nil || !bytes.Equal(record.OriginalEnvelope, wire) || record.Children[1].Attempt != 2 || record.OwnerEpoch != successor.Snapshot().Epoch {
		t.Fatal("original signed lineage or durable retry count changed")
	}
	if outageFetches.Load() != 0 {
		t.Fatal("recovery fetched Forgejo despite surviving mirrors")
	}
	mirrors.mu.Lock()
	mirrors.objects = nil
	mirrors.mu.Unlock()
	if replay, err := submitMasterNATS(ctx, nc, recoveryWire); err != nil || !replay.Complete {
		t.Fatalf("completed replay: %+v %v", replay, err)
	}
	fetcher.before = nil
	// Matching operation IDs cannot change the original signed payload.
	changedPayload, _ := json.Marshal(request)
	changed, err := delivery.ParseRequest(string(changedPayload))
	if err != nil {
		t.Fatal(err)
	}
	changed.Reason = "different intent"
	if _, err := submitMasterNATS(ctx, nc, masterGenerationWire(t, intentSigner, changed, successor.Snapshot().Epoch, 1)); err == nil {
		t.Fatal("changed original intent admitted")
	}
	// A delegated region signer is not automatically an accepted CI intent signer.
	if _, err := submitMasterNATS(ctx, nc, masterGenerationWire(t, masterSigner, request, successor.Snapshot().Epoch, 1)); err == nil {
		t.Fatal("regional delegation granted global intent signing")
	}
	if loss == "during-fetch" {
		fetcher.before = replaceGlobal
	} else {
		loseAfterCommit.Store(true)
	}
	failed, err := submitMasterNATS(ctx, nc, nextWire)
	if err == nil {
		t.Fatal("lost global authority did not fence master")
	}
	mirrors.mu.Lock()
	afterLoss := mirrors.puts
	mirrors.mu.Unlock()
	if loss == "during-fetch" && afterLoss != puts {
		t.Fatal("lost global authority wrote artifacts")
	}
	if loss == "after-regional-commit" {
		if failed == nil || failed.Complete || failed.Regions[0].Accepted {
			t.Fatalf("unsaved acceptance reported as durable: %+v", failed)
		}
		saved, err := recovered.store.Get(masterRecordKey(nextRequest.OperationID))
		if err != nil {
			t.Fatal(err)
		}
		var record masterDeliveryRecord
		if json.Unmarshal(saved.Value, &record) != nil || record.Children[0].Accepted {
			t.Fatal("failed durable acceptance write changed record")
		}
	}

	if err := ingress.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-ingress.Completion():
	default:
		t.Fatal("master ingress completion did not follow close")
	}
	if !nc.IsConnected() {
		t.Fatal("master ingress closed the caller-owned connection")
	}
	if err := nc.FlushTimeout(time.Second); err != nil {
		t.Fatal(err)
	}
	if _, err := nc.Request(natspolicy.NatsSubjectTaxonomy.GlobalDeliverySubject(), nextWire, time.Second); !errors.Is(err, nats.ErrNoResponders) {
		t.Fatalf("closed master retained subscription: %v", err)
	}

}

func masterGenerationWire(t *testing.T, signer *security.CommandSignatureSigner, request *delivery.Request, epoch, generationValue int64) []byte {
	t.Helper()
	cell, _ := contracts.CellIdTryCreate("gru")
	aggregate, _ := contracts.AggregateIdTryCreate("delivery-master")
	raw := signedDeliveryTestWire(t, signer, cell, aggregate, request, epoch)
	parsed, err := protocol.DecodeCommandEnvelope(raw)
	if err != nil {
		t.Fatal(err)
	}
	generation, _ := protocol.DesiredGenerationTryCreate(generationValue)
	changed := protocol.NewCommandEnvelope(parsed.ProtocolVersion, parsed.Cell, parsed.AggregateId, generation, parsed.WriterEpoch, parsed.OperationId, parsed.IdempotencyKey, parsed.IssuedAt, parsed.ExpiresAt, parsed.Attempt, parsed.Payload, parsed.PayloadDigest, protocol.OpaqueSignature{})
	signature, err := signer.Sign(changed.SignedMaterial)
	if err != nil {
		t.Fatal(err)
	}
	changed = protocol.NewCommandEnvelope(parsed.ProtocolVersion, parsed.Cell, parsed.AggregateId, generation, parsed.WriterEpoch, parsed.OperationId, parsed.IdempotencyKey, parsed.IssuedAt, parsed.ExpiresAt, parsed.Attempt, parsed.Payload, parsed.PayloadDigest, signature)
	raw, err = protocol.EncodeCommandEnvelope(changed)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func submitMasterNATS(ctx context.Context, nc *nats.Conn, wire []byte) (*MasterDeliveryReceipt, error) {
	callCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	reply, err := nc.RequestWithContext(callCtx, natspolicy.NatsSubjectTaxonomy.GlobalDeliverySubject(), wire)
	if err != nil {
		return nil, err
	}
	if len(reply.Data) > 16*1024 {
		return nil, errors.New("master response exceeds bound")
	}
	var response MasterDeliveryResponse
	if err := json.Unmarshal(reply.Data, &response); err != nil {
		return nil, err
	}
	if response.Code != CommandIngressCodeAccepted {
		return response.Receipt, errors.New("master intent not complete")
	}
	return response.Receipt, nil
}

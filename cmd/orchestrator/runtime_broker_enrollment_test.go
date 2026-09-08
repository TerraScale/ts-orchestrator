package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/brokeradmission"
	"terrascale.tech/orchestrator/src/orchestrator/enrollment"
	"terrascale.tech/orchestrator/src/orchestrator/hostremoval"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

func TestBrokerEnrollmentPendingRevocationKeepsAutoscaleRemovalRetryable(t *testing.T) {
	target := autoscale.Target{Region: "gru", Members: 2, RemovalOperationID: "remove-finished", RemovalResourceID: "instance-old", RemovalHostID: "host-old", RemovalIncarnation: "boot-old", RemovalSlot: 3}
	journal := &runtimeRemovalJournal{found: true, record: hostremoval.Operation{OperationID: target.RemovalOperationID, ResourceID: target.RemovalResourceID, Stage: hostremoval.StageComplete}}
	attempts := 0
	construct := func() *productionHostRemoval {
		return &productionHostRemoval{owner: &hostremoval.Owner{Journal: journal}, completed: func(_ context.Context, operation string) error {
			if operation != target.RemovalOperationID {
				t.Fatal("revocation retry changed removal identity")
			}
			attempts++
			if attempts == 1 {
				return errors.Join(errBrokerGrantsPending, errors.New("broker has not applied removal"))
			}
			return nil
		}}
	}
	if complete, err := construct().AutoscaleRemovalComplete(t.Context(), target); complete || err != nil {
		t.Fatalf("pending revocation stopped autoscale or admitted completion: %v %v", complete, err)
	}
	if complete, err := construct().AutoscaleRemovalComplete(t.Context(), target); !complete || err != nil {
		t.Fatalf("restarted completion failed to retry broker revocation: %v %v", complete, err)
	}
	if attempts != 2 {
		t.Fatalf("revocation attempts = %d", attempts)
	}
}

func TestBrokerEnrollmentPublisherAndScopedReaderUseRealR3(t *testing.T) {
	cluster := newRotationStateCluster(t)
	root := cluster.connect(t)
	store := openRotationTestLeaseStore(t, t.Context(), root, true)
	lease := rotationTestLease(7, "global-controller-gru-one")
	putRotationTestLease(t, t.Context(), store, lease)
	worker, err := cluster.connectionPlan.Connect(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer worker.Close()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := security.NewCommandSignatureSignerFromKey(key)
	if err != nil {
		t.Fatal(err)
	}
	defer signer.Close()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := brokeradmission.NewVerifier(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}), signer.PublicKeyID())
	if err != nil {
		t.Fatal(err)
	}
	publisher, err := brokeradmission.NewPublisher(authorityjournal.Config{Connection: worker, CandidateID: lease.CandidateId, AuthorityEpoch: uint64(lease.Epoch), LeaseID: lease.LeaseId}, signer, verifier, "production", "cluster")
	if err != nil {
		t.Fatal(err)
	}
	record := enrollment.Record{Environment: "production", Cluster: "cluster", NodeID: "gru-3", MemberID: "01ARZ3NDEKTSV4RRFFQ69G5FAB", Region: "gru", Slot: 3, Generation: 7, OperationID: "enroll-three", IdentityReference: "ocivault:identity", Public: &enrollment.PublicBootstrap{Grant: []byte("published-bootstrap"), PublicKeys: map[string]string{}}}
	for _, role := range brokeradmission.Roles {
		pair, err := nkeys.CreateUser()
		if err != nil {
			t.Fatal(err)
		}
		record.Public.PublicKeys[role], err = pair.PublicKey()
		pair.Wipe()
		if err != nil {
			t.Fatal(err)
		}
	}
	state := enrollment.State{Records: map[string]enrollment.Record{"gru:3": record}}
	wire, err := publisher.Publish(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	again, err := publisher.Publish(t.Context(), state)
	if err != nil || !bytes.Equal(wire, again) {
		t.Fatalf("unchanged desired replaced revision/signature: %v", err)
	}
	if err := brokeradmission.Acknowledged(t.Context(), worker, []string{"broker-one"}, wire, verifier); err == nil {
		t.Fatal("unapplied grants admitted member")
	}

	readerKey, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer readerKey.Wipe()
	readerPublic, err := readerKey.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	for i, server := range cluster.servers {
		options, err := brokeradmission.ApplyReaderGrants(cluster.options[i], []brokeradmission.ReaderGrant{{BrokerID: "broker-one", PublicNKey: readerPublic, Account: "$G"}}, []string{"broker-one"}, brokeradmission.Policy{Regions: map[string]brokeradmission.Accounts{"gru": {Global: "$G"}}})
		if err != nil {
			t.Fatal(err)
		}
		if err := server.ReloadOptions(options); err != nil {
			t.Fatal(err)
		}
	}
	reader, err := nats.Connect(root.ConnectedUrl(), nats.Secure(cluster.tls.Clone()), nats.Nkey(readerPublic, readerKey.Sign), nats.NoReconnect(), nats.ReconnectBufSize(-1), nats.ErrorHandler(func(*nats.Conn, *nats.Subscription, error) {}))
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	read, err := brokeradmission.ReadDesired(t.Context(), reader, verifier)
	if err != nil || !bytes.Equal(read, wire) {
		t.Fatalf("authenticated desired read: %v", err)
	}
	writeFile := func(name string, data []byte) string {
		path := filepath.Join(cluster.root, name)
		if err := os.WriteFile(path, data, 0600); err != nil {
			t.Fatal(err)
		}
		return path
	}
	seed, err := readerKey.Seed()
	if err != nil {
		t.Fatal(err)
	}
	seedPath := writeFile("broker-reader.seed", seed)
	clear(seed)
	publicPath := writeFile("broker-signer.pub", pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der}))
	desired, err := verifier.Verify(wire)
	if err != nil {
		t.Fatal(err)
	}
	checkpoint := filepath.Join(cluster.root, "broker-checkpoint", "accepted.json")
	file := productionBrokerAdmissionFile{Version: 1, BrokerID: "broker-one", Environment: "production", Cluster: "cluster", SignerPublicKeyFile: publicPath, SignerSHA256: signer.PublicKeyID(), CheckpointPath: checkpoint, MinimumRevision: desired.Revision, Regions: map[string]brokeradmission.Accounts{"gru": {Global: "CONTROL", Regional: "CONTROL", Node: "CONTROL"}}, Reader: bootstrapcredentials.Reference{URL: root.ConnectedUrl(), CAFile: cluster.authorityConfig.Tls.CaFile, CertificateFile: cluster.authorityConfig.Tls.CertificateFile, PrivateKeyFile: cluster.authorityConfig.Tls.KeyFile, NKeySeedFile: seedPath}}
	file.BrokerIDs = []string{"broker-one"}
	file.ReaderGrants = []brokeradmission.ReaderGrant{{BrokerID: "broker-one", PublicNKey: readerPublic, Account: "CONTROL"}}
	encoded, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	admissionPath := writeFile("broker-admission.json", encoded)
	serverPath := writeFile("broker.conf", []byte(fmt.Sprintf("listen: \"127.0.0.1:0\"\nserver_name: broker-one\njetstream: {store_dir: %q}\ntls: {cert_file: %q, key_file: %q, ca_file: %q, verify: true, min_version: \"1.3\"}\naccounts: {CONTROL: {users: [{user: runner, password: test-only}]}}\n", filepath.Join(cluster.root, "broker-store"), file.Reader.CertificateFile, file.Reader.PrivateKeyFile, file.Reader.CAFile)))
	lookup := func(key string) (string, bool) {
		value, found := map[string]string{natsServerConfigEnvironment: serverPath, brokerAdmissionEnvironment: admissionPath}[key]
		return value, found
	}
	config, err := selectedNatsConfiguration(lookup)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err := startEmbeddedNatsRuntime(t.Context(), *config)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if runtime != nil {
			runtime.Close()
		}
	}()
	waitAcknowledged := func(wire []byte) {
		t.Helper()
		bounded, stop := context.WithTimeout(t.Context(), 5*time.Second)
		defer stop()
		for {
			if err := brokeradmission.Acknowledged(bounded, worker, []string{"broker-one"}, wire, verifier); err == nil {
				break
			}
			select {
			case <-bounded.Done():
				t.Fatal("real broker did not acknowledge applied grants")
			case <-time.After(25 * time.Millisecond):
			}
		}
		stored, _, err := brokeradmission.ReadCheckpoint(checkpoint, verifier)
		if err != nil || !bytes.Equal(stored, wire) {
			t.Fatalf("broker ack preceded durable application: %v", err)
		}
	}
	waitAcknowledged(wire)
	js, err := jetstream.New(reader)
	if err != nil {
		t.Fatal(err)
	}
	for _, subject := range []string{"$KV.ORCH_LEADERS.authority.global", "$KV.ORCH_LEADERS.broker.enrollment.state", "$KV.ORCH_LEADERS.broker.enrollment.ack.broker-two"} {
		bounded, stop := context.WithTimeout(t.Context(), 250*time.Millisecond)
		_, err := js.Publish(bounded, subject, []byte("forged"))
		stop()
		if err == nil {
			t.Fatalf("reader mutated forbidden subject %s", subject)
		}
	}
	read, err = brokeradmission.ReadDesired(t.Context(), reader, verifier)
	if err != nil || !bytes.Equal(read, wire) {
		t.Fatalf("reader damaged desired state: %v", err)
	}
	if err := runtime.Close(); err != nil {
		t.Fatal(err)
	}
	record.Retirement = &enrollment.Retirement{OperationID: "remove-three", ResourceID: "ocid1.instance.three"}
	state.Records["gru:3"] = record
	revoked, err := publisher.Publish(t.Context(), state)
	if err != nil {
		t.Fatal(err)
	}
	d, err := verifier.Verify(revoked)
	if err != nil || len(d.Members) != 0 || len(d.Retired) != 1 {
		t.Fatalf("retired public projection: %+v %v", d, err)
	}
	if err := brokeradmission.Acknowledged(t.Context(), worker, []string{"broker-one"}, revoked, verifier); err == nil {
		t.Fatal("old broker acknowledgement accepted for revocation")
	}
	config, err = selectedNatsConfiguration(lookup)
	if err != nil {
		t.Fatal(err)
	}
	runtime, err = startEmbeddedNatsRuntime(t.Context(), *config)
	if err != nil {
		t.Fatal(err)
	}
	waitAcknowledged(revoked)
	record.Retirement = nil
	state.Records["gru:3"] = record
	if _, err := publisher.Publish(t.Context(), state); err == nil {
		t.Fatal("retired keys resurrected through publisher")
	}
}

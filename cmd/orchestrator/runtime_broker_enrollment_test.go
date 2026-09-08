package main

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"testing"
	"time"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/autoscale"
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
	pub, sub, err := brokeradmission.ReaderPermissions("broker-one")
	if err != nil {
		t.Fatal(err)
	}
	for i, server := range cluster.servers {
		options := cluster.options[i].Clone()
		options.Nkeys = append(options.Nkeys, &natsserver.NkeyUser{Nkey: readerPublic, Permissions: &natsserver.Permissions{Publish: &natsserver.SubjectPermission{Allow: pub}, Subscribe: &natsserver.SubjectPermission{Allow: sub}}})
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
	if err := brokeradmission.PublishAck(t.Context(), reader, "broker-one", read, verifier); err != nil {
		t.Fatal(err)
	}
	if err := brokeradmission.Acknowledged(t.Context(), worker, []string{"broker-one"}, wire, verifier); err != nil {
		t.Fatal(err)
	}
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
	if err := brokeradmission.PublishAck(t.Context(), reader, "broker-one", revoked, verifier); err != nil {
		t.Fatal(err)
	}
	if err := brokeradmission.Acknowledged(t.Context(), worker, []string{"broker-one"}, revoked, verifier); err != nil {
		t.Fatal(err)
	}
	record.Retirement = nil
	state.Records["gru:3"] = record
	if _, err := publisher.Publish(t.Context(), state); err == nil {
		t.Fatal("retired keys resurrected through publisher")
	}
}

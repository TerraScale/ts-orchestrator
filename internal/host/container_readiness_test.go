//go:build linux

package host

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/storage/executionwire"
	"github.com/nats-io/nats.go"
)

func TestContainerReadinessRejectsStaleChallenge(t *testing.T) {
	registration, _, _ := managedContractFixture()
	effect := authority.RuntimeEffect{RegistrationID: registration.ID, RegistrationGeneration: registration.Generation,
		WorkerPublicKey: registration.PublicKey, NATSUserPublicKey: registration.NATSUserPublicKey, HostSessionID: "original-session"}
	challenge := ContainerReadinessChallenge{Nonce: strings.Repeat("a", 32), TaskID: "task", TaskSHA256: "hash", AdmissionSHA256: "admission", EffectID: "effect", Deadline: time.Now().Add(time.Second)}
	for _, test := range []struct {
		name   string
		change func(*containerReadinessPending, *containerReadinessQuery, *request)
	}{
		{"expired", func(p *containerReadinessPending, _ *containerReadinessQuery, _ *request) {
			p.challenge.Deadline = time.Now().Add(-time.Second)
		}},
		{"already consumed", func(p *containerReadinessPending, _ *containerReadinessQuery, _ *request) { p.completed = true }},
		{"another nonce", func(_ *containerReadinessPending, q *containerReadinessQuery, _ *request) {
			q.Challenge.Nonce = strings.Repeat("b", 32)
		}},
		{"another session", func(_ *containerReadinessPending, _ *containerReadinessQuery, r *request) { r.SessionID = "successor" }},
		{"another task", func(_ *containerReadinessPending, q *containerReadinessQuery, _ *request) { q.TaskID = "other" }},
		{"another admission", func(_ *containerReadinessPending, q *containerReadinessQuery, _ *request) {
			q.AdmissionSHA256 = "other"
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			pending := &containerReadinessPending{challenge: challenge, effect: effect, result: make(chan ManagedRuntimeReport, 1)}
			copy := challenge
			query := containerReadinessQuery{TaskID: challenge.TaskID, TaskSHA256: challenge.TaskSHA256, AdmissionSHA256: challenge.AdmissionSHA256,
				EffectID: challenge.EffectID, Challenge: &copy, Report: &ManagedRuntimeReport{}}
			req := request{SessionID: effect.HostSessionID}
			test.change(pending, &query, &req)
			payload, err := json.Marshal(query)
			if err != nil {
				t.Fatal(err)
			}
			req.Payload = payload
			controller := &Controller{readiness: map[string]*containerReadinessPending{challenge.Nonce: pending}}
			if _, err := controller.serveContainerReadiness(t.Context(), req, registration, session{}); err == nil {
				t.Fatal("stale or changed challenge accepted")
			}
			if len(pending.result) != 0 {
				t.Fatal("denied challenge published an observation")
			}
		})
	}
}

func readinessReportFixture() (Desired, authority.RuntimeEffect, ManagedRuntimeReport) {
	_, desired, _ := managedContractFixture()
	desired.ManagedMember.AttachmentETag = "etag"
	desired.ManagedMember.Runtime = &ManagedRuntimePins{DevicePath: "/dev/sdb", MountPath: "/srv/volume", FileSystemUUID: "uuid", FileSystemType: "ext4", ReplicationPeerMemberID: "peer"}
	effect := authority.RuntimeEffect{TaskID: "task", TaskSHA256: strings.Repeat("a", 64), AdmissionSHA256: strings.Repeat("b", 64), EffectID: entityid.New()}
	binding := ManagedContainerRuntime{TaskID: effect.TaskID, TaskSHA256: effect.TaskSHA256, AdmissionSHA256: effect.AdmissionSHA256, EffectID: effect.EffectID,
		ContainerID: "ts-task", HostPID: 1234, MemberPID: 1, KernelStart: "12345", Cgroup: "/terrascale/ts-task", PIDNamespace: 1, MountNamespace: 2,
		MountID: 3, ControlDevice: 4, ControlInode: 5, PublicationDevice: 6, PublicationInode: 7}
	proof := memberstatus.ServingProof{SchemaVersion: 1, Process: memberstatus.Process{PID: 1, StartNonce: strings.Repeat("c", 32)},
		Scope: memberstatus.Scope(desired.ManagedMember.Member.Scope), Authority: memberstatus.Authority(desired.ManagedMember.Authority),
		Serving: true, Listeners: memberstatus.Listeners{Client: true, Replication: true}, Replication: memberstatus.ReplicationProof{PeerMemberID: "peer"}}
	report := ManagedRuntimeReport{Container: &binding, ServingProof: &proof, Member: desired.ManagedMember.Member, Authority: desired.ManagedMember.Authority,
		OCI: desired.ManagedMember.OCI, VolumeID: desired.ManagedMember.VolumeID, AttachmentID: desired.ManagedMember.AttachmentID, AttachmentETag: "etag",
		FileSystemUUID: "uuid", FileSystemType: "ext4", MountDevice: "/dev/sdb", MountPath: "/srv/volume", MountID: binding.MountID,
		ProcessPID: binding.HostPID, ProcessStart: binding.KernelStart, ProcessCgroup: binding.Cgroup, ProcessBootID: proof.Process.StartNonce, StorageRecovered: true, ListenerReady: true}
	return desired, effect, report
}

func TestContainerReadinessRequiresExactSourceWitness(t *testing.T) {
	desired, effect, report := readinessReportFixture()
	binding, proof := *report.Container, *report.ServingProof
	if err := validateContainerReadinessReport(effect, desired, report); err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name   string
		change func(*ManagedRuntimeReport)
	}{
		{"native report", func(r *ManagedRuntimeReport) { r.Container = nil }},
		{"missing serving proof", func(r *ManagedRuntimeReport) { r.ServingProof = nil }},
		{"changed task", func(r *ManagedRuntimeReport) { r.Container.TaskID = "other" }},
		{"changed admission", func(r *ManagedRuntimeReport) { r.Container.AdmissionSHA256 = strings.Repeat("c", 64) }},
		{"changed effect", func(r *ManagedRuntimeReport) { r.Container.EffectID = entityid.New() }},
		{"changed PID", func(r *ManagedRuntimeReport) { r.Container.HostPID++ }},
		{"changed attachment", func(r *ManagedRuntimeReport) { r.AttachmentETag = "successor" }},
		{"wrong member PID", func(r *ManagedRuntimeReport) { r.ServingProof.Process.PID = binding.HostPID }},
	} {
		t.Run(test.name, func(t *testing.T) {
			changed, container, serving := report, binding, proof
			changed.Container, changed.ServingProof = &container, &serving
			test.change(&changed)
			if err := validateContainerReadinessReport(effect, desired, changed); err == nil {
				t.Fatal("missing or changed Source witness accepted")
			}
		})
	}
}

func TestContainerReadinessAuthenticatedChallengeIsOneUse(t *testing.T) {
	controller, conn, registration, private, controllerKey, effect, report, session := readinessTransportFixture(t)
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- controller.Run(ctx) }()
	select {
	case <-controller.Ready():
	case err := <-controllerDone:
		t.Fatalf("readiness controller stopped: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	result := make(chan error, 1)
	var calls int
	go func() {
		_, _, err := controller.ObserveContainerReadiness(ctx, effect, func(_ context.Context, caller RuntimeEffectCaller) error {
			calls++
			if caller.SessionID() != effect.HostSessionID || caller.Registration().NATSUserPublicKey != effect.NATSUserPublicKey {
				return authority.ErrFenced
			}
			return nil
		})
		result <- err
	}()
	query := containerReadinessQuery{TaskID: effect.TaskID, TaskSHA256: effect.TaskSHA256, AdmissionSHA256: effect.AdmissionSHA256, EffectID: effect.EffectID}
	var challenge *ContainerReadinessChallenge
	for challenge == nil {
		var reply containerReadinessReply
		if err := exchange(ctx, conn, registration.Cell, controllerKey.Public().(ed25519.PublicKey), signedHostRequest(t, private, "runtime-readiness", session.SessionID, session.Epoch, query), &reply); err != nil {
			t.Fatal(err)
		}
		challenge = reply.Challenge
		select {
		case err := <-result:
			t.Fatalf("challenge ended before response: %v", err)
		default:
		}
	}
	query.Challenge, query.Report = challenge, &report
	var acknowledged containerReadinessReply
	if err := exchange(ctx, conn, registration.Cell, controllerKey.Public().(ed25519.PublicKey), signedHostRequest(t, private, "runtime-readiness", session.SessionID, session.Epoch, query), &acknowledged); err != nil {
		t.Fatal(err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	if calls != 2 || acknowledged.Challenge == nil || !sameContainerReadinessChallenge(*acknowledged.Challenge, *challenge) {
		t.Fatal("original session was not verified before and after the fresh observation")
	}
	if err := exchange(ctx, conn, registration.Cell, controllerKey.Public().(ed25519.PublicKey), signedHostRequest(t, private, "runtime-readiness", session.SessionID, session.Epoch, query), &acknowledged); err == nil {
		t.Fatal("signed observation replay accepted")
	}
}

func readinessTransportFixture(t *testing.T) (*Controller, *nats.Conn, Registration, ed25519.PrivateKey, ed25519.PrivateKey, authority.RuntimeEffect, ManagedRuntimeReport, session) {
	t.Helper()
	registration, _, private := managedContractFixture()
	desired, effect, report := readinessReportFixture()
	registration.ManagedPlacement = &ManagedPlacementBinding{DatabaseID: entityid.New(), PartitionID: entityid.New(), SeatID: entityid.New(), IntentGeneration: 1,
		IntentPayloadDigest: strings.Repeat("1", 64), CanonicalRosterDigest: strings.Repeat("2", 64), ManagedHostProfileDigest: strings.Repeat("3", 64)}
	pins := desired.ManagedMember.Runtime
	pins.FileSystemUUID = "12345678-1234-1234-1234-123456789abc"
	report.FileSystemUUID = pins.FileSystemUUID
	pins.TrustedKeySHA256, pins.ServerCertificateSHA256, pins.ServerPrivateKeySHA256 = strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)
	pins.ClientCARootsSHA256, pins.ClientManagedMaterialManifestSHA256 = strings.Repeat("4", 64), strings.Repeat("5", 64)
	pins.LiveS3ConfigSHA256, pins.LiveS3TargetSHA256 = strings.Repeat("6", 64), strings.Repeat("7", 64)
	pins.LiveS3Credential = oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3}
	pins.ReplicationListenAddress, pins.ReplicationPeerAddress = "10.0.0.11:7000", "10.0.0.12:7001"
	pins.ReplicationServerCASHA256, pins.ReplicationPeerMemberID = strings.Repeat("8", 64), "01HW000000E008000000000002"
	report.ServingProof.Replication.PeerMemberID = pins.ReplicationPeerMemberID
	controller, conn, artifacts, _, controllerKey := testControllerWithVerifier(t, managedRegistrationVerifierFunc(func(context.Context, Registration) error { return nil }))
	if _, err := controller.Register(t.Context(), registration); err != nil {
		t.Fatal(err)
	}
	artifact := []byte("readiness transport fixture")
	digest := sha256.Sum256(artifact)
	desired.Digest = hex.EncodeToString(digest[:])
	if _, err := artifacts.PutBytes(t.Context(), "sha256-"+desired.Digest, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.ApplyDesired(t.Context(), desired); err != nil {
		t.Fatal(err)
	}
	accepted, err := controller.handleSession(t.Context(), signedHostRequest(t, private, "session", entityid.New(), 0, struct {
		Kind string `json:"kind"`
	}{Kind: "acquire"}))
	if err != nil {
		t.Fatal(err)
	}
	session := accepted.(session)
	effect.RegistrationID, effect.RegistrationGeneration = registration.ID, registration.Generation
	effect.WorkerPublicKey, effect.NATSUserPublicKey = registration.PublicKey, registration.NATSUserPublicKey
	effect.InstanceID, effect.HostSessionID = registration.ManagedOCI.InstanceID, session.SessionID
	effect.Phase, effect.Epoch, effect.ExpiresAt = authority.RuntimeEffectHeld, 1, time.Now().Add(5*time.Second)
	registered, err := json.Marshal(registration)
	if err != nil {
		t.Fatal(err)
	}
	desiredBytes, err := json.Marshal(desired)
	if err != nil {
		t.Fatal(err)
	}
	effect.Material, err = json.Marshal(executionwire.WorkerGrantMaterial{Registration: registered, Desired: desiredBytes})
	if err != nil {
		t.Fatal(err)
	}
	return controller, conn, registration, private, controllerKey, effect, report, session
}

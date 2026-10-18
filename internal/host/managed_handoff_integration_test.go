//go:build linux

package host

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/json/v2"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func TestManagedNativeFenceCancelsAndJoinsPausedPermits(t *testing.T) {
	gate := &managedNativeGate{}
	permit, release, err := gate.acquire(t.Context(), "physical-volume")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(release)
	fenced := make(chan error, 1)
	go func() { fenced <- gate.fence(t.Context()) }()
	select {
	case <-permit.ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("fence did not cancel prior native effect")
	}
	if _, _, err := gate.acquire(t.Context(), "physical-volume"); !errors.Is(err, ErrManagedNativeFenced) {
		t.Fatalf("fence admitted another effect: %v", err)
	}
	select {
	case err := <-fenced:
		t.Fatalf("fence acknowledged a paused effect before join: %v", err)
	default:
	}
	release()
	select {
	case err := <-fenced:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("fence did not finish after prior effect joined")
	}
}

func TestManagedNativeSignedEnrollmentRetainsPhysicalFenceAndPublicationHold(t *testing.T) {
	t.Run("retained original", func(t *testing.T) { testManagedNativeSignedEnrollment(t, true) })
	t.Run("unknown original", func(t *testing.T) { testManagedNativeSignedEnrollment(t, false) })
}

func testManagedNativeSignedEnrollment(t *testing.T, retainedOriginal bool) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, JetStream: true, StoreDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	js, err := jetstream.New(conn)
	if err != nil {
		t.Fatal(err)
	}
	control, err := authority.Start(ctx, js, authority.Config{DeploymentID: entityid.New(), Scope: "gru", CandidateID: entityid.New(), Replicas: 1})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = control.Close() })
	objects, err := js.CreateObjectStore(ctx, jetstream.ObjectStoreConfig{Bucket: "MANAGED_FENCE_ARTIFACTS", Storage: jetstream.FileStorage})
	if err != nil {
		t.Fatal(err)
	}
	controllerKey := ed25519.NewKeyFromSeed([]byte(strings.Repeat("c", ed25519.SeedSize)))
	c, err := NewController(ctx, ControllerConfig{Cell: "gru", Conn: conn, JS: js, Artifacts: objects,
		ResponseKey: controllerKey, StateReplicas: 1, HostMutations: control,
		ManagedRegistrationVerifier: managedRegistrationVerifierFunc(func(context.Context, Registration) error { return nil }),
		ManagedDesiredVerifier:      func(context.Context, Desired, Registration, Desired, bool) error { return nil },
		AuthorityEpoch:              func() uint64 { return control.Current().Epoch }, AuthorityGuard: control.Guard})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.cacheCancel)
	go func() { _ = c.Run(ctx) }()
	select {
	case <-c.Ready():
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	r, d, hostKey := managedContractFixture()
	r.ManagedPlacement = &ManagedPlacementBinding{DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000Z3WK359G2W66CVT8", SeatID: entityid.New(), IntentGeneration: 1,
		IntentPayloadDigest: strings.Repeat("1", 64), CanonicalRosterDigest: strings.Repeat("2", 64), ManagedHostProfileDigest: strings.Repeat("3", 64)}
	paths, err := runtimePaths("/srv/managed", *d.ManagedMember)
	if err != nil {
		t.Fatal(err)
	}
	d.ManagedMember.Runtime = &ManagedRuntimePins{DevicePath: "/dev/sdb", MountPath: paths.mount,
		FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4",
		TrustedKeySHA256: strings.Repeat("1", 64), ServerCertificateSHA256: strings.Repeat("2", 64), ServerPrivateKeySHA256: strings.Repeat("3", 64),
		ClientCARootsSHA256: strings.Repeat("4", 64), ClientManagedMaterialManifestSHA256: strings.Repeat("5", 64),
		LiveS3ConfigSHA256: strings.Repeat("6", 64), LiveS3TargetSHA256: strings.Repeat("7", 64),
		LiveS3Credential:         oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3},
		ReplicationListenAddress: "10.0.0.11:7000", ReplicationPeerMemberID: "01HW000000E008000000000002", ReplicationPeerAddress: "10.0.0.12:7001", ReplicationServerCASHA256: strings.Repeat("8", 64)}
	d.ManagedMember.AttachmentETag = "attachment-etag-not-publication-proof"
	artifact := []byte("retained native artifact fixture")
	d.Digest = fmt.Sprintf("%x", sha256.Sum256(artifact))
	d.AuthorityEpoch = control.Current().Epoch
	if _, err := objects.PutBytes(ctx, "sha256-"+d.Digest, artifact); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Register(ctx, r); err != nil {
		t.Fatal(err)
	}
	if _, err := c.ApplyDesired(ctx, d); err != nil {
		t.Fatal(err)
	}
	if err := GuardManagedContainerOwner(ctx, control, c.cell, d.ManagedMember.VolumeID); !errors.Is(err, authority.ErrNotFound) {
		t.Fatalf("missing owner granted container authority: %v", err)
	}
	acquired, err := c.handleSession(ctx, signedHostRequest(t, hostKey, "session", entityid.New(), 0, struct {
		Kind string `json:"kind"`
	}{"acquire"}))
	if err != nil {
		t.Fatal(err)
	}
	s := acquired.(session)
	call := func(action string, stop *ManagedNativeStop) (managedNativeReply, error) {
		var reply managedNativeReply
		err := exchange(ctx, conn, c.cell, controllerKey.Public().(ed25519.PublicKey), signedHostRequest(t, hostKey, "managed-native", s.SessionID, s.Epoch, managedNativeQuery{Role: d.Role, Action: action, Stop: stop}), &reply)
		return reply, err
	}
	process := memberstatus.Process{PID: 4242, StartNonce: strings.Repeat("9", 32)}
	survivor := memberstatus.Survivor{MemberID: d.ManagedMember.Runtime.ReplicationPeerMemberID, Incarnation: strings.Repeat("a", 32)}
	command := ManagedDrainCommand{OperationID: entityid.New(), Node: d.Node, Role: d.Role, Epoch: control.Current().Epoch, DesiredGeneration: d.Generation,
		ExpectedETag: "authenticated-drain-root-etag-fixture", Member: d.ManagedMember.Member, Authority: d.ManagedMember.Authority, OCI: d.ManagedMember.OCI,
		VolumeID: d.ManagedMember.VolumeID, AttachmentID: d.ManagedMember.AttachmentID, ExpectedProcess: process, Survivor: survivor, SourceSequence: 1}
	identity := drainIdentity(command)
	proof := &memberstatus.ServingProof{SchemaVersion: 1, Nonce: strings.Repeat("b", 32), Process: process, Scope: identity.Scope, Authority: identity.Authority,
		Serving: true, Listeners: memberstatus.Listeners{Client: true, Replication: true},
		Object:      memberstatus.ObjectProof{RootSHA256: strings.Repeat("c", 64), TargetSHA256: strings.Repeat("d", 64), InboxArchiveSHA256AtRecovery: strings.Repeat("e", 64), LocalSourceSequence: 1},
		Replication: memberstatus.ReplicationProof{LocalSourceSequence: 1, PeerMemberID: survivor.MemberID, PeerIncarnation: survivor.Incarnation, CurrentAuthenticated: true, PeerDurableSequence: 1, PeerAppliedSequence: 1}}
	report := Report{Cell: d.Cell, Node: d.Node, Environment: d.Environment, Role: d.Role, Digest: d.Digest, Generation: d.Generation, SessionID: s.SessionID, Epoch: s.Epoch, State: "running", ObservedAt: time.Now().UTC(),
		Managed: &ManagedRuntimeReport{Member: d.ManagedMember.Member, Authority: d.ManagedMember.Authority, OCI: d.ManagedMember.OCI, VolumeID: command.VolumeID, AttachmentID: command.AttachmentID,
			AttachmentETag: d.ManagedMember.AttachmentETag, FileSystemUUID: d.ManagedMember.Runtime.FileSystemUUID, FileSystemType: "ext4", MountDevice: "/dev/sdb", MountPath: paths.mount, MountID: 7,
			ProcessPID: process.PID, ProcessBootID: process.StartNonce, ProcessStart: "12345", ProcessCgroup: "/fixture/terrabase", StorageRecovered: true, ListenerReady: true, ServingProof: proof}}
	if retainedOriginal {
		// Simulate the prior source's durable report using a genuinely signed
		// and authorized host request; the new source requires enrollment first.
		legacy := report
		legacyProcess := *report.Managed
		legacyProcess.ServingProof = nil
		legacy.Managed = &legacyProcess
		req := signedHostRequest(t, hostKey, "report", s.SessionID, s.Epoch, legacy)
		if _, _, err := c.authorize(ctx, req); err != nil {
			t.Fatal(err)
		}
		if err := validateManagedReportForDesired(legacy, d); err != nil {
			t.Fatal(err)
		}
		if _, err := c.cas(ctx, reportKey(c.cell, d.Node, d.Role), legacy, 0); err != nil {
			t.Fatal(err)
		}
	}
	// The write-only transition verifier must not be called for a retained
	// Desired read after the placement stage has advanced.
	c.managedDesiredVerifier = func(context.Context, Desired, Registration, Desired, bool) error {
		return errors.New("write transition closed")
	}
	initial, err := call("admit", nil)
	if err != nil || initial.Sequence == 0 || initial.Owner.Phase != "native" {
		t.Fatalf("signed enrollment: %+v %v", initial, err)
	}
	if retainedOriginal && (initial.Owner.Writer == nil || initial.Owner.ObservationOrigin != "retained-before-admission") {
		t.Fatal("enrollment lost retained original process")
	}
	if !retainedOriginal && (initial.Owner.Writer != nil || initial.Owner.ObservationOrigin != "original-unobserved") {
		t.Fatal("enrollment manufactured an absent original process")
	}
	if err := GuardManagedContainerOwner(ctx, control, c.cell, d.ManagedMember.VolumeID); !errors.Is(err, ErrNativePublicationUnsettled) {
		t.Fatalf("native owner granted container: %v", err)
	}
	report.ObservedAt = time.Now().UTC()
	if _, err := c.handleAuthorized(ctx, signedHostRequest(t, hostKey, "report", s.SessionID, s.Epoch, report)); err != nil {
		t.Fatal(err)
	}
	if !retainedOriginal {
		current, _, err := ReadManagedRuntimeOwner(ctx, control, c.cell, command.VolumeID)
		if err != nil || current.ObservationOrigin != "original-unobserved" || current.Writer == nil {
			t.Fatalf("new report erased unknown original: %+v %v", current, err)
		}
		if err := c.FenceManagedNative(ctx, d.Node, command.OperationID, strings.Repeat("b", 64), func(context.Context) error { return nil }); err == nil || errors.Is(err, ErrNativePublicationUnsettled) {
			t.Fatalf("unknown original acquired a completed native fence: %v", err)
		}
		current, _, err = ReadManagedRuntimeOwner(ctx, control, c.cell, command.VolumeID)
		if err != nil || current.Phase != "native" {
			t.Fatalf("unknown origin advanced before witness: %+v %v", current, err)
		}
		return
	}
	if err := c.RequestManagedDrain(ctx, command); err != nil {
		t.Fatal(err)
	}
	receipt := memberstatus.DrainReceipt{SchemaVersion: 1, OperationID: command.OperationID, RequestNonce: strings.Repeat("f", 32), RequestedProcess: process, DrainedProcess: process,
		Scope: identity.Scope, Authority: identity.Authority, LocalSourceOrigin: memberstatus.Origin{MemberID: identity.Scope.MemberID, Incarnation: identity.Scope.Incarnation},
		LocalSourceDurableSequence: 1, ArchivedSourceSequence: 1, ObjectRootSHA256: strings.Repeat("c", 64),
		Peer: memberstatus.DrainPeer{Origin: memberstatus.Origin{MemberID: survivor.MemberID, Incarnation: survivor.Incarnation}, DurableSequence: 1, AppliedSequence: 1}, ReplicationQuiesced: true}
	wire, err := json.Marshal(receipt)
	if err != nil {
		t.Fatal(err)
	}
	digest := fmt.Sprintf("%x", sha256.Sum256(wire))
	drain := ManagedDrainResult{Command: command, Envelope: memberstatus.DrainEnvelope{SchemaVersion: 1, Nonce: strings.Repeat("a", 32), Process: process, OperationID: command.OperationID, State: "complete", Receipt: &receipt, ReceiptSHA256: &digest}}
	if _, err := c.handleAuthorized(ctx, signedHostRequest(t, hostKey, "drain-result", s.SessionID, s.Epoch, drain)); err != nil {
		t.Fatal(err)
	}
	denied := errors.New("replacement qualification refused")
	if err := c.FenceManagedNative(ctx, d.Node, command.OperationID, strings.Repeat("b", 64), func(context.Context) error { return denied }); !errors.Is(err, denied) {
		t.Fatalf("unqualified replacement fenced native: %v", err)
	}
	agent := &Agent{cfg: AgentConfig{Cell: d.Cell, Node: d.Node, Environment: d.Environment, Conn: conn,
		Identity: hostKey, NATSUserPublicKey: r.NATSUserPublicKey, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey)},
		session: s, processID: s.SessionID}
	testManagedNativeRootFenceRefusal(t, ctx, agent, d, func() {
		if err := c.FenceManagedNative(ctx, d.Node, command.OperationID, strings.Repeat("b", 64), func(context.Context) error { return nil }); !errors.Is(err, ErrNativePublicationUnsettled) {
			t.Fatalf("fence result: %v", err)
		}
	})
	fenced, err := call("state", nil)
	if err != nil || fenced.Owner.Phase != "native-fenced" || fenced.Owner.Writer == nil || fenced.Owner.Stop != nil {
		t.Fatalf("retained fence: %+v %v", fenced, err)
	}
	if fenced.Owner.Writer.SessionID != s.SessionID || fenced.Owner.Writer.Process.ProcessStart != report.Managed.ProcessStart || !sameJSON(fenced.Owner.Native, initial.Owner.Native) {
		t.Fatal("fence replaced original native provenance")
	}
	currentDesired, _, found, err := c.readDesired(ctx, d.Node, d.Role)
	if err != nil || !found || !sameJSON(currentDesired, d) {
		t.Fatalf("fence removed DATA desired material: %v", err)
	}
	if err := GuardManagedContainerOwner(ctx, control, c.cell, command.VolumeID); !errors.Is(err, ErrNativePublicationUnsettled) {
		t.Fatalf("drain or fence granted container: %v", err)
	}
	writerDigest, err := managedOwnerDigest(fenced.Owner.Writer)
	if err != nil {
		t.Fatal(err)
	}
	stop := ManagedNativeStop{OwnerSequence: fenced.Sequence, Challenge: fenced.Owner.Challenge, WriterSHA256: writerDigest,
		ObservedAt: time.Now().UTC(), SessionID: s.SessionID, Registration: r}
	for _, mutate := range []func(*ManagedNativeStop){
		func(s *ManagedNativeStop) { s.WriterSHA256 = strings.Repeat("0", 64) },
		func(s *ManagedNativeStop) { s.OwnerSequence++ },
		func(s *ManagedNativeStop) { s.ObservedAt = time.Now().Add(-ReportMaxAge) },
	} {
		invalid := stop
		mutate(&invalid)
		if _, err := call("stop", &invalid); err == nil {
			t.Fatal("substituted or expired stop observation accepted")
		}
	}
	// This signed synthetic observer exercises retention only. No physical
	// cgroup, mount, OCI settlement, or container-completion credit is claimed.
	observed, err := call("stop", &stop)
	if err != nil || observed.Owner.Stop == nil || observed.Owner.Phase != "native-fenced" {
		t.Fatalf("signed observer retention: %+v %v", observed, err)
	}
	if err := GuardManagedContainerOwner(ctx, control, c.cell, command.VolumeID); !errors.Is(err, ErrNativePublicationUnsettled) {
		t.Fatalf("local stop manufactured publication closure: %v", err)
	}
	if !sameJSON(observed.Owner.Writer, fenced.Owner.Writer) {
		t.Fatal("observer replaced original writer identity")
	}
	if err := c.FenceManagedNative(ctx, d.Node, entityid.New(), strings.Repeat("b", 64), func(context.Context) error { return nil }); err == nil {
		t.Fatal("another replacement reused permanent fence")
	}
	// A new identity still addresses the same physical exclusion key.
	changed := d
	changed.Generation++
	changed.Environment = "staging"
	changedLaunch := *d.ManagedMember
	changedLaunch.Member.HostAttempt++
	changed.ManagedMember = &changedLaunch
	if managedOwnerKey(changed.Cell, changed.ManagedMember.VolumeID) != managedOwnerKey(d.Cell, d.ManagedMember.VolumeID) {
		t.Fatal("new identity escaped physical volume key")
	}
	reader := &Controller{cell: c.cell, mutations: control}
	retained, _, err := ReadManagedRuntimeOwner(ctx, reader.mutations, c.cell, command.VolumeID)
	if err != nil || retained.Phase != "native-fenced" || retained.Stop == nil {
		t.Fatalf("fresh controller lost permanent floor: %v", err)
	}
}

type managedFenceStopRunner struct {
	Runner
	attempted chan struct{}
	refusal   error
}

func (r *managedFenceStopRunner) Stop(context.Context, string) error {
	r.attempted <- struct{}{}
	return r.refusal
}

func testManagedNativeRootFenceRefusal(t *testing.T, parent context.Context, agent *Agent, desired Desired, fence func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	stopRefused := errors.New("synthetic runner cannot prove physical stop")
	stopped := make(chan struct{}, 1)
	agent.runner = &managedFenceStopRunner{attempted: stopped, refusal: stopRefused}
	// Keep the same production permit scope that reconcile retains through root acquisition.
	nativeContext, release, err := agent.acquireManagedNative(ctx, desired)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if err := agent.checkManagedNative(nativeContext, desired); err != nil {
		t.Fatal(err)
	}
	rootContext, releaseRoot, err := agent.acquireManagedNativeRoot(nativeContext, desired)
	if err != nil {
		t.Fatal(err)
	}
	defer releaseRoot()
	resumeRoot := make(chan struct{})
	rootReturned := make(chan error, 1)
	allowParentRelease := make(chan struct{})
	parentJoined := make(chan struct{})
	go func() {
		defer close(parentJoined)
		defer release()
		select {
		case <-resumeRoot:
		case <-ctx.Done():
			return
		}
		_, nestedRelease, err := agent.acquireManagedNativeRoot(nativeContext, desired)
		if nestedRelease != nil {
			nestedRelease()
		}
		rootReturned <- err
		select {
		case <-allowParentRelease:
		case <-ctx.Done():
		}
	}()
	fence()
	close(resumeRoot)
	select {
	case err := <-rootReturned:
		if !errors.Is(err, ErrManagedNativeFenced) {
			t.Fatalf("nested root acquisition did not refuse the signed fence: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("nested root acquisition joined its own held reconcile permit")
	}
	if nativeContext.Err() == nil || rootContext.Err() == nil || ctx.Err() != nil {
		t.Fatal("nested fence failed to cancel all permits independently of the parent session")
	}
	if _, _, err := agent.managedGate(desired).acquire(ctx, desired.ManagedMember.VolumeID); !errors.Is(err, ErrManagedNativeFenced) {
		t.Fatalf("nested fence left native admission open: %v", err)
	}
	var reply managedNativeReply
	if err := agent.request(ctx, "managed-native", managedNativeQuery{Role: desired.Role, Action: "state"}, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Owner.Phase != "native-fenced" || reply.Owner.Stop != nil {
		t.Fatal("nested refusal produced a premature stop acknowledgement")
	}
	observed := make(chan error, 1)
	go func() { observed <- agent.observeManagedNativeFence(ctx, desired, reply) }()
	select {
	case <-stopped:
		t.Fatal("observer stopped before the reconcile permit joined")
	case err := <-observed:
		t.Fatalf("observer returned before the reconcile permit joined: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	close(allowParentRelease)
	select {
	case <-parentJoined:
	case <-time.After(time.Second):
		t.Fatal("reconcile permit did not release after nested refusal")
	}
	select {
	case <-stopped:
		t.Fatal("observer stopped before the prior root permit joined")
	case err := <-observed:
		t.Fatalf("observer returned before the prior root permit joined: %v", err)
	case <-time.After(25 * time.Millisecond):
	}
	releaseRoot()
	select {
	case err := <-observed:
		if !errors.Is(err, stopRefused) {
			t.Fatalf("independent observer did not reach the stop capability after joining: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("independent observer remained blocked after all permits joined")
	}
	select {
	case <-stopped:
	default:
		t.Fatal("independent observer never attempted stop")
	}
	if err := agent.request(ctx, "managed-native", managedNativeQuery{Role: desired.Role, Action: "state"}, &reply); err != nil {
		t.Fatal(err)
	}
	if reply.Owner.Stop != nil {
		t.Fatal("synthetic runner manufactured a physical stop acknowledgement")
	}
}

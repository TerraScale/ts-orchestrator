//go:build linux

package host

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

func TestManagedVolumeInitDecisionNeverFormatsUnknownOrAdoptedData(t *testing.T) {
	pins := ManagedRuntimePins{FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4"}
	tests := []struct {
		name        string
		probe       volumeFilesystemProbe
		allowFormat bool
		consumed    bool
		want        volumeInitAction
		wantErr     bool
	}{
		{name: "exact formatted filesystem is adopted on restart", probe: volumeFilesystemProbe{FSUUID: pins.FileSystemUUID, FSType: pins.FileSystemType, Signatures: true}, consumed: true, want: volumeInitMount},
		{name: "exact formatted filesystem is mounted without formatting", probe: volumeFilesystemProbe{FSUUID: pins.FileSystemUUID, FSType: pins.FileSystemType, Signatures: true}, allowFormat: true, want: volumeInitMount},
		{name: "authorized blank volume is formatted once", probe: volumeFilesystemProbe{BlankSample: true}, allowFormat: true, want: volumeInitFormat},
		{name: "blank volume without signed format authority is held", probe: volumeFilesystemProbe{BlankSample: true}, wantErr: true},
		{name: "previously consumed blank volume is held", probe: volumeFilesystemProbe{BlankSample: true}, allowFormat: true, consumed: true, wantErr: true},
		{name: "foreign UUID is never overwritten", probe: volumeFilesystemProbe{FSUUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", FSType: "ext4", Signatures: true}, allowFormat: true, wantErr: true},
		{name: "foreign filesystem type is never overwritten", probe: volumeFilesystemProbe{FSUUID: pins.FileSystemUUID, FSType: "xfs", Signatures: true}, allowFormat: true, wantErr: true},
		{name: "signature without an identified filesystem is ambiguous", probe: volumeFilesystemProbe{Signatures: true, BlankSample: true}, allowFormat: true, wantErr: true},
		{name: "foreign signature beside the pinned filesystem is rejected", probe: volumeFilesystemProbe{FSUUID: pins.FileSystemUUID, FSType: pins.FileSystemType, ForeignSignatures: true}, allowFormat: true, wantErr: true},
		{name: "nonblank sample without an identified filesystem is ambiguous", probe: volumeFilesystemProbe{BlankSample: false}, allowFormat: true, wantErr: true},
		{name: "mounted device is never adopted or reformatted", probe: volumeFilesystemProbe{FSUUID: pins.FileSystemUUID, FSType: pins.FileSystemType, Mounted: true, Signatures: true}, allowFormat: true, wantErr: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := volumeInitActionFor(test.probe, pins, test.allowFormat, test.consumed)
			if (err != nil) != test.wantErr || got != test.want {
				t.Fatalf("volume initialization decision = %v, %v; want action %v, error=%t", got, err, test.want, test.wantErr)
			}
		})
	}
}

func TestManagedVolumeInitEffectsFormatOnceAndAdoptWithoutFormatting(t *testing.T) {
	pins := ManagedRuntimePins{FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4"}
	blank := volumeFilesystemProbe{BlankSample: true}
	formatted := volumeFilesystemProbe{FSUUID: pins.FileSystemUUID, FSType: pins.FileSystemType, Signatures: true}
	var calls []string
	completedLayout := false
	effects := volumeInitEffects{
		Consume: func() error {
			calls = append(calls, "consume")
			return nil
		},
		Format: func(context.Context) error {
			calls = append(calls, "format")
			return nil
		},
		Probe: func(context.Context) (volumeFilesystemProbe, error) {
			calls = append(calls, "verify-format")
			return formatted, nil
		},
		Mount: func(_ context.Context, complete bool) error {
			calls = append(calls, "mount")
			completedLayout = complete
			return nil
		},
	}
	if err := executeVolumeInitAction(t.Context(), pins, blank, true, false, time.Now().Add(time.Minute), effects); err != nil {
		t.Fatalf("authorized blank volume did not initialize: %v", err)
	}
	if want := []string{"consume", "format", "verify-format", "mount"}; !slices.Equal(calls, want) {
		t.Fatalf("fresh initialization effects = %v, want %v", calls, want)
	}
	if !completedLayout {
		t.Fatal("fresh filesystem mount did not request exact initial layout completion")
	}

	// A retry after formatting must recognize the exact filesystem and mount it
	// without consuming another permit or invoking mkfs.
	calls = nil
	completedLayout = false
	if err := executeVolumeInitAction(t.Context(), pins, formatted, false, true, time.Now().Add(time.Minute), effects); err != nil {
		t.Fatalf("exact formatted volume was not adopted on retry: %v", err)
	}
	if want := []string{"mount"}; !slices.Equal(calls, want) {
		t.Fatalf("restart adoption effects = %v, want %v", calls, want)
	}
	if !completedLayout {
		t.Fatal("restart adoption did not request completion of a crash-interrupted initial layout")
	}
}

func TestManagedVolumeInitFormatsPinnedXFSAndRejectsUnsupportedPins(t *testing.T) {
	blank := volumeFilesystemProbe{BlankSample: true}
	for _, fsType := range []string{"xfs", "btrfs"} {
		pins := ManagedRuntimePins{FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: fsType}
		var calls []string
		effects := volumeInitEffects{
			Consume: func() error { calls = append(calls, "consume"); return nil },
			Format:  func(context.Context) error { calls = append(calls, "format"); return nil },
			Probe: func(context.Context) (volumeFilesystemProbe, error) {
				return volumeFilesystemProbe{FSUUID: pins.FileSystemUUID, FSType: fsType, Signatures: true}, nil
			},
			Mount: func(context.Context, bool) error { calls = append(calls, "mount"); return nil },
		}
		err := executeVolumeInitAction(t.Context(), pins, blank, true, false, time.Now().Add(time.Minute), effects)
		if fsType == "xfs" {
			if err != nil || !slices.Equal(calls, []string{"consume", "format", "mount"}) {
				t.Fatalf("pinned xfs did not format once: %v calls=%v", err, calls)
			}
			continue
		}
		if err == nil || len(calls) != 0 {
			t.Fatalf("unsupported %s pin reached disk effects: %v calls=%v", fsType, err, calls)
		}
	}
}

func TestManagedVolumeInitFailuresNeverReachMountOrClaimReadiness(t *testing.T) {
	pins := ManagedRuntimePins{FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4"}
	blank := volumeFilesystemProbe{BlankSample: true}
	formatted := volumeFilesystemProbe{FSUUID: pins.FileSystemUUID, FSType: pins.FileSystemType, Signatures: true}
	consumeFailure := errors.New("format state persistence failed")
	formatFailure := errors.New("mkfs failed")
	layoutFailure := errors.New("initial directory layout failed")
	tests := []struct {
		name        string
		probe       volumeFilesystemProbe
		allowFormat bool
		consumed    bool
		expiresAt   time.Time
		consumeErr  error
		formatErr   error
		readback    volumeFilesystemProbe
		readbackErr error
		mountErr    error
		wantCalls   []string
		wantErr     bool
		wantCause   error
	}{
		{name: "foreign filesystem", probe: volumeFilesystemProbe{FSUUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", FSType: "ext4", Signatures: true}, allowFormat: true, wantErr: true},
		{name: "mounted disk", probe: volumeFilesystemProbe{Mounted: true, BlankSample: true}, allowFormat: true, wantErr: true},
		{name: "blank without OCI format authorization", probe: blank, wantErr: true},
		{name: "previously consumed blank disk", probe: blank, allowFormat: true, consumed: true, wantErr: true},
		{name: "expired format permit", probe: blank, allowFormat: true, expiresAt: time.Now().Add(-time.Minute), wantErr: true},
		{name: "format state persistence failure", probe: blank, allowFormat: true, expiresAt: time.Now().Add(time.Minute), consumeErr: consumeFailure, wantCalls: []string{"consume"}, wantErr: true, wantCause: consumeFailure},
		{name: "format failure leaves disk held", probe: blank, allowFormat: true, expiresAt: time.Now().Add(time.Minute), formatErr: formatFailure, wantCalls: []string{"consume", "format"}, wantErr: true, wantCause: formatFailure},
		{name: "wrong UUID after format is held", probe: blank, allowFormat: true, expiresAt: time.Now().Add(time.Minute), readback: volumeFilesystemProbe{FSUUID: "aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa", FSType: "ext4", Signatures: true}, wantCalls: []string{"consume", "format", "verify-format"}, wantErr: true},
		{name: "foreign signature after format is held", probe: blank, allowFormat: true, expiresAt: time.Now().Add(time.Minute), readback: volumeFilesystemProbe{FSUUID: pins.FileSystemUUID, FSType: "ext4", ForeignSignatures: true}, wantCalls: []string{"consume", "format", "verify-format"}, wantErr: true},
		{name: "format readback error is held", probe: blank, allowFormat: true, expiresAt: time.Now().Add(time.Minute), readbackErr: errors.New("filesystem readback failed"), wantCalls: []string{"consume", "format", "verify-format"}, wantErr: true},
		{name: "layout failure is propagated before readiness", probe: blank, allowFormat: true, expiresAt: time.Now().Add(time.Minute), readback: formatted, mountErr: layoutFailure, wantCalls: []string{"consume", "format", "verify-format", "mount"}, wantErr: true, wantCause: layoutFailure},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			calls := make([]string, 0, 4)
			readback := test.readback
			if readback == (volumeFilesystemProbe{}) && test.readbackErr == nil {
				readback = formatted
			}
			effects := volumeInitEffects{
				Consume: func() error {
					calls = append(calls, "consume")
					return test.consumeErr
				},
				Format: func(context.Context) error {
					calls = append(calls, "format")
					return test.formatErr
				},
				Probe: func(context.Context) (volumeFilesystemProbe, error) {
					calls = append(calls, "verify-format")
					return readback, test.readbackErr
				},
				Mount: func(context.Context, bool) error {
					calls = append(calls, "mount")
					return test.mountErr
				},
			}
			err := executeVolumeInitAction(t.Context(), pins, test.probe, test.allowFormat, test.consumed, test.expiresAt, effects)
			if (err != nil) != test.wantErr || !slices.Equal(calls, test.wantCalls) {
				t.Fatalf("effect result = %v, calls=%v; want error=%t calls=%v", err, calls, test.wantErr, test.wantCalls)
			}
			if test.wantCause != nil && !errors.Is(err, test.wantCause) {
				t.Fatalf("effect error %v does not preserve cause %v", err, test.wantCause)
			}
		})
	}
}

func TestManagedVolumeInitPermitRequiresCurrentSignedState(t *testing.T) {
	registration, desired, hostKey := managedContractFixture()
	registration.ManagedPlacement = &ManagedPlacementBinding{
		DatabaseID: "0000000000JJVVW9EMWY1PE1VX", PartitionID: "0000000000Z3WK359G2W66CVT8", SeatID: "000000000082AXF7GZQT1D126Y", IntentGeneration: 7,
		IntentPayloadDigest: strings.Repeat("c", 64), CanonicalRosterDigest: strings.Repeat("d", 64),
		ManagedHostProfileDigest: strings.Repeat("e", 64),
	}
	desired.ManagedMember.AttachmentETag = "attachment-etag-1"
	runtimeRoot, err := os.MkdirTemp("", "volume-init-")
	if err != nil {
		t.Fatalf("create short managed runtime root: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(runtimeRoot) })
	desired.ManagedMember.Runtime = &ManagedRuntimePins{
		DevicePath:     "/dev/sdb",
		FileSystemUUID: "12345678-1234-1234-1234-123456789abc", FileSystemType: "ext4",
		TrustedKeySHA256: strings.Repeat("1", 64), ServerCertificateSHA256: strings.Repeat("2", 64),
		ServerPrivateKeySHA256: strings.Repeat("3", 64), ClientCARootsSHA256: strings.Repeat("4", 64),
		ClientManagedMaterialManifestSHA256: strings.Repeat("5", 64),
		LiveS3ConfigSHA256:                  strings.Repeat("6", 64),
		LiveS3TargetSHA256:                  strings.Repeat("7", 64),
		LiveS3Credential:                    oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3},
		ReplicationListenAddress:            "10.0.0.11:7000",
		ReplicationPeerMemberID:             "01HW000000E008000000000002",
		ReplicationPeerAddress:              "10.0.0.12:7001",
		ReplicationServerCASHA256:           strings.Repeat("8", 64),
	}
	paths, err := runtimePaths(runtimeRoot, *desired.ManagedMember)
	if err != nil {
		t.Fatal(err)
	}
	desired.ManagedMember.Runtime.MountPath = paths.mount
	descriptor := hostboot.Descriptor{
		SchemaVersion: hostboot.SchemaVersion, Cell: "gru", Region: "GRU", Node: registration.Node,
		Owner: registration.ManagedOCI.Owner, FleetGeneration: registration.ManagedOCI.FleetGeneration,
		CreateKey: registration.ManagedOCI.CreateKey, ImageID: "ocid1.image.oc1..managed-host",
		DatabaseID: registration.ManagedPlacement.DatabaseID, PartitionID: registration.ManagedPlacement.PartitionID,
		SeatID: registration.ManagedPlacement.SeatID, HostAttempt: registration.ManagedMember.HostAttempt,
		IntentGeneration:         registration.ManagedPlacement.IntentGeneration,
		IntentPayloadDigest:      registration.ManagedPlacement.IntentPayloadDigest,
		CanonicalRosterDigest:    registration.ManagedPlacement.CanonicalRosterDigest,
		ManagedHostProfileDigest: registration.ManagedPlacement.ManagedHostProfileDigest,
		RuntimeManifestDigest:    strings.Repeat("a", 64),
	}
	bootDigest, err := descriptor.Digest()
	if err != nil {
		t.Fatalf("make exact signed boot descriptor: %v", err)
	}
	artifact := []byte("volume initialization desired artifact")
	digest := sha256.Sum256(artifact)
	desired.Digest = hex.EncodeToString(digest[:])

	var inspections atomic.Int32
	var denyInspection atomic.Bool
	var rotateSessionDuringInspection atomic.Bool
	var sessionRotationPerformed atomic.Bool
	observation := VolumeInitObservation{BootDescriptorSHA256: bootDigest, AllowFormat: true}
	controller, conn, store, _, controllerKey := testControllerWithVerifier(t,
		managedRegistrationVerifierFunc(func(context.Context, Registration) error { return nil }))
	controller.volumeInspector = func(ctx context.Context, gotDesired Desired, got Registration) (VolumeInitObservation, error) {
		inspections.Add(1)
		if gotDesired.ManagedMember == nil || !sameJSON(*gotDesired.ManagedMember, *desired.ManagedMember) ||
			got.ManagedOCI == nil || got.ManagedMember == nil ||
			gotDesired.ManagedMember.OCI != *got.ManagedOCI || gotDesired.ManagedMember.Member != *got.ManagedMember {
			return VolumeInitObservation{}, errors.New("inspector received another host or volume")
		}
		if denyInspection.Load() {
			return VolumeInitObservation{}, errors.New("owned attachment readback failed")
		}
		if rotateSessionDuringInspection.Swap(false) {
			key := sessionKey("gru", registration.Node)
			current, revision, exists, err := controller.sessionSnapshot(ctx, key)
			if err != nil || !exists {
				return VolumeInitObservation{}, errors.New("test could not read current host session")
			}
			current.SessionID = "248H248H248H248H248H248H24"
			current.Epoch++
			current.ExpiresAt = time.Now().Add(sessionTTL)
			current.LastNonce = "55555555555555555555555555555555"
			current.LastIssuedAt = time.Now().UTC()
			if _, err := controller.cas(ctx, key, current, revision); err != nil {
				return VolumeInitObservation{}, errors.New("test could not replace current host session")
			}
			sessionRotationPerformed.Store(true)
		}
		return observation, nil
	}

	registrationReceipt, err := controller.Register(t.Context(), registration)
	if err != nil {
		t.Fatalf("register managed host: %v", err)
	}
	registrationRevision := registrationReceipt.Revision
	if _, err := store.PutBytes(t.Context(), "sha256-"+desired.Digest, artifact); err != nil {
		t.Fatal(err)
	}
	desiredReceipt, err := controller.ApplyDesired(t.Context(), desired)
	if err != nil {
		t.Fatalf("apply managed desired: %v", err)
	}

	controllerCtx, cancelController := context.WithCancel(t.Context())
	controllerDone := make(chan error, 1)
	go func() { controllerDone <- controller.Run(controllerCtx) }()
	t.Cleanup(func() {
		cancelController()
		<-controllerDone
	})
	select {
	case <-controller.Ready():
	case err := <-controllerDone:
		t.Fatalf("controller stopped before ready: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("controller did not become ready")
	}

	const firstSessionID = "0H248H248H248H248H248H248H"
	acquire := signedHostRequest(t, hostKey, "session", firstSessionID, 0, struct {
		Kind string `json:"kind"`
	}{"acquire"})
	var currentSession session
	if err := exchange(t.Context(), conn, "gru", controllerKey.Public().(ed25519.PublicKey), acquire, &currentSession); err != nil {
		t.Fatalf("acquire host session: %v", err)
	}

	query := volumeInitQuery{Role: desired.Role, DesiredRevision: desiredReceipt.Revision,
		RegistrationRevision: registrationRevision}
	permitRequest := func(key ed25519.PrivateKey, sessionID string, epoch uint64, q volumeInitQuery) request {
		t.Helper()
		return signedHostRequest(t, key, "volume-init", sessionID, epoch, q)
	}
	requestPermit := func(req request) (volumeInitPermit, error) {
		t.Helper()
		var permit volumeInitPermit
		err := exchange(t.Context(), conn, "gru", controllerKey.Public().(ed25519.PublicKey), req, &permit)
		return permit, err
	}

	currentPermitRequest := permitRequest(hostKey, currentSession.SessionID, currentSession.Epoch, query)
	var signedPermit protocol.Envelope
	var permit volumeInitPermit
	err = exchangeWithEnvelope(t.Context(), conn, "gru", controllerKey.Public().(ed25519.PublicKey),
		currentPermitRequest, &permit, &signedPermit)
	if err != nil {
		t.Fatalf("current signed desired did not receive volume permit: %v", err)
	}
	if !sameJSON(permit.Desired, desired) || !sameJSON(permit.Registration, registration) ||
		permit.DesiredRevision != desiredReceipt.Revision || permit.RegistrationRevision != registrationRevision ||
		permit.SessionID != currentSession.SessionID || permit.Observation != observation {
		t.Fatalf("permit did not bind current desired, registration, session and OCI observation: %+v", permit)
	}
	if inspections.Load() != 1 {
		t.Fatalf("valid permit inspected OCI %d times, want once", inspections.Load())
	}
	config := VolumeInitConfig{Cell: registration.Cell, Node: registration.Node,
		Environment: registration.Environment, ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey),
		ManagedRuntimeRoot: runtimeRoot}
	metadata := VolumeInitMetadata{InstanceID: desired.ManagedMember.OCI.InstanceID, Descriptor: descriptor}
	verifiedPermit, err := verifyVolumeInitPermit(config, signedPermit, metadata)
	if err != nil || !sameJSON(verifiedPermit, permit) {
		t.Fatalf("helper rejected the real controller-signed permit: verified=%+v err=%v", verifiedPermit, err)
	}
	wrongInstance := metadata
	wrongInstance.InstanceID = "ocid1.instance.oc1..another-host"
	if _, err := verifyVolumeInitPermit(config, signedPermit, wrongInstance); err == nil {
		t.Fatal("signed permit was accepted for a different OCI instance")
	}
	wrongBootDescriptor := metadata
	wrongBootDescriptor.Descriptor.RuntimeManifestDigest = strings.Repeat("b", 64)
	if _, err := verifyVolumeInitPermit(config, signedPermit, wrongBootDescriptor); err == nil {
		t.Fatal("signed permit was accepted with a different boot descriptor")
	}
	issuedAt := time.Now().Add(-time.Minute).UTC()
	expiredPermit, err := protocol.SignEnvelope([]byte(signedPermit.Payload), protocol.EnvelopeScope{
		Region: registration.Cell, Kind: "host.response.volume-init", Actor: "controller",
		OperationID: signedPermit.OperationID, Epoch: signedPermit.Epoch,
	}, issuedAt, issuedAt.Add(requestTTL), controllerKey)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := verifyVolumeInitPermit(config, expiredPermit, metadata); err == nil {
		t.Fatal("expired controller-signed volume permit was accepted")
	}

	// A host that learned one desired cannot prepare its disk after the desired
	// revision advances, even though its role and logical member are unchanged.
	changedArtifact := []byte("replacement desired artifact")
	changedDigest := sha256.Sum256(changedArtifact)
	if _, err := store.PutBytes(t.Context(), "sha256-"+hex.EncodeToString(changedDigest[:]), changedArtifact); err != nil {
		t.Fatal(err)
	}
	newDesired := desired
	newDesired.Generation++
	newDesired.Digest = hex.EncodeToString(changedDigest[:])
	newReceipt, err := controller.ApplyDesired(t.Context(), newDesired)
	if err != nil {
		t.Fatalf("advance managed desired: %v", err)
	}
	if newReceipt.Revision == query.DesiredRevision {
		t.Fatal("fixture did not advance the desired revision")
	}
	if _, err := requestPermit(permitRequest(hostKey, currentSession.SessionID, currentSession.Epoch, query)); err == nil {
		t.Fatal("stale desired revision received a volume initialization permit")
	}
	if inspections.Load() != 1 {
		t.Fatalf("stale desired reached OCI inspector: calls=%d", inspections.Load())
	}

	// Rotate the registered key and generation, then use the new current session
	// with the old registration revision. A valid host signature alone cannot
	// revive a permit from the previous registration.
	newPublic, newHostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rotatedRegistration := registration
	rotatedRegistration.Generation++
	rotatedRegistration.PublicKey = base64.StdEncoding.EncodeToString(newPublic)
	rotatedReceipt, err := controller.Register(t.Context(), rotatedRegistration)
	if err != nil {
		t.Fatalf("rotate host registration: %v", err)
	}
	if rotatedReceipt.Revision == registrationRevision {
		t.Fatal("fixture did not advance the registration revision")
	}
	const secondSessionID = "00000000000000000000000002"
	rotatedAcquire := signedHostRequest(t, newHostKey, "session", secondSessionID, 0, struct {
		Kind string `json:"kind"`
	}{"acquire"})
	var rotatedSession session
	if err := exchange(t.Context(), conn, "gru", controllerKey.Public().(ed25519.PublicKey), rotatedAcquire, &rotatedSession); err != nil {
		t.Fatalf("acquire rotated host session: %v", err)
	}
	currentQuery := volumeInitQuery{Role: desired.Role, DesiredRevision: newReceipt.Revision,
		RegistrationRevision: registrationRevision}
	if _, err := requestPermit(permitRequest(newHostKey, rotatedSession.SessionID, rotatedSession.Epoch, currentQuery)); err == nil {
		t.Fatal("stale registration revision received a volume initialization permit")
	}
	if inspections.Load() != 1 {
		t.Fatalf("stale registration reached OCI inspector: calls=%d", inspections.Load())
	}

	// Replacing an expired session makes requests signed by its old session ID
	// invalid, even when the host registration and desired revisions are current.
	stateKey := sessionKey("gru", registration.Node)
	current, sessionRevision, exists, err := controller.sessionSnapshot(t.Context(), stateKey)
	if err != nil || !exists {
		t.Fatalf("read rotated session before expiry: exists=%t err=%v", exists, err)
	}
	current.ExpiresAt = time.Now().Add(-time.Second)
	if _, err := controller.cas(t.Context(), stateKey, current, sessionRevision); err != nil {
		t.Fatalf("expire current host session: %v", err)
	}
	const thirdSessionID = "0000000000RYN967Q4ZZSYRSS0"
	thirdAcquire := signedHostRequest(t, newHostKey, "session", thirdSessionID, 0, struct {
		Kind string `json:"kind"`
	}{"acquire"})
	var thirdSession session
	if err := exchange(t.Context(), conn, "gru", controllerKey.Public().(ed25519.PublicKey), thirdAcquire, &thirdSession); err != nil {
		t.Fatalf("replace expired host session: %v", err)
	}
	currentQuery.RegistrationRevision = rotatedReceipt.Revision
	if _, err := requestPermit(permitRequest(newHostKey, rotatedSession.SessionID, rotatedSession.Epoch, currentQuery)); err == nil {
		t.Fatal("permit was issued to the replaced host session")
	}
	if inspections.Load() != 1 {
		t.Fatalf("stale session reached OCI inspector: calls=%d", inspections.Load())
	}

	// A current session and desired still cannot authorize local disk writes if
	// independent OCI ownership inspection fails.
	denyInspection.Store(true)
	if _, err := requestPermit(permitRequest(newHostKey, thirdSession.SessionID, thirdSession.Epoch, currentQuery)); err == nil {
		t.Fatal("OCI inspection failure returned a volume initialization permit")
	}
	if inspections.Load() != 2 {
		t.Fatalf("inspector denial was not observed exactly once: calls=%d", inspections.Load())
	}
	denyInspection.Store(false)
	lateSessionRequest := permitRequest(newHostKey, thirdSession.SessionID, thirdSession.Epoch, currentQuery)
	var lateSignedPermit protocol.Envelope
	var latePermit volumeInitPermit
	if err := exchangeWithEnvelope(t.Context(), conn, "gru", controllerKey.Public().(ed25519.PublicKey),
		lateSessionRequest, &latePermit, &lateSignedPermit); err != nil {
		t.Fatalf("valid replacement session did not receive a signed permit: %v", err)
	}
	if lateSignedPermit.Epoch != thirdSession.Epoch || latePermit.Desired.AuthorityEpoch == lateSignedPermit.Epoch {
		t.Fatalf("fixture did not distinguish host session epoch from regional authority epoch: session=%d desired=%d",
			lateSignedPermit.Epoch, latePermit.Desired.AuthorityEpoch)
	}
	verifiedLatePermit, err := verifyVolumeInitPermit(config, lateSignedPermit, metadata)
	if err != nil || !sameJSON(verifiedLatePermit, latePermit) {
		t.Fatalf("helper rejected permit for current replacement session: verified=%+v err=%v", verifiedLatePermit, err)
	}
	if inspections.Load() != 3 {
		t.Fatalf("replacement session inspected OCI %d times, want three total valid-target calls", inspections.Load())
	}

	// Exercise the real agent caller with a local helper socket. It must send
	// the controller-signed permit, then independently reject helper success
	// until the signed mount is visible at the pinned path.
	helpers := []struct {
		name    string
		ack     byte
		wantErr string
	}{
		{name: "helper success still requires mount readback", ack: 0, wantErr: "volume initializer mount readback"},
		{name: "helper denial stops volume setup", ack: 1, wantErr: "fixed volume initializer did not establish"},
	}
	agent := &Agent{cfg: AgentConfig{Cell: registration.Cell, Node: registration.Node,
		Environment: registration.Environment, Conn: conn, Identity: newHostKey,
		ClockCheck:          func() error { return nil },
		NATSUserPublicKey:   rotatedRegistration.NATSUserPublicKey,
		ControllerPublicKey: controllerKey.Public().(ed25519.PublicKey), ManagedRuntimeRoot: runtimeRoot,
		VolumeInitSocket: filepath.Join(t.TempDir(), "volume-init.sock")}, processID: thirdSession.SessionID}
	if err := agent.acceptSession(thirdSession); err != nil {
		t.Fatalf("accept current replacement session: %v", err)
	}
	latestTarget := desiredReply{Desired: &newDesired, Revision: newReceipt.Revision,
		Registration: &rotatedRegistration, RegistrationRevision: rotatedReceipt.Revision}
	for _, test := range helpers {
		t.Run(test.name, func(t *testing.T) {
			captured := startVolumeInitHelperCapture(t, agent.cfg.VolumeInitSocket, config, metadata, test.ack,
				thirdSession.SessionID, latestTarget)
			err := agent.ensureManagedVolume(t.Context(), newDesired, latestTarget)
			if err == nil || !strings.Contains(err.Error(), test.wantErr) {
				t.Fatalf("agent accepted helper outcome without required verification: %v", err)
			}
			select {
			case got := <-captured:
				if got.err != nil {
					t.Fatalf("fake helper could not verify caller's signed permit: %v", got.err)
				}
				if got.permit.SessionID != thirdSession.SessionID ||
					got.permit.DesiredRevision != latestTarget.Revision ||
					got.permit.RegistrationRevision != latestTarget.RegistrationRevision {
					t.Fatalf("agent forwarded permit for another session or desired: %+v", got.permit)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("agent did not invoke the fixed volume initializer")
			}
		})
	}

	rotateSessionDuringInspection.Store(true)
	if _, err := requestPermit(permitRequest(newHostKey, thirdSession.SessionID, thirdSession.Epoch, currentQuery)); err == nil {
		t.Fatal("permit was issued after the inspected host session was replaced")
	}
	if !sessionRotationPerformed.Load() || inspections.Load() != 6 {
		t.Fatalf("session replacement race was not exercised: replaced=%t inspector calls=%d",
			sessionRotationPerformed.Load(), inspections.Load())
	}
}

type volumeInitHelperCapture struct {
	permit volumeInitPermit
	err    error
}

func startVolumeInitHelperCapture(t *testing.T, socketPath string, config VolumeInitConfig,
	metadata VolumeInitMetadata, ack byte, sessionID string, target desiredReply,
) <-chan volumeInitHelperCapture {
	t.Helper()
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("listen for fake volume initializer: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	captured := make(chan volumeInitHelperCapture, 1)
	go func() {
		connection, err := listener.Accept()
		if err != nil {
			captured <- volumeInitHelperCapture{err: err}
			return
		}
		defer connection.Close()

		var size [4]byte
		if _, err := io.ReadFull(connection, size[:]); err != nil {
			captured <- volumeInitHelperCapture{err: err}
			return
		}
		length := binary.BigEndian.Uint32(size[:])
		if length == 0 || length > 64<<10 {
			captured <- volumeInitHelperCapture{err: errors.New("forwarded permit length is outside the helper wire bound")}
			return
		}
		wire := make([]byte, length)
		if _, err := io.ReadFull(connection, wire); err != nil {
			captured <- volumeInitHelperCapture{err: err}
			return
		}
		var signed protocol.Envelope
		if err := protocol.DecodeStrict(wire, &signed, 64<<10); err != nil {
			captured <- volumeInitHelperCapture{err: err}
			return
		}
		permit, err := verifyVolumeInitPermit(config, signed, metadata)
		if err == nil && (target.Desired == nil || target.Registration == nil ||
			permit.SessionID != sessionID || permit.DesiredRevision != target.Revision ||
			permit.RegistrationRevision != target.RegistrationRevision ||
			!sameJSON(permit.Desired, *target.Desired) || !sameJSON(permit.Registration, *target.Registration)) {
			err = errors.New("forwarded permit differs from the current session or desired target")
		}
		response := ack
		if err != nil {
			response = 1
		}
		if _, writeErr := connection.Write([]byte{response}); err == nil && writeErr != nil {
			err = writeErr
		}
		captured <- volumeInitHelperCapture{permit: permit, err: err}
	}()
	return captured
}

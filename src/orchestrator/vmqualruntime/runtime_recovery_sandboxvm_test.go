//go:build sandboxvm

package vmqualruntime

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"gopkg.in/yaml.v2"
	"reflect"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/vmcontrolseed"
	"terrascale.tech/orchestrator/src/orchestrator/vmimage"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualbootstrap"
	"testing"

	"terrascale.tech/orchestrator/src/orchestrator/sandboxvm"
	"terrascale.tech/orchestrator/src/orchestrator/vmdisk"
	"terrascale.tech/orchestrator/src/orchestrator/vmguest"
	"terrascale.tech/orchestrator/src/orchestrator/vmnet"
	"terrascale.tech/orchestrator/src/orchestrator/vmqual"
	"terrascale.tech/orchestrator/src/orchestrator/vmqualsuite"
)

func TestRecoveryDataDrivePlanPreservesVMDiskContract(t *testing.T) {
	digest := strings.Repeat("a", 64)
	plan := vmdisk.BootPlan{
		RunID:                       "qualification-run",
		DriveID:                     "gru-member-2",
		Generation:                  7,
		Activation:                  vmdisk.ActivationNextBoot,
		RequiresStoppedGuest:        true,
		Attachment:                  vmdisk.AttachmentAttached,
		Path:                        "/var/lib/terrascale/drives/gru-member-2/data-7.ext4",
		Size:                        64 << 20,
		SHA256:                      digest,
		ReadOnly:                    true,
		RequiresGuestFilesystemFill: false,
		Filesystem:                  vmdisk.DefaultFilesystem(),
	}
	got, err := recoveryDataDrivePlan(plan, plan.RunID, plan.DriveID)
	if err != nil {
		t.Fatal(err)
	}
	want := sandboxvm.DataDrivePlan{
		DriveID: plan.DriveID, Generation: plan.Generation, Attached: true,
		Path: plan.Path, Size: plan.Size, SHA256: plan.SHA256, ReadOnly: true,
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("translated plan = %+v, want %+v", got, want)
	}

	plan.Attachment = vmdisk.AttachmentDetached
	plan.Path, plan.SHA256, plan.ReadOnly = "", "", false
	got, err = recoveryDataDrivePlan(plan, plan.RunID, plan.DriveID)
	if err != nil {
		t.Fatal(err)
	}
	want = sandboxvm.DataDrivePlan{DriveID: plan.DriveID, Generation: plan.Generation, Size: plan.Size}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("translated detached plan = %+v, want %+v", got, want)
	}
}

func TestRecoveryDataDrivePlanRejectsInconsistentRequirements(t *testing.T) {
	valid := vmdisk.BootPlan{
		RunID: "qualification-run", DriveID: "gru-member-2", Generation: 2,
		Activation: vmdisk.ActivationNextBoot, RequiresStoppedGuest: true,
		Attachment: vmdisk.AttachmentAttached, Path: "/data.ext4", Size: 64 << 20,
		SHA256: strings.Repeat("b", 64), Filesystem: vmdisk.DefaultFilesystem(),
	}
	cases := map[string]func(*vmdisk.BootPlan){
		"foreign run":     func(plan *vmdisk.BootPlan) { plan.RunID = "other-run" },
		"live activation": func(plan *vmdisk.BootPlan) { plan.RequiresStoppedGuest = false },
		"missing digest":  func(plan *vmdisk.BootPlan) { plan.SHA256 = "" },
		"fault adapter":   func(plan *vmdisk.BootPlan) { plan.RequiresRuntimeFaultAdapter = true },
		"fill action":     func(plan *vmdisk.BootPlan) { plan.FillToENOSPC = true },
		"detached read-only": func(plan *vmdisk.BootPlan) {
			plan.Attachment, plan.Path, plan.SHA256, plan.ReadOnly = vmdisk.AttachmentDetached, "", "", true
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			plan := valid
			mutate(&plan)
			if _, err := recoveryDataDrivePlan(plan, valid.RunID, valid.DriveID); err == nil {
				t.Fatalf("inconsistent plan was accepted: %+v", plan)
			}
		})
	}
}

func TestRecoveryExpansionTargetIsBoundedByDiskBudget(t *testing.T) {
	if got, err := recoveryExpansionTarget(64<<20, 384<<20, 8<<30); err != nil || got != 128<<20 {
		t.Fatalf("default expansion target = %d, err=%v", got, err)
	}
	if got, err := recoveryExpansionTarget(64<<20, 120<<20, 132<<20); err != nil || got != 76<<20 {
		t.Fatalf("budget-limited expansion target = %d, err=%v", got, err)
	}
	if _, err := recoveryExpansionTarget(64<<20, 120<<20, 124<<20); err == nil {
		t.Fatal("sub-minimum expansion budget was accepted")
	}
}

func TestRecoveryStorageEvidenceRequiresGuestDeviceAndWrite(t *testing.T) {
	observe := vmguest.StorageObservation{
		Action: vmguest.StorageActionObserve, Device: recoveryDataDevice,
		MountPath: recoveryDataMount, Filesystem: vmdisk.FilesystemExt4,
		Mounted: true, TotalBytes: 64 << 20, Healthy: true,
	}
	if !recoveryHealthyStorage(observe) {
		t.Fatalf("healthy storage was rejected: %+v", observe)
	}
	observe.Device = "/dev/vdc"
	if recoveryHealthyStorage(observe) {
		t.Fatal("foreign guest device was accepted")
	}
}

func TestRecoveryShapeFallbackUsesOCIReconcilerAndHTTPProvider(t *testing.T) {
	factory := recoverySeedFactory(t)
	observation, err := factory.ExhaustA1AndFallback(context.Background(), vmqual.Guest{
		ID: "gru-member-2", Region: vmnet.GRU,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(observation.Attempts, []string{recoveryPrimaryShape, recoveryFallbackShape}) {
		t.Fatalf("shape attempts = %v", observation.Attempts)
	}
	if !observation.A1CapacityExhausted || observation.SelectedShape != recoveryFallbackShape ||
		observation.SelectedArchitecture != "amd64" || !observation.ReplacementReady {
		t.Fatalf("shape fallback observation = %+v", observation)
	}
	if err := vmqualsuite.ValidateShapeFallback(observation); err != nil {
		t.Fatalf("validated fallback: %v", err)
	}
}

func TestRecoveryCertificateUsesExpiredRenewalAndTLSReadback(t *testing.T) {
	observation, err := exerciseCertificateRotation(context.Background(), "gru")
	if err != nil {
		t.Fatal(err)
	}
	if observation.ExpiredSerial == observation.RotatedSerial || !observation.ExpiredRejected ||
		!observation.RotatedAccepted || !observation.ServiceHealthy {
		t.Fatalf("certificate rotation observation = %+v", observation)
	}
	if err := vmqualsuite.ValidateCertificateRotation(observation); err != nil {
		t.Fatalf("validated certificate rotation: %v", err)
	}
}

func TestRecoveryClockFailsClosedWithoutTerraBaseEvidence(t *testing.T) {
	observation, err := (&firecrackerFactory{}).SkewClockAndRepair(context.Background(), vmqual.Guest{})
	if !errors.Is(err, errRecoveryClockUnavailable) {
		t.Fatalf("clock error = %v", err)
	}
	if observation.WritesFenced || observation.WritesAdmittedAfter || observation.SuspectHLCMinted {
		t.Fatalf("unobserved clock claims = %+v", observation)
	}
}

func recoverySeedFactory(t *testing.T) *firecrackerFactory {
	t.Helper()
	plan, err := vmnet.Plan(vmnet.DefaultConfig())
	if err != nil {
		t.Fatal(err)
	}
	authority, err := newQualificationNATSAuthority(plan)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(authority.close)
	var guests []vmcontrolseed.Guest
	for _, region := range plan.Regions {
		if region.Code != vmnet.GRU {
			continue
		}
		for _, guest := range region.Guests {
			guests = append(guests, vmcontrolseed.Guest{ID: guest.ID, Address: guest.Address, CommandPrivateKey: authority.commandSigners["gru-controller-"+guest.ID].PrivatePEM})
		}
	}
	seeds, err := vmcontrolseed.GenerateGRU(plan.RunID, guests)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for _, seed := range seeds {
			seed.Clear()
		}
	})
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var artifacts []guestArtifactInput
	for _, name := range []string{"orchestrator", "terrabase", "ts-node"} {
		binary := []byte("signed recovery " + name)
		digest := sha256.Sum256(binary)
		artifacts = append(artifacts, guestArtifactInput{manifest: vmimage.GuestArtifact{Component: name, Version: "1.0.0", SHA256: hex.EncodeToString(digest[:]), Size: int64(len(binary)), Source: "https://releases.terrascale.tech:8443/releases/" + name + "/1.0.0/" + name}, binary: binary, signature: ed25519.Sign(private, binary)})
	}
	manifest, err := desiredHostManifest(artifacts, 8443)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := vmqualbootstrap.NewIssuer()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = issuer.Close() })
	return &firecrackerFactory{services: &qualificationRuntimeServices{plan: plan, natsAuthority: authority, controlSeeds: seeds, artifacts: artifacts, manifest: manifest, bootstrapIssuer: issuer, publicKey: public}}
}

func TestRecoverySeedBindsManifestWithoutPrivateMetadata(t *testing.T) {
	factory := recoverySeedFactory(t)
	guest := vmqual.Guest{ID: "gru-member-1", Region: vmnet.GRU}
	encoded, err := factory.recoveryHostCloudInit(guest)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	var cloud struct {
		Files []struct {
			Path     string `yaml:"path"`
			Content  string `yaml:"content"`
			Encoding string `yaml:"encoding"`
		} `yaml:"write_files"`
	}
	if err := yaml.Unmarshal(raw, &cloud); err != nil {
		t.Fatal(err)
	}
	seed, _, err := factory.services.Bootstrap(guest)
	if err != nil {
		t.Fatal(err)
	}
	defer seed.Controller.Clear()
	found := map[string][]byte{}
	for _, file := range cloud.Files {
		data := []byte(file.Content)
		if file.Encoding == "b64" {
			data, err = base64.StdEncoding.DecodeString(file.Content)
			if err != nil {
				t.Fatal(err)
			}
		}
		found[file.Path] = data
		for _, secret := range [][]byte{seed.NATSIdentity.NKeySeed, seed.NATSIdentity.TLSPrivateKey, seed.MembershipIdentityPrivateKey, seed.Controller.Files[vmcontrolseed.CommandKeyPath], seed.Controller.Files[vmcontrolseed.NKeyPath], seed.Controller.Files[vmcontrolseed.PrivateKeyPath], seed.Controller.Files[vmcontrolseed.ServerPrivateKeyPath]} {
			if len(secret) != 0 && bytes.Contains(data, secret) {
				t.Fatal("private credential entered user-data")
			}
		}
	}
	if !bytes.Equal(found["/var/lib/terrascale/ts-node/manifest.json"], seed.DesiredHostManifest) {
		t.Fatal("recovery manifest differs")
	}
	var config map[string]any
	if json.Unmarshal(found["/etc/terrascale/ts-node.json"], &config) != nil || config["nodeId"] != guest.ID || config["natsUrl"] != seed.Config.NATSURL {
		t.Fatal("guest configuration missing")
	}
	if _, err := (&firecrackerFactory{}).recoveryHostCloudInit(guest); err == nil {
		t.Fatal("configless recovery admitted")
	}
}

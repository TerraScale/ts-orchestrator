package hostagent

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
)

func hostStoragePlan(t *testing.T, a *BootstrapAuthority) controltransition.Plan {
	t.Helper()
	public := func(keyFile ...string) string {
		k, e := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if e != nil {
			t.Fatal(e)
		}
		raw, e := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if e != nil {
			t.Fatal(e)
		}
		if len(keyFile) > 0 {
			private, e := x509.MarshalPKCS8PrivateKey(k)
			if e != nil {
				t.Fatal(e)
			}
			encoded := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: private})
			if e = os.WriteFile(keyFile[0], encoded, 0600); e != nil {
				t.Fatal(e)
			}
			clear(private)
			clear(encoded)
		}
		return string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: raw}))
	}
	h := strings.Repeat("a", 64)
	p := controltransition.Plan{Version: 1, Mode: controltransition.Mode, PreliminaryScopeSHA256: h, EstateID: "launch", TransitionID: "first-r3", IssuedAt: time.Now().UTC().Add(-time.Minute), ExpiresAt: time.Now().UTC().Add(time.Hour), ClusterName: "control-r3", TrustBundleSHA256: h, SourceTopologyEpoch: 1, TargetTopologyEpoch: 2, GlobalElectionFloor: 1, RegionalElectionFloor: 1, Source: controltransition.Source{NodeID: "gru-1", ServerName: "source-r1", BootstrapGrantSHA256: h, InitialManifestSHA256: strings.Repeat("b", 64), CaptureManifestSHA256: h, LaunchSHA256: h, StoreScopeSHA256: h, ProfileSHA256: h, StoreDir: "/data/source", CaptureDir: "/data/capture", ArchiveDir: "/data/archive", ReceiptPublicKeyPEM: public()}, Limits: controltransition.Limits{MaxStoreBytes: 64 << 20, MaxStoreFiles: 10000, MaxSnapshotBytes: 8 << 20, MaxTransferBytes: 32 << 20, MaxRestoreBytes: 32 << 20}}
	if a.initialProof != nil {
		i, c := a.initialProof.Identity(), a.initialProof.Config()
		p.Source.NodeID = i.NodeID
		p.Source.ServerName = c.Broker.ServerName
		p.Source.BootstrapGrantSHA256 = i.GrantSHA256
		p.Source.InitialManifestSHA256 = i.ManifestSHA256
		p.Source.LaunchSHA256 = i.LaunchSHA256
		p.Source.StoreScopeSHA256 = i.StoreScopeSHA256
		p.Source.ProfileSHA256 = c.ProfileSHA256
		p.Source.StoreDir = c.Broker.StoreDir
	}
	for i, region := range []string{"gru", "sfo", "fra"} {
		d := controltransition.Destination{Region: region, NodeID: region + "-1", ServerName: region + "-r3", BootstrapGrantSHA256: h, PreparedManifestSHA256: strings.Repeat("b", 64), ActivationManifestSHA256: h, RouteURL: "nats-route://" + region + ".internal:6222", CertificateSHA256: strings.Repeat(string(rune('d'+i)), 64), ReceiptPublicKeyPEM: public(), PreliminaryStoreDir: "/data/preliminary", StoreDir: "/data/r3", StagingDir: "/data/staging", Objects: controltransition.ObjectLocation{OCIRegion: []string{"sa-saopaulo-1", "us-sanjose-1", "eu-frankfurt-1"}[i], Namespace: "tenancy", Bucket: region + "-control", BucketResourceID: "ocid1.bucket." + region, CompartmentID: "ocid1.compartment.launch", OwnershipObservationSHA256: h, Prefix: "control-transitions/first-r3"}}
		if a.initialProof == nil && strings.HasPrefix(a.grant.NodeID, region+"-") {
			d.NodeID = a.grant.NodeID
		}
		if d.NodeID == p.Source.NodeID {
			d.BootstrapGrantSHA256 = p.Source.BootstrapGrantSHA256
		}
		if d.NodeID == a.grant.NodeID && a.initialProof == nil {
			d.BootstrapGrantSHA256 = a.digest
			d.PreparedManifestSHA256 = a.manifestDigest
		}
		p.Destinations = append(p.Destinations, d)
	}
	for _, role := range []string{"global", "gru-regional"} {
		p.Accounts = append(p.Accounts, controltransition.Account{Role: role, SourceName: role, DestinationName: role, Streams: []controltransition.Stream{{Name: "EVENTS", SourceConfigSHA256: h, FinalConfigSHA256: h}}})
	}
	delivery, source, err := a.storageTransitionDelivery()
	if err != nil {
		t.Fatal(err)
	}
	if delivery != (controltransition.Delivery{}) {
		key := public(delivery.ReceiptPrivateKeyFile)
		if source {
			p.Source.ReceiptPublicKeyPEM = key
		} else {
			for i, d := range p.Destinations {
				if d.NodeID == a.grant.NodeID {
					p.Destinations[i].ReceiptPublicKeyPEM = key
				}
			}
		}
	}
	return p
}

func TestStorageTransitionDestinationDeliveryPinsAndRecoversWithoutNATS(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("requires root-owned delivery and receiver")
	}
	h := newTestHarness(t)
	spec := h.publish(t, "orchestrator", "1.0.0")
	spec.User = "terrascale-orchestrator"
	dir := t.TempDir()
	cfg := transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: "first-r3", NodeID: "sfo-1", Region: "sfo", ServerName: "sfo-r3", StoreDir: filepath.Join(spec.DataVolume, "store"), GrantFile: filepath.Join(dir, "prepare.json"), GrantPublicKeyFile: filepath.Join(dir, "public.pem"), StorageTransition: controltransition.Delivery{TransitionID: "first-r3", PlanFile: filepath.Join(dir, "plan.json"), ReceiptPrivateKeyFile: filepath.Join(dir, "receipt.pem")}}
	raw, err := json.Marshal(cfg, jsonv1.DefaultOptionsV1())
	if err != nil {
		t.Fatal(err)
	}
	spec.Arguments = transitiongrant.Arguments
	spec.Configuration = string(raw)
	manifest := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{spec}}
	signer, public, _, grant := bootstrapTestGrant(t, manifest)
	grant.NodeID = cfg.NodeID
	signed, err := SignBootstrapGrant(signer, grant)
	if err != nil {
		t.Fatal(err)
	}
	authority, err := parseBootstrapAuthority(cfg.NodeID, public, signed)
	if err != nil {
		t.Fatal(err)
	}
	journal, err := newCommandJournal(filepath.Join(h.lifecycle.dataRoot, hostmanifest.TsNodeComponentName, "command-journal"))
	if err != nil {
		t.Fatal(err)
	}
	if err = journal.initialize(); err != nil {
		t.Fatal(err)
	}
	epochs, err := nodeauthority.NewEpochStore(journal.dir, cfg.NodeID)
	if err != nil {
		t.Fatal(err)
	}
	defer epochs.Close()
	transport := &NatsTransport{authorizer: authority, epochs: epochs}
	if err = epochs.AdmitBootstrap(authority.digest, authority.manifestDigest); err != nil {
		t.Fatal(err)
	}
	if err = transport.pinDestinationStorageTransition(t.Context()); err != nil {
		t.Fatal(err)
	}
	pinPath := filepath.Join(journal.dir, "storage-transition-plan.json")
	if _, err = os.Stat(pinPath); !os.IsNotExist(err) {
		t.Fatal("missing delivery reported a pin", err)
	}
	p := hostStoragePlan(t, authority)
	plan, err := controltransition.SignPlan(signer, p)
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, _, _ := bootstrapTestGrant(t, manifest)
	foreignPlan, err := controltransition.SignPlan(foreign, p)
	if err != nil {
		t.Fatal(err)
	}
	expired := p
	expired.IssuedAt = time.Now().Add(-2 * time.Hour)
	expired.ExpiresAt = time.Now().Add(-time.Hour)
	expiredPlan, err := controltransition.SignPlan(signer, expired)
	if err != nil {
		t.Fatal(err)
	}
	for name, wire := range map[string][]byte{"foreign owner": foreignPlan, "expired": expiredPlan, "malformed": []byte("{}"), "noncanonical": append(bytes.Clone(plan), '\n')} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(cfg.StorageTransition.PlanFile, wire, 0600); err != nil {
				t.Fatal(err)
			}
			if err := transport.pinDestinationStorageTransition(t.Context()); err == nil {
				t.Fatal("invalid delivery pinned")
			}
			if _, err := os.Stat(pinPath); !os.IsNotExist(err) {
				t.Fatal("invalid delivery left a pin", err)
			}
		})
	}
	if err = os.WriteFile(cfg.StorageTransition.PlanFile, plan, 0600); err != nil {
		t.Fatal(err)
	}
	keyFile := cfg.StorageTransition.ReceiptPrivateKeyFile
	keyBytes, err := os.ReadFile(keyFile)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(keyBytes)
	if err = os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	if err = transport.pinDestinationStorageTransition(t.Context()); err == nil {
		t.Fatal("missing key acknowledged pin")
	}
	retained, err := os.ReadFile(pinPath)
	if err != nil {
		t.Fatal("missing key lost plan pin", err)
	}
	receiptPath := filepath.Join(journal.dir, "storage-transition-pin-receipt.json")
	if _, err = os.Stat(receiptPath); !os.IsNotExist(err) {
		t.Fatal("missing key left acknowledgement", err)
	}
	// Generate another host key at the same configured path. Its signature
	// must be refused because the immutable plan binds the original key.
	_ = hostStoragePlan(t, authority)
	if err = transport.pinDestinationStorageTransition(t.Context()); err == nil {
		t.Fatal("wrong key acknowledged pin")
	}
	if _, err = os.Stat(receiptPath); !os.IsNotExist(err) {
		t.Fatal("wrong key left acknowledgement", err)
	}
	if err = os.WriteFile(keyFile, keyBytes, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(keyFile, 0644); err != nil {
		t.Fatal(err)
	}
	if err = transport.pinDestinationStorageTransition(t.Context()); err == nil {
		t.Fatal("publicly readable key accepted")
	}
	if err = os.Chmod(keyFile, 0600); err != nil {
		t.Fatal(err)
	}
	if err = transport.pinDestinationStorageTransition(t.Context()); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(pinPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(retained, before) {
		t.Fatal("acknowledgement retry replaced pin")
	}
	ack, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := controltransition.VerifyPlan(public, plan)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := controltransition.VerifyPinReceipt(verified, ack)
	if err != nil || receipt.NodeID != cfg.NodeID || receipt.Role != "destination" || receipt.PinSHA256 != controltransition.Digest(before) {
		t.Fatal("lost acknowledgement binding", err)
	}
	if err = os.Remove(keyFile); err != nil {
		t.Fatal(err)
	}
	if err = epochs.Close(); err != nil {
		t.Fatal(err)
	}
	if err = ResumeLocalStorageTransitionPlan(t.Context(), h.lifecycle, cfg.NodeID, public, signed); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(pinPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("recovery changed pin", err)
	}
	again, err := os.ReadFile(receiptPath)
	if err != nil || !bytes.Equal(ack, again) {
		t.Fatal("restart changed acknowledgement", err)
	}
	if err = os.WriteFile(receiptPath, []byte("{}"), 0600); err != nil {
		t.Fatal(err)
	}
	if err = ResumeLocalStorageTransitionPlan(t.Context(), h.lifecycle, cfg.NodeID, public, signed); err == nil || errors.Is(err, nodeauthority.ErrStorageTransitionReceiptSignerRequired) {
		t.Fatal("corrupt receipt treated as missing signer", err)
	}
	corrupt, err := os.ReadFile(receiptPath)
	if err != nil || string(corrupt) != "{}" {
		t.Fatal("corrupt receipt overwritten", err)
	}
	if err = os.WriteFile(receiptPath, ack, 0600); err != nil {
		t.Fatal(err)
	}
	if err = ResumeLocalStorageTransitionPlan(t.Context(), h.lifecycle, cfg.NodeID, public, signed); err != nil {
		t.Fatal("key-free receipt recovery failed", err)
	}
	// A new valid signature on changed intent cannot replace a retained pin.
	p.ClusterName = "different-r3"
	changed, err := controltransition.SignPlan(signer, p)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(cfg.StorageTransition.PlanFile, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err = ResumeLocalStorageTransitionPlan(t.Context(), h.lifecycle, cfg.NodeID, public, signed); err == nil {
		t.Fatal("replacement delivery resumed")
	}
	after, err = os.ReadFile(pinPath)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("conflict changed pin", err)
	}
	if len(h.systemd.ops()) != 0 {
		t.Fatal("plan agreement performed systemd effects")
	}
}

func TestStorageTransitionSourceCommandPinsBeforeRefusingRetirement(t *testing.T) {
	delivery := controltransition.Delivery{TransitionID: "first-r3", PlanFile: filepath.Join(t.TempDir(), "plan.json"), ReceiptPrivateKeyFile: filepath.Join(t.TempDir(), "receipt.pem")}
	h, initial, _, _, path := initialHostFixture(t, delivery)
	signer, public, wire, _ := bootstrapTestGrant(t, initial)
	authority, err := NewBootstrapAuthority(testCommandAuthorizer{}, "gru-1", public, wire)
	if err != nil {
		t.Fatal(err)
	}
	transport, _ := bootstrapTestTransport(t, h, authority)
	oldDigest, err := hostmanifest.HostManifestSha256(initial)
	if err != nil {
		t.Fatal(err)
	}
	replacement := hostmanifest.HostManifest{Components: []hostmanifest.ComponentSpec{h.publish(t, "orchestrator", "2.0.0")}}
	command, err := hostmanifest.NewApplyManifestCommand("capture-transition", oldDigest, replacement)
	if err != nil {
		t.Fatal(err)
	}
	body, err := json.Marshal(command, jsonv1.DefaultOptionsV1())
	if err != nil {
		t.Fatal(err)
	}
	transport.authorizer = testCommandAuthorizer{}
	ctx, cancel, err := transport.authorizeLocked(&nats.Msg{Data: body, Header: nats.Header{internalCommandProof: []string{base64.StdEncoding.EncodeToString(body)}}})
	if err != nil {
		t.Fatal(err)
	}
	defer cancel()
	transport.authorizer = authority
	before, _ := os.ReadFile(path)
	ops := len(h.systemd.ops())
	if _, err = transport.applyManifest(ctx, command); err == nil {
		t.Fatal("missing plan retired source")
	}
	p := hostStoragePlan(t, authority)
	p.Source.CaptureManifestSHA256, _ = hostmanifest.HostManifestSha256(replacement)
	plan, err := controltransition.SignPlan(signer, p)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(delivery.PlanFile, plan, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = transport.applyManifest(ctx, command); !errors.Is(err, ErrStorageTransitionPreparationMissing) {
		t.Fatal(err)
	}
	if _, err = transport.epochs.ResumeStorageTransitionPlan(t.Context(), controltransition.Digest(plan)); err != nil {
		t.Fatal("source plan not pinned", err)
	}
	transport.authorizer = testCommandAuthorizer{}
	if _, err = transport.applyManifest(ctx, command); !errors.Is(err, controltransition.ErrPreparationMissing) {
		t.Fatal("runtime-only verifier bypassed barrier", err)
	}
	if _, err = initialgrant.AdmitComponent(t.Context(), initial.Components[0]); err != nil {
		t.Fatal("incomplete preparation retired source", err)
	}
	after, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(before, after) || len(h.systemd.ops()) != ops {
		t.Fatal("incomplete preparation changed manifest or units", err)
	}
	receiptPath := filepath.Join(transport.journal.dir, "storage-transition-pin-receipt.json")
	ack, err := os.ReadFile(receiptPath)
	if err != nil {
		t.Fatal(err)
	}
	verified, err := controltransition.VerifyPlan(public, plan)
	if err != nil {
		t.Fatal(err)
	}
	receipt, err := controltransition.VerifyPinReceipt(verified, ack)
	if err != nil || receipt.Role != "source" || receipt.CommandSHA256 != controltransition.Digest(body) {
		t.Fatal("source acknowledgement lost command binding", err)
	}
	if err = os.Remove(delivery.ReceiptPrivateKeyFile); err != nil {
		t.Fatal(err)
	}
	if err = transport.Close(); err != nil {
		t.Fatal(err)
	}
	if err = ResumeLocalStorageTransitionPlan(t.Context(), h.lifecycle, "gru-1", public, wire); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(receiptPath)
	if err != nil || !bytes.Equal(ack, again) {
		t.Fatal("source restart changed acknowledgement", err)
	}
}

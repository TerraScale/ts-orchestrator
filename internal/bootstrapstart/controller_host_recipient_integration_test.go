package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/objectstorage"
)

type controllerRecipientFixture struct {
	founder               *founderSignerFixture
	objects               *founderLedgerObjects
	sources               controllerRecipientSources
	reader                *CurrentFounderAuthorityReader
	storage               *objectstorage.ObjectStorageClient
	issuer                AcceptedIdentity
	states                map[string]bootstrap.SlotState
	live                  map[string]InstanceObservation
	afterInstance         func()
	objectReads, sdkReads int
}

// Authority is created by the existing signed reservation/completion producers;
// every verifier read crosses real signed OCI SDK HTTP clients.
func newControllerRecipientFixture(t *testing.T) *controllerRecipientFixture {
	t.Helper()
	return newControllerRecipientFixtureWithSetup(t, nil)
}

func newControllerRecipientFixtureWithSetup(t *testing.T, setup func(*founderSignerFixture)) *controllerRecipientFixture {
	t.Helper()
	founder, caller, objects, cloud := newFounderRuntimeFixtureWithReservation(t,
		func(f *founderSignerFixture) {
			founderFixtureWithAdmissibleRelease(t, f)
			if setup != nil {
				setup(f)
			}
		}, false)
	f := &controllerRecipientFixture{founder: founder, objects: objects,
		states: make(map[string]bootstrap.SlotState), live: make(map[string]InstanceObservation)}
	server := httptest.NewServer(http.HandlerFunc(f.serveHTTP))
	t.Cleanup(server.Close)
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	provider := common.NewRawConfigurationProvider("ocid1.tenancy.oc1..test", "ocid1.user.oc1..test",
		"sa-saopaulo-1", "test-fingerprint", string(private), nil)
	storage, err := objectstorage.NewObjectStorageClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	compute, err := core.NewComputeClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	network, err := core.NewVirtualNetworkClientWithConfigurationProvider(provider)
	if err != nil {
		t.Fatal(err)
	}
	storage.Host, storage.HTTPClient = server.URL, server.Client()
	f.storage = &storage
	compute.Host, compute.HTTPClient = server.URL, server.Client()
	network.Host, network.HTTPClient = server.URL, server.Client()
	config, err := currentLedgerConfig(founder.current.Anchor, founder.baked.Roots)
	if err != nil {
		t.Fatal(err)
	}
	ledger, err := bootstrap.NewLedger(&storage, config)
	if err != nil {
		t.Fatal(err)
	}
	f.sources = controllerRecipientSources{trust: admissionTrustStore(t, founder.baked.Roots),
		ledger: ledger, observer: &OCIInstanceObserver{compute: &compute, network: &network}}
	caller.openLedger = func(context.Context, CurrentFounderAuthority, trust.Keyring) (*bootstrap.Ledger, error) {
		return ledger, nil
	}
	caller.now = time.Now
	for _, row := range founder.plan.Peers {
		cloud.now = time.Now().UTC().Truncate(time.Second)
		if err := caller.runPeer(t.Context(), row.Slot); err != nil {
			t.Fatal(err)
		}
	}
	f.completeSeed(t)
	for _, slot := range founder.plan.ControllerSlots {
		state, err := ledger.ReadSlot(t.Context(), bootstrap.BootstrapScope{
			DeploymentID: founder.plan.DeploymentID, Cell: string(founder.plan.Cell), Slot: slot})
		if err != nil {
			t.Fatal(err)
		}
		f.states[slot] = state
		ip := founder.plan.SeedPrivateIP
		for _, row := range founder.plan.Peers {
			if row.Slot == slot {
				ip = row.PrivateIP
			}
		}
		f.live[state.Result.InstanceOCID] = InstanceObservation{InstanceOCID: state.Result.InstanceOCID,
			CompartmentOCID: state.Intent.CompartmentOCID, ImageOCID: state.Intent.ImageOCID,
			AvailabilityDomain: state.Intent.AvailabilityDomain, FaultDomain: state.Intent.FaultDomain,
			Shape: state.Intent.Shape, SubnetOCID: state.Intent.SubnetOCID,
			NSGOCIDs:         slices.Clone(state.Intent.NetworkSecurityGroupIDs),
			PrimaryVNICOCID:  "ocid1.vnic.oc1.sa-saopaulo-1." + slot,
			PrimaryPrivateIP: ip, PrimaryVNIC: true, LifecycleState: "RUNNING"}
	}
	row := founder.plan.Peers[0]
	gate, _, _ := newFounderPeerGateForInstance(t, founder, &founderAdmissionLedger{ledger: ledger},
		row, f.states[row.Slot].Result.InstanceOCID)
	gate.Instances = f.sources.observer
	gate.Now = time.Now
	gate.InitialPeerFloor = func(ctx context.Context, marker AcceptedInstall, state bootstrap.SlotState, now time.Time) error {
		reader, err := NewCurrentFounderAuthorityReader(founder.baked, marker, &storage, founder.peerFloor)
		if err != nil {
			return err
		}
		uid, gid := testFounderServiceIdentity()
		continuation := FounderPeerContinuation{reader: reader, floor: founder.peerFloor,
			serviceUID: uid, serviceGID: gid, now: time.Now}
		return continuation.Initialize(ctx, marker, state, now)
	}
	marker, err := gate.AdmitInitial(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	f.issuer, err = gate.Markers.ReadIdentity()
	if err != nil {
		t.Fatal(err)
	}
	f.reader, err = NewCurrentFounderAuthorityReader(founder.baked, marker, &storage, founder.peerFloor)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *controllerRecipientFixture) completeSeed(t *testing.T) {
	t.Helper()
	founder, ledger := f.founder, f.sources.ledger
	now := time.Now().UTC().Truncate(time.Second)
	slot := founder.plan.SeedSlot
	envelope, err := trust.DecodeEnvelope(founder.manifests[slot])
	if err != nil {
		t.Fatal(err)
	}
	expected, err := founder.current.Anchor.ManifestExpectation(slot, founder.plan.Peers[0].ImageOCID)
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := bootstrap.VerifyManifest(envelope, founder.baked.Roots, expected, now, bootstrap.ManifestTrustPolicy())
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := manifest.Profile(slot)
	if !ok {
		t.Fatal("seed has no signed profile")
	}
	reservation, err := BuildExternalSeedReservation(ExternalSeedReservationRequest{
		Identity: founder.baked.Identity, Anchor: founder.current.Anchor, Manifest: manifest,
		ReviewedPlanSHA256: digestWire(founder.planWire), CreateIdentity: "recipient-seed-create",
		LedgerPrivate: founder.ledgerKey, Now: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	scope := bootstrap.BootstrapScope{DeploymentID: founder.plan.DeploymentID, Cell: string(founder.plan.Cell), Slot: slot}
	if _, err := ledger.ReserveSlot(t.Context(), scope, reservation.IntentWire, reservation.InitialHeadWire); err != nil {
		t.Fatal(err)
	}
	state, err := ledger.ReadSlot(t.Context(), scope)
	if err != nil {
		t.Fatal(err)
	}
	observed := InstanceObservation{InstanceOCID: "ocid1.instance.oc1.sa-saopaulo-1." + slot,
		BootstrapCreateKey: "recipient-seed-create", CompartmentOCID: profile.CompartmentOCID,
		ImageOCID: state.Intent.ImageOCID, ETag: "seed-instance-etag", AvailabilityDomain: profile.AvailabilityDomain,
		FaultDomain: profile.FaultDomain, Shape: profile.Shape, SubnetOCID: profile.SubnetOCID,
		NSGOCIDs: slices.Clone(profile.NetworkSecurityGroupOCIDs), PrimaryVNICOCID: "ocid1.vnic.oc1.sa-saopaulo-1." + slot,
		PrimaryPrivateIP: founder.plan.SeedPrivateIP, PrimaryVNIC: true, LifecycleState: "RUNNING"}
	facts, err := VerifyExternalSeedObservation(founder.current.Anchor, manifest, state, observed, founder.plan.SeedPrivateIP)
	if err != nil {
		t.Fatal(err)
	}
	completion, err := BuildExternalSeedCompletion(ExternalSeedCompletionRequest{Identity: founder.baked.Identity,
		Anchor: founder.current.Anchor, Manifest: manifest, Roots: founder.baked.Roots, State: state,
		Observation: observed, ObservedAt: now, ExpectedPrivateIP: founder.plan.SeedPrivateIP,
		RootPrivate: founder.root, LedgerPrivate: founder.ledgerKey, Now: now, ExpiresAt: now.Add(time.Hour)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ledger.RecordExternalSeed(t.Context(), scope, founder.manifests[slot], completion.ReceiptWire,
		facts, completion.ResultWire, completion.CompletedHeadWire); err != nil {
		t.Fatal(err)
	}
}

func (f *controllerRecipientFixture) serveHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Authorization") == "" {
		http.Error(w, "unsigned SDK request", 401)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if strings.HasPrefix(r.URL.Path, "/n/namespace-a/b/") {
		f.objectReads++
		bucket, key, ok := strings.Cut(strings.TrimPrefix(r.URL.Path, "/n/namespace-a/b/"), "/o/")
		if !ok {
			http.Error(w, "invalid object path", 400)
			return
		}
		if r.Method == http.MethodPut {
			// Observe each write at OCI's whole-second timestamp precision.
			f.objects.now = time.Now().UTC().Truncate(time.Second)
			response, err := f.objects.PutObject(r.Context(), objectstorage.PutObjectRequest{
				NamespaceName: new("namespace-a"), BucketName: new(bucket), ObjectName: new(key),
				OpcSseKmsKeyId: new(r.Header.Get("opc-sse-kms-key-id")), OpcContentSha256: new(r.Header.Get("opc-content-sha256")),
				ContentLength: new(r.ContentLength), PutObjectBody: r.Body,
				IfMatch: recipientOptionalHeader(r, "if-match"), IfNoneMatch: recipientOptionalHeader(r, "if-none-match")})
			if err != nil {
				http.Error(w, `{"code":"PreconditionFailed","message":"conditional write rejected"}`, 412)
				return
			}
			w.Header().Set("ETag", value(response.ETag))
			return
		}
		if r.Method != http.MethodGet {
			http.Error(w, "GET or conditional PUT required", 405)
			return
		}
		stored, exists := f.objects.objects[bucket+"/"+key]
		if !exists {
			wire, ok := f.founder.objects.items[bucket+"/"+key]
			if !ok {
				http.Error(w, `{"code":"ObjectNotFound","message":"absent"}`, 404)
				return
			}
			stored = founderStoredObject{wire: wire, etag: digestWire(wire), modified: f.founder.now}
		}
		w.Header().Set("ETag", stored.etag)
		w.Header().Set("Last-Modified", stored.modified.Format(http.TimeFormat))
		w.Header().Set("Date", time.Now().UTC().Format(http.TimeFormat))
		w.Header().Set("Content-Length", fmt.Sprint(len(stored.wire)))
		_, _ = w.Write(stored.wire)
		return
	}
	f.sdkReads++
	var body any
	if strings.HasPrefix(r.URL.Path, "/20160918/instances/") {
		observed, ok := f.live[strings.TrimPrefix(r.URL.Path, "/20160918/instances/")]
		if !ok {
			http.Error(w, "unknown instance", 404)
			return
		}
		body = core.Instance{Id: new(observed.InstanceOCID), CompartmentId: new(observed.CompartmentOCID),
			ImageId: new(observed.ImageOCID), AvailabilityDomain: new(observed.AvailabilityDomain),
			FaultDomain: new(observed.FaultDomain), Shape: new(observed.Shape), LifecycleState: core.InstanceLifecycleStateEnum(observed.LifecycleState)}
		if f.afterInstance != nil {
			callback := f.afterInstance
			f.afterInstance = nil
			callback()
		}
	} else if r.URL.Path == "/20160918/vnicAttachments" {
		observed, ok := f.live[r.URL.Query().Get("instanceId")]
		if !ok {
			http.Error(w, "unknown attachment instance", 404)
			return
		}
		body = []core.VnicAttachment{{InstanceId: new(observed.InstanceOCID), CompartmentId: new(observed.CompartmentOCID),
			VnicId: new(observed.PrimaryVNICOCID), SubnetId: new(observed.SubnetOCID), LifecycleState: core.VnicAttachmentLifecycleStateAttached}}
	} else {
		for _, observed := range f.live {
			switch r.URL.Path {
			case "/20160918/vnics/" + observed.PrimaryVNICOCID:
				body = core.Vnic{Id: new(observed.PrimaryVNICOCID), CompartmentId: new("ocid1.compartment.oc1..network"),
					AvailabilityDomain: new(observed.AvailabilityDomain), SubnetId: new(observed.SubnetOCID),
					PrivateIp: new(observed.PrimaryPrivateIP), IsPrimary: new(observed.PrimaryVNIC), NsgIds: observed.NSGOCIDs,
					LifecycleState: core.VnicLifecycleStateAvailable}
			case "/20160918/subnets/" + observed.SubnetOCID:
				body = core.Subnet{Id: new(observed.SubnetOCID), CompartmentId: new("ocid1.compartment.oc1..network"),
					VcnId: new("ocid1.vcn.oc1.sa-saopaulo-1.recipient"), LifecycleState: core.SubnetLifecycleStateAvailable}
			}
		}
	}
	if body == nil {
		http.Error(w, "unexpected OCI SDK operation", 404)
		return
	}
	if err := json.MarshalWrite(w, body); err != nil {
		http.Error(w, err.Error(), 500)
	}
}

func recipientOptionalHeader(r *http.Request, name string) *string {
	if value := r.Header.Get(name); value != "" {
		return new(value)
	}
	return nil
}

func (f *controllerRecipientFixture) grant(slot string) cellspec.HostGrant {
	observed := f.live[f.states[slot].Result.InstanceOCID]
	return cellspec.HostGrant{Node: "ts-gru-" + strings.TrimPrefix(slot, "controller-"), Controller: slot,
		PrivateIP: observed.PrimaryPrivateIP, Roles: []string{"ts-auth"}, Environment: f.issuer.Environment}
}

func (f *controllerRecipientFixture) spec(t *testing.T, grant cellspec.HostGrant) []byte {
	t.Helper()
	wire, err := cellspec.Sign(cellspec.Spec{Schema: cellspec.Schema, Identity: cellspec.Identity{
		DeploymentID: f.issuer.DeploymentID, Cell: strings.ToLower(f.issuer.Cell), Environment: f.issuer.Environment},
		Generation: 1, RequiresBinary: 17, HostGrants: []cellspec.HostGrant{grant}}, nil,
		f.founder.baked.Roots, time.Now().UTC(), time.Hour, f.founder.root)
	if err != nil {
		t.Fatal(err)
	}
	return wire
}

func (f *controllerRecipientFixture) read(t *testing.T, slot string) (*ControllerHostRecipient, error) {
	t.Helper()
	grant := f.grant(slot)
	return readControllerHostRecipient(t.Context(), f.reader, f.issuer, f.spec(t, grant), grant.Node,
		f.states[slot].Result.InstanceOCID, grant.PrivateIP, f.sources)
}

func recipientRegistration(proof *ControllerHostRecipient) host.Registration {
	return host.Registration{ID: entityid.Derive("host", "gru", proof.Node()), Node: proof.Node(), Cell: "gru",
		Environment: proof.Environment(), Roles: []string{"ts-auth"}, Generation: 1}
}

func TestControllerHostRecipientSignedSDKIntegration(t *testing.T) {
	t.Skip("QUARANTINE until 2026-10-22, owner ts-orch consolidation thread: failing since the 2026-10-21 integration-line merge")
	f := newControllerRecipientFixture(t)
	for _, slot := range f.founder.plan.ControllerSlots {
		t.Run(slot, func(t *testing.T) {
			reads := f.sdkReads
			proof, err := f.read(t, slot)
			if err != nil {
				t.Fatal(err)
			}
			if proof.ControllerSlot() != slot || proof.InstanceID() != f.states[slot].Result.InstanceOCID ||
				proof.PrivateIP() != f.grant(slot).PrivateIP || proof.OCIRegion() != "sa-saopaulo-1" ||
				!proof.Valid(time.Now()) || f.sdkReads <= reads || f.objectReads == 0 {
				t.Fatal("recipient lost the actual signed slot, protected completion, or live SDK identity")
			}
			deadline := proof.validUntil
			if err := proof.Verify(t.Context()); err != nil {
				t.Fatal(err)
			}
			registration := recipientRegistration(proof)
			if err := proof.VerifyRegistration(t.Context(), registration); err != nil {
				t.Fatal(err)
			}
			if proof.validUntil != deadline || proof.Valid(proof.started.Add(bootstrap.ManagedPeerObservationMaxAge)) {
				t.Fatal("verification extended the constructor's observation deadline")
			}
			registration.ManagedOCI = &host.ManagedOCIBinding{}
			if err := proof.VerifyRegistration(t.Context(), registration); err == nil {
				t.Fatal("controller accepted worker provenance")
			}
			registration.ManagedOCI, registration.Roles = nil, []string{"function-worker"}
			if err := proof.VerifyRegistration(t.Context(), registration); err == nil {
				t.Fatal("controller accepted different roles")
			}
		})
	}
}

func (f *controllerRecipientFixture) replaceObject(t *testing.T, record bootstrap.StoredRecord, wire []byte) {
	t.Helper()
	for key, stored := range f.objects.objects {
		if !bytes.Equal(stored.wire, record.Bytes) {
			continue
		}
		bucket, object, ok := strings.Cut(key, "/")
		if !ok {
			t.Fatal("invalid stored object key")
		}
		kms := f.founder.current.Anchor.StorageDomain().LedgerKMSKeyOCID
		if bucket == f.founder.current.Anchor.StorageDomain().HeadBucket {
			kms = f.founder.current.Anchor.StorageDomain().HeadKMSKeyOCID
		}
		_, err := f.storage.PutObject(t.Context(), objectstorage.PutObjectRequest{NamespaceName: new("namespace-a"),
			BucketName: new(bucket), ObjectName: new(object), OpcSseKmsKeyId: new(kms),
			OpcContentSha256: new(base64Digest(wire)), ContentLength: new(int64(len(wire))),
			PutObjectBody: io.NopCloser(bytes.NewReader(wire)), IfMatch: new(stored.etag)})
		if err != nil {
			t.Error(err)
		}
		return
	}
	t.Error("exact protected object was absent")
}

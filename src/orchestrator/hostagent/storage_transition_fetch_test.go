package hostagent

import (
	"bytes"
	"context"
	jsonv1 "encoding/json"
	"encoding/json/v2"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
	fixture "terrascale.tech/orchestrator/src/orchestrator/sandboxproviders/ociinstance"
	"terrascale.tech/orchestrator/src/orchestrator/transitiongrant"
	"terrascale.tech/orchestrator/src/orchestrator/transitionreceipts"
)

func hostStorageRemoteLocation(t *testing.T, region string) *controltransition.PlanDeliveryObject {
	t.Helper()
	bucket := hostStorageBucket(region)
	digest, err := transitionreceipts.BucketObservationDigest(bucket)
	if err != nil {
		t.Fatal(err)
	}
	return &controltransition.PlanDeliveryObject{Region: region, Objects: controltransition.ObjectLocation{OCIRegion: map[string]string{"gru": "sa-saopaulo-1", "sfo": "us-sanjose-1", "fra": "eu-frankfurt-1"}[region], Namespace: bucket.Namespace, Bucket: bucket.Name, BucketResourceID: bucket.ID, CompartmentID: bucket.CompartmentID, OwnershipObservationSHA256: digest, Prefix: "control-transitions/first-r3"}}
}

func putHostRemotePlan(t *testing.T, d controltransition.Delivery, raw []byte) {
	t.Helper()
	o := d.PlanObject.Objects
	identity, err := ociinstance.NewFromConfig(t.Context(), ociinstance.Config{Region: o.OCIRegion, Qualification: d.OCIQualification}, func(path string) ([]byte, error) { return bootstrapcredentials.ReadFile(path, true, 64<<10) })
	if err != nil {
		t.Fatal(err)
	}
	defer identity.Close()
	transport, err := identity.NewTransport(provider.OCIServiceObjectStorage, controltransition.MaximumBytes+1)
	if err != nil {
		t.Fatal(err)
	}
	response, err := transport.PutObjectBody(t.Context(), provider.ObjectRef{Namespace: o.Namespace, Bucket: o.Bucket, Name: o.Prefix + "/plan.json"}, bytes.NewReader(raw), map[string]string{"If-None-Match": "*", "opc-meta-terrascale-sha256": controltransition.Digest(raw)})
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal("fixture plan upload failed", response.StatusCode)
	}
}

func TestStorageTransitionRemoteDeliveryRetainsOnlyAdmittedPlan(t *testing.T) {
	if os.Geteuid() != 0 || os.Getenv("TS_INITIAL_R1_ISOLATED_TEST") != "1" {
		t.Skip("requires isolated root /var/lib mount")
	}
	for _, mode := range []string{"valid", "foreign owner", "expired", "wrong grant", "wrong location", "malformed", "ownership", "cancelled"} {
		t.Run(mode, func(t *testing.T) {
			h := newTestHarness(t)
			spec := h.publish(t, "orchestrator", "1.0.0")
			spec.User = "terrascale-orchestrator"
			dir := t.TempDir()
			d := controltransition.Delivery{TransitionID: "first-r3", PlanFile: filepath.Join(dir, "plan.json"), ReceiptPrivateKeyFile: filepath.Join(dir, "receipt.pem"), PlanObject: hostStorageRemoteLocation(t, "sfo")}
			server := hostStoragePublicationFixture(t, &d, "sfo-1", "us-sanjose-1")
			cfg := transitiongrant.Config{Version: 1, Mode: transitiongrant.Mode, TransitionID: d.TransitionID, NodeID: "sfo-1", Region: "sfo", ServerName: "sfo-r3", StoreDir: filepath.Join(spec.DataVolume, "store"), GrantFile: filepath.Join(dir, "prepare.json"), GrantPublicKeyFile: filepath.Join(dir, "owner.pem"), StorageTransition: d}
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
			a, err := parseBootstrapAuthority(cfg.NodeID, public, signed)
			if err != nil {
				t.Fatal(err)
			}
			if _, _, found, err := a.readStorageTransition(t.Context(), false); err != nil || found {
				t.Fatal("absent remote plan treated as delivered", err)
			}
			if _, _, _, err := a.readStorageTransition(t.Context(), true); err == nil {
				t.Fatal("required missing plan accepted")
			}
			p := hostStoragePlan(t, a)
			switch mode {
			case "expired":
				p.IssuedAt = time.Now().Add(-2 * time.Hour)
				p.ExpiresAt = time.Now().Add(-time.Hour)
			case "wrong grant":
				p.Destinations[1].BootstrapGrantSHA256 = strings.Repeat("f", 64)
			case "wrong location":
				p.Destinations[1].Objects.Prefix = "other-prefix"
			case "foreign owner":
				signer, _, _, _ = bootstrapTestGrant(t, manifest)
			}
			plan, err := controltransition.SignPlan(signer, p)
			if err != nil {
				t.Fatal(err)
			}
			if mode == "malformed" {
				plan = []byte("{}")
			}
			putHostRemotePlan(t, d, plan)
			if mode == "ownership" {
				bucket := hostStorageBucket("sfo")
				bucket.CompartmentID = "ocid1.compartment.foreign"
				if err := server.SetBucket(fixture.Bucket{OCIRegion: d.PlanObject.Objects.OCIRegion, Observation: bucket}); err != nil {
					t.Fatal(err)
				}
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			if mode == "cancelled" {
				cancel()
			}
			before := len(server.Requests())
			verified, got, found, err := a.readStorageTransition(ctx, true)
			if mode != "valid" {
				if err == nil || found {
					t.Fatal("invalid remote plan admitted")
				}
				if _, err := os.Lstat(d.PlanFile); !os.IsNotExist(err) {
					t.Fatal("invalid remote plan retained", err)
				}
				if mode == "cancelled" && len(server.Requests()) != before {
					t.Fatal("cancelled delivery reached network")
				}
				return
			}
			if err != nil || !found || !bytes.Equal(got, plan) {
				t.Fatal("remote plan intake failed", err)
			}
			retained, err := bootstrapcredentials.ReadFile(d.PlanFile, true, controltransition.MaximumBytes)
			if err != nil || !bytes.Equal(retained, plan) {
				t.Fatal("local retention differs", err)
			}
			// Durable candidate pin and publication use the downloaded file directly.
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
			if err = epochs.AdmitBootstrap(a.digest, a.manifestDigest); err != nil {
				t.Fatal(err)
			}
			transport := &NatsTransport{authorizer: a, epochs: epochs}
			if err = transport.pinDestinationStorageTransition(t.Context()); err != nil {
				t.Fatal(err)
			}
			receipt, err := os.ReadFile(filepath.Join(journal.dir, "storage-transition-pin-receipt.json"))
			if err != nil {
				t.Fatal(err)
			}
			checkHostPublishedPin(t, server, verified, cfg.NodeID, receipt)
			// Retrieval is unnecessary once the exact plan is retained. Remove the
			// fixture credential to prove this is local recovery, not a second fetch.
			if err = os.Remove(d.OCIQualification.ClientPrivateKeyFile); err != nil {
				t.Fatal(err)
			}
			before = len(server.Requests())
			if _, got, found, err := a.readStorageTransition(t.Context(), true); err != nil || !found || !bytes.Equal(got, plan) {
				t.Fatal("retained plan required remote access", err)
			}
			if len(server.Requests()) != before {
				t.Fatal("retained plan was downloaded again")
			}
			if err = os.WriteFile(d.PlanFile, []byte("{}"), 0600); err != nil {
				t.Fatal(err)
			}
			if _, _, _, err := a.readStorageTransition(t.Context(), true); err == nil {
				t.Fatal("corrupt local plan accepted")
			}
			if len(server.Requests()) != before {
				t.Fatal("corrupt local plan triggered replacement fetch")
			}
		})
	}
}

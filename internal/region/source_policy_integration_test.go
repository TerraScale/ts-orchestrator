package region

import (
	"encoding/json/v2"
	"errors"
	"fmt"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

// Source reservations cross signed SDK HTTP and disk CAS, including restart,
// stale checkpoints and rejection of widened IAM read from durable bytes.
func TestSourcePolicyJournalPreservesOriginalRecipientAndRejectsWidening(t *testing.T) {
	store, client, raw := foundationProtocolStore(t)
	now := time.Now().UTC()
	object := "owned/bootstrap/v2/material-source/" + strings.Repeat("a", 64) + ".json"
	mapKey := sourcePolicyKey("ns", "heads", object)
	escrow := bootstrap.StartupVaultTarget{CompartmentOCID: "ocid1.compartment.oc1..home", VaultOCID: "ocid1.vault.oc1.sa-saopaulo-1.home", KMSKeyOCID: "ocid1.key.oc1.sa-saopaulo-1.home"}
	pending := SourcePolicyRecord{Namespace: "ns", Bucket: "heads", Object: object, InstallationID: "installation", InstanceID: "ocid1.instance.oc1.us-sanjose-1.seed", GrantDigest: strings.Repeat("b", 64), TemplateDigest: strings.Repeat("c", 64), GrantGeneration: 1, FirstAttemptAt: now, Escrow: escrow, BucketCompartment: escrow.CompartmentOCID, SecretName: "ts-bootstrap-source-" + strings.Repeat("a", 32)}
	statements, err := ociregion.BootstrapSourceStatements(pending.InstanceID, pending.SecretName, vaultsecret.Target{CompartmentID: escrow.CompartmentOCID, VaultID: escrow.VaultOCID, KeyID: escrow.KMSKeyOCID})
	if err != nil {
		t.Fatal(err)
	}
	statements = append(statements, fmt.Sprintf("Allow any-user to manage objects in compartment id %s where all {request.principal.type='instance', request.principal.id='%s', target.bucket.name='heads', target.object.name='%s', any {request.permission='OBJECT_CREATE', request.permission='OBJECT_OVERWRITE', request.permission='OBJECT_READ'}}", escrow.CompartmentOCID, pending.InstanceID, object))
	pending.Request = identity.CreatePolicyDetails{CompartmentId: new(escrow.CompartmentOCID), Name: new("ts-bootstrap-source-" + mapKey[:32]), Description: new("Exact founder source escrow and registration"), Statements: statements}
	requestWire, err := json.Marshal(pending.Request, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	pending.RequestDigest = digestSource(requestWire)
	pending.RetryToken = digestSource([]byte(mapKey + "\x00" + pending.InstanceID + "\x00" + pending.GrantDigest + "\x00" + pending.RequestDigest))
	record := FoundationRecord{SchemaVersion: 1, Cell: "GRU", OCIRegion: "sa-saopaulo-1", TenancyID: "ocid1.tenancy.oc1..test", ParentCompartmentID: "ocid1.compartment.oc1..parent", SharedCompartmentID: "ocid1.compartment.oc1..shared", Generation: 1, IntentDigest: strings.Repeat("0", 64), OperationID: entityid.New(), Epoch: 1, Stage: "reconciled", StartedAt: now, UpdatedAt: now, CompletedAt: now, ResourceIDs: map[string]string{}, SourcePolicyIDs: map[string]SourcePolicyRecord{mapKey: pending}}
	etag, err := store.CompareAndSwap(t.Context(), record, "")
	if err != nil {
		t.Fatal(err)
	}
	restarted, err := NewObjectFoundationStore(client, "ns", "heads")
	if err != nil {
		t.Fatal(err)
	}
	saved, savedETag, err := restarted.Load(t.Context(), "GRU")
	if err != nil || savedETag != etag || saved.SourcePolicyIDs[mapKey].RetryToken != pending.RetryToken {
		t.Fatalf("pending reservation lost: %v", err)
	}
	// A later signed generation retains the first recipient's exact original bindings.
	saved.Generation = 2
	saved.SourcePolicyIDs = maps.Clone(saved.SourcePolicyIDs)
	established := saved.SourcePolicyIDs[mapKey]
	established.PolicyID = "ocid1.policy.oc1..source"
	established.ProtectionEstablishedAt = now.Add(time.Second)
	saved.SourcePolicyIDs[mapKey] = established
	if _, err = restarted.CompareAndSwap(t.Context(), saved, savedETag); err != nil {
		t.Fatal(err)
	}
	if _, err = store.CompareAndSwap(t.Context(), record, etag); !errors.Is(err, ErrFoundationConflict) {
		t.Fatalf("stale policy checkpoint accepted: %v", err)
	}
	loaded, _, err := restarted.Load(t.Context(), "GRU")
	if err != nil {
		t.Fatal(err)
	}
	original := loaded.SourcePolicyIDs[mapKey]
	if original.InstanceID != pending.InstanceID || original.GrantDigest != pending.GrantDigest || original.TemplateDigest != pending.TemplateDigest || original.GrantGeneration != 1 || original.PolicyID != established.PolicyID {
		t.Fatal("renewal transferred original source binding")
	}
	// Corrupt an authenticated record at rest: no broad policy may become replay authority.
	original.Request.Statements = append(original.Request.Statements, "Allow any-user to manage objects in tenancy")
	loaded.SourcePolicyIDs[mapKey] = original
	wire, err := json.Marshal(loaded, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	raw(foundationObjectPrefix+"GRU.json", wire)
	if _, _, err := restarted.Load(t.Context(), "GRU"); err == nil {
		t.Fatal("durable widened policy accepted")
	}
}

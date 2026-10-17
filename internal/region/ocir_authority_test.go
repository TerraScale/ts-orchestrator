package region

import (
	"encoding/json/v2"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/oracle/oci-go-sdk/v65/common"
	"github.com/oracle/oci-go-sdk/v65/core"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

func ocirAuthorityFixture(t *testing.T) FoundationRecord {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	installation := entityid.New()
	slot := BootstrapSlotID(installation, "SFO", "controller", "controller-a")
	writer := FoundationWriterRecord{Cell: "SFO", Slot: "controller-a", InstallationID: installation, Generation: 1, GrantSHA256: strings.Repeat("a", 64), ProfileSHA256: strings.Repeat("b", 64), RecipeSHA256: strings.Repeat("c", 64), ScopeSHA256: strings.Repeat("d", 64), PhysicalScopeSHA256: strings.Repeat("e", 64), SlotID: slot, OperationID: BootstrapOperationID(installation, slot), Namespace: "ns", Bucket: "heads", BucketCompartment: "ocid1.compartment.oc1..home", KMSKeyID: "ocid1.key.oc1.sa-saopaulo-1.home", FirstAttemptAt: now.Add(-time.Minute), InstanceID: "ocid1.instance.oc1.us-sanjose-1.original", Request: core.LaunchInstanceDetails{CompartmentId: new("ocid1.compartment.oc1..control"), Metadata: foundationWriterMetadata("controller-a"), ExtendedMetadata: map[string]any{}, LaunchVolumeAttachments: []core.LaunchAttachVolumeDetails{}, LicensingConfigs: []core.LaunchInstanceLicensingConfig{}, DefinedTags: map[string]map[string]any{}, SecurityAttributes: map[string]map[string]any{}, FreeformTags: map[string]string{}, SourceDetails: core.InstanceSourceViaImageDetails{ImageId: new("ocid1.image.oc1.us-sanjose-1.seed")}}}
	var err error
	writer.RequestDigest, err = netBirdRequestDigest(writer.Request)
	if err != nil {
		t.Fatal(err)
	}
	writer.RetryToken = BootstrapRetryToken(writer.OperationID, writer.RequestDigest)
	details, err := foundationWriterPolicy(writer)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := foundationWriterPolicyBody(details)
	if err != nil {
		t.Fatal(err)
	}
	digest := digestSource(wire)
	writer.Policy = &FoundationWriterPolicy{Request: details, RequestDigest: digest, RetryToken: digestSource([]byte(writer.RequestDigest + "\x00" + writer.InstanceID + "\x00" + digest)), FirstAttemptAt: now.Add(-50 * time.Second), PolicyID: "ocid1.policy.oc1..original", VerifiedAt: now.Add(-40 * time.Second)}
	reservation := OCIRAuthorityRecord{FoundationOperation: entityid.New(), Epoch: 1, FirstAttemptAt: now.Add(-30 * time.Second), DispatchExpiresAt: now.Add(time.Minute), AuthorityExpiresAt: now.Add(time.Hour)}
	for _, item := range []struct{ compartment, name string }{{"control", "terrascale/terrabase"}, {"control", "terrascale/ts-auth"}, {"workload", "terrascale/functions"}} {
		reservation.Scope = append(reservation.Scope, OCIRIssuerIntent{OCIRegion: "us-sanjose-1", RegistryHost: "sjc.ocir.io", RegistryNamespace: "ns", RepositoryCompartmentID: "ocid1.compartment.oc1.." + item.compartment, RepositoryName: item.name, RepositoryLifecycle: "private-immutable", PrincipalName: "ts-pull", PrincipalEmail: "ts-pull@terrascale.tech", SecretName: "sfo-orch-ocir-pull"})
	}
	reservation.ScopeSHA256, err = ocirAuthorityScopeDigest(reservation.Scope)
	if err != nil {
		t.Fatal(err)
	}
	reservation.WriterSHA256, err = ocirWriterDigest(writer)
	if err != nil {
		t.Fatal(err)
	}
	reservation.Policies, err = ocirAuthorityPolicies(writer, reservation)
	if err != nil {
		t.Fatal(err)
	}
	writer.OCIRAuthority = &reservation
	if err := writer.validate(); err != nil {
		t.Fatal(err)
	}
	return FoundationRecord{Cell: writer.Cell, FoundationWriter: &writer}
}

func cloneOCIRAuthorityFixture(t *testing.T, original FoundationRecord) FoundationRecord {
	t.Helper()
	wire, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var current FoundationRecord
	if err := json.Unmarshal(wire, &current); err != nil {
		t.Fatal(err)
	}
	return current
}

func TestOCIRAuthorityExactConditionalPolicyAndLifetimes(t *testing.T) {
	record := ocirAuthorityFixture(t)
	writer := record.FoundationWriter
	reservation := writer.OCIRAuthority
	if len(reservation.Policies) != 2 || !reservation.DispatchExpiresAt.Before(reservation.AuthorityExpiresAt) {
		t.Fatal("exact compartments or separate original lifetimes lost")
	}
	for index, policy := range reservation.Policies {
		compartment, names := "control", "any {target.repo.name='terrascale/terrabase', target.repo.name='terrascale/ts-auth'}"
		if index == 1 {
			compartment, names = "workload", "target.repo.name='terrascale/functions'"
		}
		id := "ocid1.compartment.oc1.." + compartment
		expected := "Allow any-user to manage repos in compartment id " + id + " where all {request.principal.type='instance', request.principal.id='" + writer.InstanceID + "', request.region='SJC', request.utc-timestamp before '" + reservation.AuthorityExpiresAt.Format(time.RFC3339Nano) + "', " + names + ", any {all {request.operation='CreateContainerRepository', request.permission='REPOSITORY_CREATE'}, all {request.operation='GetContainerRepository', request.permission='REPOSITORY_READ'}, all {request.operation='UpdateContainerRepository', request.permission='REPOSITORY_MANAGE'}}}"
		if policy.Request.CompartmentId == nil || *policy.Request.CompartmentId != id || !reflect.DeepEqual(policy.Request.Statements, []string{expected}) {
			t.Fatal("policy escaped exact original principal, compartment, names, OCI region key, signed expiry or operation/permission pair")
		}
	}
	for _, mutate := range []func(*OCIRAuthorityRecord){
		func(r *OCIRAuthorityRecord) {
			r.Policies[0].Request.Statements[0] = strings.ReplaceAll(r.Policies[0].Request.Statements[0], "target.repo.name=", "target.repo.prefix=")
		},
		func(r *OCIRAuthorityRecord) { r.AuthorityExpiresAt = r.AuthorityExpiresAt.Add(time.Hour) },
		func(r *OCIRAuthorityRecord) { r.Policies[0].RetryToken = strings.Repeat("f", 64) },
		func(r *OCIRAuthorityRecord) {
			r.Policies[0].PolicyID, r.Policies[0].VerifiedAt = "ocid1.policy.oc1..adopted", time.Now().UTC()
		},
	} {
		current := cloneOCIRAuthorityFixture(t, record)
		mutate(current.FoundationWriter.OCIRAuthority)
		if current.FoundationWriter.validate() == nil {
			t.Fatal("changed policy or unproven same-name identity accepted")
		}
	}
}

func TestOCIRAuthorityRetainsUnknownAndPositiveOriginalDispatches(t *testing.T) {
	record := ocirAuthorityFixture(t)
	reservation := record.FoundationWriter.OCIRAuthority
	start := reservation.FirstAttemptAt.Add(time.Second)
	reservation.Policies[0].Dispatches = []OCIRAuthorityDispatch{{OCIRIssuerDispatch: OCIRIssuerDispatch{StartedAt: start}}}
	current := cloneOCIRAuthorityFixture(t, record)
	policy := &current.FoundationWriter.OCIRAuthority.Policies[0]
	policy.Dispatches[0].Sent, policy.Dispatches[0].Status, policy.Dispatches[0].FinishedAt = true, 503, start.Add(time.Second)
	policy.Dispatches = append(policy.Dispatches, OCIRAuthorityDispatch{OCIRIssuerDispatch: OCIRIssuerDispatch{StartedAt: start.Add(2 * time.Second), Sent: true, Status: 200, FinishedAt: start.Add(3 * time.Second)}, ObservedID: "ocid1.policy.oc1..created"})
	policy.PolicyID, policy.VerifiedAt = "ocid1.policy.oc1..created", start.Add(4*time.Second)
	if err := current.FoundationWriter.validate(); err != nil {
		t.Fatal(err)
	}
	if err := record.retainOCIRAuthority(current); err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*FoundationWriterRecord){
		func(w *FoundationWriterRecord) { w.OCIRAuthority = nil },
		func(w *FoundationWriterRecord) {
			w.OCIRAuthority.Policies[0].Dispatches = w.OCIRAuthority.Policies[0].Dispatches[1:]
		},
		func(w *FoundationWriterRecord) { w.OCIRAuthority.Policies[0].Dispatches[0].Status = 429 },
		func(w *FoundationWriterRecord) {
			w.OCIRAuthority.DispatchExpiresAt = w.OCIRAuthority.DispatchExpiresAt.Add(time.Minute)
		},
		func(w *FoundationWriterRecord) { w.Policy.VerifiedAt = w.Policy.VerifiedAt.Add(time.Second) },
		func(w *FoundationWriterRecord) { w.InstanceID = "ocid1.instance.oc1.us-sanjose-1.replacement" },
		func(w *FoundationWriterRecord) {
			w.OCIRAuthority.Policies[0].PolicyID = "ocid1.policy.oc1..replacement"
		},
	} {
		changed := cloneOCIRAuthorityFixture(t, current)
		mutate(changed.FoundationWriter)
		if current.retainOCIRAuthority(changed) == nil {
			t.Fatal("retained birth, original deadline, history or positive receipt rewritten")
		}
	}
	// Permission-independent sibling progress is composed at the whole-record
	// CAS boundary without changing this capability or the original writer.
	sibling := cloneOCIRAuthorityFixture(t, current)
	sibling.NetBirdManager = &NetBirdManagerLaunch{}
	if err := current.retainOCIRAuthority(sibling); err != nil {
		t.Fatal("independent sibling blocked by OCIR retention", err)
	}
}

func TestOCIRAuthorityReadbackRejectsChangedPolicyVersionAndScope(t *testing.T) {
	record := ocirAuthorityFixture(t)
	details := record.FoundationWriter.OCIRAuthority.Policies[0].Request
	policy := identity.Policy{CompartmentId: details.CompartmentId, Name: details.Name, Description: details.Description, Statements: details.Statements}
	if !matchesOCIRAuthorityPolicy(details, policy) {
		t.Fatal("original exact policy rejected")
	}
	policy.Statements = []string{"Allow any-user to manage repos in tenancy"}
	if matchesOCIRAuthorityPolicy(details, policy) {
		t.Fatal("broadened remote policy accepted")
	}
	policy.Statements, policy.VersionDate = details.Statements, new(common.SDKDate)
	if matchesOCIRAuthorityPolicy(details, policy) {
		t.Fatal("changed remote policy version accepted")
	}
}

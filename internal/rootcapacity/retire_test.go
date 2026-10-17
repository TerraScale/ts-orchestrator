package rootcapacity

import (
	"net/http"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/capacityledger"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/oracle/oci-go-sdk/v65/common"
)

func TestRetirementUsesProtectedSelectorsWithoutCallerAuthorityBytes(t *testing.T) {
	child := region.PoolChildRecord{OperationID: "original-birth", RecipeSHA256: "original-recipe", PoolID: "original-pool", ConfigurationID: "original-configuration",
		InstanceID: "original-instance", BootVolumeID: "original-boot", PublicCAPEM: []byte("original-ca"), AvailabilityDomains: []string{"original-ad"}}
	request := rootoci.PoolRetirementExpectation{Child: rootoci.PoolChildExpectation{OperationID: child.OperationID, RecipeSHA256: child.RecipeSHA256},
		InstanceID: child.InstanceID, RemovalOperationID: "original-removal"}
	if !retirementSelectors(request, child) {
		t.Fatal("retirement required caller CA, placement or drain authority instead of independent protected selection")
	}
	for _, change := range []struct {
		name  string
		apply func(*rootoci.PoolRetirementExpectation)
	}{
		{"another original instance", func(r *rootoci.PoolRetirementExpectation) { r.InstanceID = "another-instance" }},
		{"another configuration", func(r *rootoci.PoolRetirementExpectation) { r.Child.ConfigurationID = "another-configuration" }},
		{"another public source", func(r *rootoci.PoolRetirementExpectation) { r.Child.PublicCAPEM = []byte("another-ca") }},
		{"another placement", func(r *rootoci.PoolRetirementExpectation) { r.Child.AvailabilityDomains = []string{"another-ad"} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			candidate := request
			change.apply(&candidate)
			if retirementSelectors(candidate, child) {
				t.Fatal("retirement accepted selectors conflicting with the original protected child")
			}
		})
	}
	child.RemovalOperationID = request.RemovalOperationID
	request.RemovalOperationID = "successor-removal"
	if retirementSelectors(request, child) {
		t.Fatal("successor removal rebound the original retirement")
	}
}

func TestRetirementGrantSelectorsRetainOriginalPurchaseAcrossCurrentGrantChange(t *testing.T) {
	now := time.Now().UTC()
	child := region.PoolChildRecord{OperationID: "birth", RecipeSHA256: "original-recipe", InstanceID: "instance", BootVolumeID: "boot", BornAt: now}
	request := rootoci.PoolRetirementExpectation{Child: rootoci.PoolChildExpectation{GrantSHA256: "original-grant", Generation: 1}}
	record := region.FoundationRecord{GrantSHA256: "current-grant", Generation: 2, CapacityLedger: &capacityledger.Ledger{Hosts: []capacityledger.Host{{
		Receipt:    capacityledger.Receipt{OperationID: child.OperationID, RecipeSHA256: child.RecipeSHA256, GrantSHA256: "original-grant", GrantGeneration: 1},
		InstanceID: child.InstanceID, BootVolumeID: child.BootVolumeID, BornAt: now,
	}}}}
	if !retirementBirthAuthority(record, request, child) {
		t.Fatal("compatible current grant update blocked original birth selectors")
	}
	request.Child.GrantSHA256, request.Child.Generation = record.GrantSHA256, record.Generation
	if retirementBirthAuthority(record, request, child) {
		t.Fatal("retirement rebound original purchase to current grant selectors")
	}
	request.Child.GrantSHA256, request.Child.Generation = "original-grant", 1
	record.CapacityLedger.Hosts = append(record.CapacityLedger.Hosts, record.CapacityLedger.Hosts[0])
	if retirementBirthAuthority(record, request, child) {
		t.Fatal("retirement accepted ambiguous original financial lineage")
	}
}

func TestTerminalRequestsPreserveBootAndDataAndNeverInventDeleteTokens(t *testing.T) {
	child := region.PoolChildRecord{InstanceID: "original-instance", BootVolumeID: "original-boot"}
	terminate := terminateRequest(child, "original-instance-etag")
	if value(terminate.InstanceId) != child.InstanceID || value(terminate.IfMatch) != "original-instance-etag" ||
		terminate.PreserveBootVolume == nil || !*terminate.PreserveBootVolume ||
		terminate.PreserveDataVolumesCreatedAtLaunch == nil || !*terminate.PreserveDataVolumesCreatedAtLaunch {
		t.Fatal("termination widened original identity or implicitly deleted original boot/data volumes")
	}
	deletion := deleteBootRequest(child, "original-boot-etag")
	if value(deletion.BootVolumeId) != child.BootVolumeID || value(deletion.IfMatch) != "original-boot-etag" {
		t.Fatal("boot deletion changed original exact volume or conditional wire")
	}
	for _, request := range []common.OCIRequest{terminate, deletion} {
		raw, err := request.HTTPRequest(http.MethodDelete, "/original", nil, nil)
		if err != nil || raw.Header.Get("opc-retry-token") != "" {
			t.Fatalf("DELETE acquired an unsupported retry token: %v", err)
		}
	}
}

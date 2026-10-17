package rootcapacity

import (
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/oracle/oci-go-sdk/v65/core"
)

func TestPoolRequestsNeverCreateImplicitChildrenOrTerminateMembers(t *testing.T) {
	a := attempt{operation: "original-removal", receipt: budget.Reservation{OperationID: "original-birth", CompartmentID: "original-compartment"},
		recipe: nodescale.Recipe{Cell: "gru", AvailabilityDomains: []string{"original-AD"}, SubnetID: "original-subnet", Metadata: map[string]string{"base": "signed"}}}
	pool := a.poolRequest("original-configuration")
	if pool.Size == nil || *pool.Size != 0 || value(pool.InstanceConfigurationId) != "original-configuration" {
		t.Fatal("pool inception can implicitly create a child or select another configuration")
	}
	child := region.PoolChildRecord{ConfigurationID: "original-configuration", PoolID: "original-pool", InstanceID: "original-instance",
		Node: "ts-gru-4", Descriptor: "original-descriptor", AvailabilityDomain: "original-AD"}
	launch := a.launchRequest(child)
	details := launch.InstanceConfiguration.(core.ComputeInstanceDetails).LaunchDetails
	if value(launch.InstanceConfigurationId) != child.ConfigurationID || value(details.DisplayName) != child.Node ||
		value(details.AvailabilityDomain) != child.AvailabilityDomain || details.Metadata[hostboot.MetadataKey] != child.Descriptor ||
		value(details.CreateVnicDetails.SubnetId) != a.recipe.SubnetID || details.CreateVnicDetails.AssignPublicIp == nil || *details.CreateVnicDetails.AssignPublicIp ||
		a.recipe.Metadata[hostboot.MetadataKey] != "" {
		t.Fatal("launch lost original child placement or changed signed base metadata")
	}
	attach := a.attachRequest(child)
	if value(attach.InstancePoolId) != child.PoolID || value(attach.InstanceId) != child.InstanceID {
		t.Fatal("attach selected identities other than the original child and pool")
	}
	detach := a.detachRequest(child.PoolID, child.InstanceID)
	if value(detach.InstancePoolId) != child.PoolID || value(detach.InstanceId) != child.InstanceID ||
		detach.IsAutoTerminate == nil || *detach.IsAutoTerminate || detach.IsDecrementSize == nil || !*detach.IsDecrementSize {
		t.Fatal("detach can terminate a member or implicitly launch a replacement")
	}
	if value(detach.OpcRetryToken) == value(attach.OpcRetryToken) {
		t.Fatal("removal reused birth retry identity")
	}
}

func TestExactAttachTargetAllowsOnlyOriginalChildReplay(t *testing.T) {
	child := region.PoolChildRecord{InstanceID: "original-child", ConfigurationID: "original-configuration", AvailabilityDomain: "original-AD", TargetFrom: 0}
	pool := core.InstancePool{CompartmentId: new("original-compartment"), InstanceConfigurationId: new(child.ConfigurationID), Size: new(0), LifecycleState: core.InstancePoolLifecycleStateRunning}
	if err := exactAttachTarget(pool, nil, child); err != nil {
		t.Fatal(err)
	}
	pool.Size = new(1)
	member := core.InstanceSummary{Id: new(child.InstanceID), InstanceConfigurationId: new(child.ConfigurationID), AvailabilityDomain: new(child.AvailabilityDomain), CompartmentId: pool.CompartmentId, State: new("RUNNING")}
	if err := exactAttachTarget(pool, []core.InstanceSummary{member}, child); err != nil {
		t.Fatal(err)
	}
	for _, change := range []struct {
		name  string
		apply func(*core.InstanceSummary)
	}{
		{"unsettled member", func(m *core.InstanceSummary) { m.State = new("TERMINATING") }},
		{"another member", func(m *core.InstanceSummary) { m.Id = new("replacement-child") }},
		{"another configuration", func(m *core.InstanceSummary) { m.InstanceConfigurationId = new("replacement-configuration") }},
		{"another AD", func(m *core.InstanceSummary) { m.AvailabilityDomain = new("replacement-AD") }},
		{"another compartment", func(m *core.InstanceSummary) { m.CompartmentId = new("replacement-compartment") }},
	} {
		t.Run(change.name, func(t *testing.T) {
			changed := member
			change.apply(&changed)
			if err := exactAttachTarget(pool, []core.InstanceSummary{changed}, child); err == nil {
				t.Fatal("allowed attach against changed original target")
			}
		})
	}
	pool.Size = new(2)
	if err := exactAttachTarget(pool, []core.InstanceSummary{member, member}, child); err == nil {
		t.Fatal("accepted duplicate original child membership")
	}
}

func TestExactDetachTargetPreservesOriginalDecrementAcrossUnknownResponse(t *testing.T) {
	pool := core.InstancePool{Size: new(1), CompartmentId: new("original-compartment"), LifecycleState: core.InstancePoolLifecycleStateRunning}
	member := core.InstanceSummary{Id: new("original-member"), CompartmentId: pool.CompartmentId}
	if err := exactDetachTarget(pool, []core.InstanceSummary{member}, "original-member", 1, false); err != nil {
		t.Fatal(err)
	}
	pool.Size = new(0)
	if err := exactDetachTarget(pool, nil, "original-member", 1, false); err == nil {
		t.Fatal("inferred a successful original detach from member absence")
	}
	if err := exactDetachTarget(pool, nil, "original-member", 1, true); err != nil {
		t.Fatal("refused exact original retry after unknown decrement", err)
	}
	pool.Size = new(1)
	member.Id = new("replacement-member")
	if err := exactDetachTarget(pool, []core.InstanceSummary{member}, "original-member", 1, true); err == nil {
		t.Fatal("allowed a replacement member or target to complete the original decrement")
	}
	pool.Size = new(2)
	member.Id = new("original-member")
	if err := exactDetachTarget(pool, []core.InstanceSummary{member, member}, "original-member", 2, true); err == nil {
		t.Fatal("accepted duplicate exact target membership")
	}
}

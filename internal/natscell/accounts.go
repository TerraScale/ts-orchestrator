package natscell

import (
	"sync"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
)

// BrokerOperatorPublishPermissions is the exact operator publish surface used
// by the embedded Lab broker, the production issuer, and credential validation.
func BrokerOperatorPublishPermissions(cell string) jwt.StringList {
	return jwt.StringList{
		protocol.DeliveryIntentSubject(cell), protocol.DeliveryArtifactAdmitSubject(cell), protocol.HostRegisterSubject(cell),
		protocol.PlacementApplySubject(cell), protocol.ManagedUpdatePrepareSubject(cell), protocol.MaterialPrepareSubject(cell),
		protocol.BackupOperationSubject(cell), protocol.BrokerClaimApplySubject(cell),
		protocol.TerminalSubject(cell, "plan"), protocol.TerminalSubject(cell, "apply"), protocol.TerminalSubject(cell, "status"),
		"$JS.API.INFO", "$JS.API.STREAM.INFO.TS_DELIVERY_INTENTS",
		"$JS.API.STREAM.INFO.OBJ_TS_ARTIFACTS",
		"$JS.API.STREAM.INFO.KV_TS_DELIVERY_ADMISSIONS",
		"$JS.API.STREAM.INFO.KV_TS_DELIVERY_OPERATIONS",
		"$JS.API.STREAM.INFO.KV_TS_HOST_STATE",
		"$JS.API.STREAM.INFO.TS_CONTROL_LOG",
		"$JS.API.STREAM.MSG.GET.OBJ_TS_ARTIFACTS",
		"$JS.API.STREAM.MSG.GET.KV_TS_DELIVERY_ADMISSIONS",
		"$JS.API.STREAM.MSG.GET.KV_TS_DELIVERY_OPERATIONS",
		"$JS.API.STREAM.MSG.GET.KV_TS_HOST_STATE",
		"$JS.API.STREAM.MSG.GET.TS_CONTROL_LOG",
		"$JS.API.CONSUMER.CREATE.OBJ_TS_ARTIFACTS.>",
		"$JS.API.CONSUMER.INFO.OBJ_TS_ARTIFACTS.*",
		"$JS.API.CONSUMER.DELETE.OBJ_TS_ARTIFACTS.*",
		"$JS.API.DIRECT.GET.OBJ_TS_ARTIFACTS",
		"$JS.API.DIRECT.GET.OBJ_TS_ARTIFACTS.>",
		"$JS.API.DIRECT.GET.KV_TS_DELIVERY_ADMISSIONS.>",
		"$JS.API.DIRECT.GET.KV_TS_DELIVERY_OPERATIONS.>",
		"$JS.API.DIRECT.GET.KV_TS_HOST_STATE.>",
		"$JS.API.DIRECT.GET.TS_CONTROL_LOG.>",
		"$O.TS_ARTIFACTS.>",
	}
}

// ControllerPublishes is the regional controller's publish surface. It also
// names every region's summary, decision and read-only query services by
// pattern, so no region needs its own grant; remote snapshots, journals and
// mutations stay out.
func ControllerPublishes(cell string) jwt.StringList {
	publishes := jwt.StringList{protocol.Regional(cell, ">"), protocol.Control(cell, ">"), "$JS.API.>", "$KV.>", "$O.>",
		protocol.Broker(cell, "ticket", ">"), protocol.Broker(cell, "fence", ">")}
	for _, leaf := range protocol.InterRegionObservabilityLeaves() {
		publishes.Add(protocol.AnyRegionObservabilitySubject(leaf))
	}
	publishes.Add(protocol.AnyRegionQuerySubject())
	return publishes
}

// ControllerSubscriptions is the exact regional request surface a controller
// serves, in issuer order. Private inbox and broker grants are added by callers.
func ControllerSubscriptions(cell string) []string {
	return []string{
		protocol.BrokerClaimApplySubject(cell), protocol.AgentObservation(cell, "*", "*"),
		protocol.DeliveryArtifactAdmitSubject(cell), protocol.HostRegisterSubject(cell),
		protocol.PlacementApplySubject(cell), protocol.ManagedUpdatePrepareSubject(cell),
		protocol.BackupOperationSubject(cell), protocol.TerminalSubject(cell, ">"),
		// The seed answers epoch-fenced slot replacement requests from a
		// non-seed authority leader. Material issued before this grant
		// existed lacks it; the request then has no responder and the
		// leader holds the slot, as before.
		protocol.MembershipReplaceSubject(cell),
		// Every controller collects its peers' signed rollout health proofs
		// (controller.rollouts.executor). Material issued before this grant
		// lacks it; such a controller sees no proofs, so its executor holds
		// every rollout in preflight and nothing moves.
		protocol.RolloutProofSubject(cell, ""),
		// Read-only query services this region answers for every region.
		protocol.Regional(cell, "query", ">"),
		// The global home builds the roster from every region's heartbeat.
		// Material issued before this grant lacks it; the home then keeps no
		// roster, and its peers keep their last one.
		protocol.AnyRegionHealthSubject(),
		// Every region's dashboard rollup (TS-805), carried by the link.
		// Material issued before this grant lacks it; such a follower's
		// global view stays empty and the leader holds only its own rollup.
		protocol.RegionRollupGrant,
	}
}

type accountResolver struct {
	mu          sync.RWMutex
	system      string
	cell        string
	claims      map[string]string
	contract    *InterRegionContract
	interregion string
	links       int
	linkCell    string
}

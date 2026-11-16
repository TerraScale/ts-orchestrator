package natscell

import (
	"errors"
	"fmt"
	"slices"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"
)

func credentialUserBytes(data []byte) (*jwt.UserClaims, string, error) {
	raw, err := nkeys.ParseDecoratedJWT(data)
	if err != nil {
		return nil, "", err
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return nil, "", err
	}
	pair, err := nkeys.ParseDecoratedUserNKey(data)
	if err != nil {
		return nil, "", err
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil || public != claim.Subject {
		return nil, "", errors.New("regional credential seed and user JWT differ")
	}
	if claim.BearerToken || claim.ProxyRequired || len(claim.Src) != 0 ||
		len(claim.AllowedConnectionTypes) != 0 && !claim.AllowedConnectionTypes.Contains(jwt.ConnectionTypeInProcess) {
		return nil, "", errors.New("regional JWT depends on client metadata unavailable through the bridge")
	}
	return claim, public, nil
}

func credentialAccount(claim *jwt.UserClaims) string {
	if claim.IssuerAccount != "" {
		return claim.IssuerAccount
	}
	return claim.Issuer
}

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

// ValidateBrokerControllerCredentialBytes checks the same contract before a
// root-signed material generation installs controller credentials.
func ValidateBrokerControllerCredentialBytes(data []byte, cell, broker string) error {
	if !cellName.MatchString(cell) || !cellName.MatchString(broker) {
		return errors.New("broker controller credential cell or instance is invalid")
	}
	claim, public, err := credentialUserBytes(data)
	if err != nil {
		return fmt.Errorf("broker controller credentials: %w", err)
	}
	ticket := protocol.Broker(cell, "ticket", ">")
	fencePublish := protocol.Broker(cell, "fence", ">")
	fenceReceive := protocol.Broker(cell, "fence", broker)
	if !slices.Contains(claim.Pub.Allow, ticket) || !slices.Contains(claim.Pub.Allow, fencePublish) ||
		!slices.Contains(claim.Sub.Allow, ticket) || !slices.Contains(claim.Sub.Allow, fenceReceive) {
		return errors.New("broker controller credentials lack ticket or instance-bound fence grants")
	}
	allowedSubscriptions := map[string]bool{
		inboxPrefix(cell, public) + ".>": true,
		ticket:                           true, fenceReceive: true,
	}
	for _, subject := range ControllerSubscriptions(cell) {
		allowedSubscriptions[subject] = true
	}
	for _, subject := range GlobalControllerRequests() {
		allowedSubscriptions[subject] = true
	}
	// Optional read-only member telemetry (observability snapshots). The
	// issuer does not grant it today; it is accepted, not required.
	allowedSubscriptions[protocol.ObservabilityGrant(cell)] = true
	for _, grant := range claim.Sub.Allow {
		if !allowedSubscriptions[grant] {
			return fmt.Errorf("broker controller credentials have unscoped subscription %q", grant)
		}
	}
	if !slices.Contains(claim.Sub.Allow, inboxPrefix(cell, public)+".>") ||
		!slices.Contains(claim.Sub.Allow, protocol.BrokerClaimApplySubject(cell)) ||
		!slices.Contains(claim.Sub.Allow, protocol.ManagedUpdatePrepareSubject(cell)) ||
		!slices.Contains(claim.Sub.Allow, protocol.BackupOperationSubject(cell)) ||
		!slices.Contains(claim.Sub.Allow, protocol.TerminalSubject(cell, ">")) ||
		len(claim.Pub.Deny) != 0 || len(claim.Sub.Deny) != 0 ||
		claim.Resp == nil || claim.Resp.MaxMsgs != 1 ||
		claim.Resp.Expires <= 0 || claim.Resp.Expires > 5*time.Second {
		return errors.New("broker controller credentials need a private inbox and one bounded response grant")
	}
	return nil
}

// ValidateSystemCredentials checks a system account credentials file's bytes:
// a seed that matches its JWT, issued by systemAccount, with only the cell
// claim-update and private reply grants.
func ValidateSystemCredentials(data []byte, cell, cellAccount, systemAccount string) error {
	claim, public, err := credentialUserBytes(data)
	if err != nil {
		return fmt.Errorf("system account credentials: %w", err)
	}
	if credentialAccount(claim) != systemAccount ||
		len(claim.Pub.Allow) != 1 || claim.Pub.Allow[0] != "$SYS.REQ.ACCOUNT."+cellAccount+".CLAIMS.UPDATE" ||
		len(claim.Pub.Deny) != 0 || len(claim.Sub.Allow) != 1 ||
		claim.Sub.Allow[0] != inboxPrefix(cell, public)+".>" || len(claim.Sub.Deny) != 0 ||
		claim.Resp != nil {
		return errors.New("system account credentials must have only the cell claim-update and private reply grants")
	}
	return nil
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

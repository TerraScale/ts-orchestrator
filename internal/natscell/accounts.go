package natscell

import (
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

// accountResolver admits exactly the configured system and cell accounts, plus
// the interregion account when leafnodes are enabled. In particular, routed
// account-claim gossip cannot cause an unrelated account to be fetched.
type accountResolver struct {
	mu     sync.RWMutex
	system string
	cell   string
	claims map[string]string
	// contract, when set, binds every cell claim replacement to the
	// interregion subject contract and the cell leafnode prohibition.
	contract    *InterRegionContract
	interregion string
	links       int
}

// admitInterRegion is called once during server option construction, before
// the server starts, after the interregion claim has been verified.
func (r *accountResolver) admitInterRegion(account, raw string, contract InterRegionContract, links int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.claims[account] = raw
	r.interregion, r.contract, r.links = account, &contract, links
}

func newAccountResolver(system, systemJWT, cell, cellJWT string) *accountResolver {
	return &accountResolver{system: system, cell: cell,
		claims: map[string]string{system: systemJWT, cell: cellJWT}}
}

func (r *accountResolver) Fetch(name string) (string, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if raw, ok := r.claims[name]; ok {
		return raw, nil
	}
	return "", server.ErrMissingAccount
}

func (r *accountResolver) Store(name, raw string) error {
	if name != r.cell {
		return server.ErrMissingAccount
	}
	claim, err := jwt.DecodeAccountClaims(raw)
	if err != nil || claim.Subject != name {
		return errors.New("replacement broker account JWT is invalid")
	}
	r.mu.Lock()
	if r.contract != nil {
		system, systemErr := jwt.DecodeAccountClaims(r.claims[r.system])
		interregion, interregionErr := jwt.DecodeAccountClaims(r.claims[r.interregion])
		if systemErr != nil || interregionErr != nil ||
			r.contract.verify(system, claim, interregion, r.links) != nil {
			r.mu.Unlock()
			return errors.New("replacement cell account JWT widens the interregion contract")
		}
	}
	if prior := r.claims[name]; prior != raw {
		old, oldErr := jwt.DecodeAccountClaims(prior)
		if oldErr != nil || claim.IssuedAt <= old.IssuedAt {
			r.mu.Unlock()
			return errors.New("replacement broker account JWT issued-at must strictly increase")
		}
	}
	r.claims[name] = raw
	r.mu.Unlock()
	return nil
}

func (*accountResolver) IsReadOnly() bool           { return false }
func (*accountResolver) IsTrackingUpdate() bool     { return false }
func (*accountResolver) Start(*server.Server) error { return nil }
func (*accountResolver) Reload() error              { return nil }
func (*accountResolver) Close()                     {}

func readSignedJWT(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	if len(data) == 0 || len(data) > 64<<10 {
		return "", errors.New("signed JWT file has invalid size")
	}
	raw := strings.TrimSpace(string(data))
	for _, c := range raw {
		if c <= ' ' || c > '~' {
			return "", errors.New("signed JWT must be one ASCII token")
		}
	}
	return raw, nil
}

func loadOperatorAccounts(e *Embedded) (*jwt.OperatorClaims, string, string, string, string, error) {
	operatorRaw, err := readSignedJWT(e.OperatorJWTFile)
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("read regional operator JWT: %w", err)
	}
	operator, err := jwt.DecodeOperatorClaims(operatorRaw)
	if err != nil || !nkeys.IsValidPublicOperatorKey(operator.Subject) ||
		!nkeys.IsValidPublicAccountKey(operator.SystemAccount) {
		return nil, "", "", "", "", errors.New("regional operator JWT is invalid")
	}
	systemRaw, err := readSignedJWT(e.SystemJWTFile)
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("read regional system JWT: %w", err)
	}
	system, err := jwt.DecodeAccountClaims(systemRaw)
	if err != nil || system.Subject != operator.SystemAccount || !operator.DidSign(system) {
		return nil, "", "", "", "", errors.New("regional system account JWT is invalid")
	}
	cellRaw, err := readSignedJWT(e.CellJWTFile)
	if err != nil {
		return nil, "", "", "", "", fmt.Errorf("read regional cell JWT: %w", err)
	}
	cell, err := jwt.DecodeAccountClaims(cellRaw)
	if err != nil || !nkeys.IsValidPublicAccountKey(cell.Subject) ||
		cell.Subject == system.Subject || !operator.DidSign(cell) {
		return nil, "", "", "", "", errors.New("regional cell account JWT is invalid")
	}
	return operator, systemRaw, cellRaw, system.Subject, cell.Subject, nil
}

func credentialUser(path string) (*jwt.UserClaims, string, error) {
	data, err := readPrivateFile(path, 64<<10)
	if err != nil {
		return nil, "", err
	}
	defer clear(data)
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

// ControllerSubscriptions is the exact regional request surface a controller
// serves, in issuer order. Private inbox and broker grants are added by callers.
func ControllerSubscriptions(cell string) []string {
	return []string{
		protocol.BrokerClaimApplySubject(cell), protocol.AgentObservation(cell, "*", "*"),
		protocol.DeliveryArtifactAdmitSubject(cell), protocol.HostRegisterSubject(cell),
		protocol.PlacementApplySubject(cell), protocol.ManagedUpdatePrepareSubject(cell),
		protocol.BackupOperationSubject(cell), protocol.TerminalSubject(cell, ">"),
	}
}

// ValidateBrokerControllerCredentials enforces the production issuer contract
// for ephemeral ticket/fence RPCs and signed claim-apply admission. These
// subjects are outside the durable control stream, and NATS grants one
// short-lived response only after a request arrives on an allowed subscription.
// The issuer must also grant the controller's private reply inbox.
func ValidateBrokerControllerCredentials(path, cell, broker string) error {
	if !cellName.MatchString(cell) || !cellName.MatchString(broker) {
		return errors.New("broker controller credential cell or instance is invalid")
	}
	claim, public, err := credentialUser(path)
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

// ValidateBrokerOperatorCredentials requires exact publishes for claim apply,
// backup operations and terminal requests, JetStream INFO and control-stream
// INFO/MSG.GET read grants, and the caller's private inbox. These are the
// production issuer grants needed by the CLI's
// readiness and authority observation before publishing its signed request.
func ValidateBrokerOperatorCredentials(path, cell string) error {
	if !cellName.MatchString(cell) {
		return errors.New("broker operator credential cell is invalid")
	}
	claim, public, err := credentialUser(path)
	if err != nil {
		return fmt.Errorf("broker operator credentials: %w", err)
	}
	allowedPublishes := BrokerOperatorPublishPermissions(cell)
	for _, grant := range claim.Pub.Allow {
		if !slices.Contains(allowedPublishes, grant) {
			return fmt.Errorf("broker operator credentials have unscoped publish %q", grant)
		}
	}
	if !slices.Contains(claim.Pub.Allow, protocol.BrokerClaimApplySubject(cell)) ||
		!slices.Contains(claim.Pub.Allow, protocol.BackupOperationSubject(cell)) ||
		!slices.Contains(claim.Pub.Allow, protocol.TerminalSubject(cell, "plan")) ||
		!slices.Contains(claim.Pub.Allow, protocol.TerminalSubject(cell, "apply")) ||
		!slices.Contains(claim.Pub.Allow, protocol.TerminalSubject(cell, "status")) ||
		!slices.Contains(claim.Pub.Allow, "$JS.API.INFO") ||
		!slices.Contains(claim.Pub.Allow, "$JS.API.STREAM.INFO.TS_CONTROL_LOG") ||
		!slices.Contains(claim.Pub.Allow, "$JS.API.STREAM.MSG.GET.TS_CONTROL_LOG") ||
		len(claim.Sub.Allow) != 1 || claim.Sub.Allow[0] != inboxPrefix(cell, public)+".>" ||
		len(claim.Pub.Deny) != 0 || len(claim.Sub.Deny) != 0 {
		return errors.New("broker operator credentials need claim-apply publish and private reply grants")
	}
	return nil
}

func validateSystemCredentials(path, cell, cellAccount, systemAccount string) error {
	claim, public, err := credentialUser(path)
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

package reaper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"regexp"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
)

var ErrKeyLeasesPending = errors.New("reaper: destroyed keys still have outstanding lease horizons")
var ErrKeyDestructionUnavailable = errors.New("reaper: all-host key destruction unresolved")

// Broker grants must restrict publish to the global authority and subscribe to
// the exact admitted host NKey. Wildcard host responder grants are forbidden.
func KeyDestructionSubject(identity string) (string, error) {
	path, ok := strings.CutPrefix(identity, "spiffe://terrascale.tech/")
	parts := strings.Split(path, "/")
	if !ok || len(parts) != 4 || !destructionEnvironment.MatchString(parts[0]) || parts[1] != "terrabase-member" || !destructionULID.MatchString(parts[2]) || !destructionULID.MatchString(parts[3]) {
		return "", ErrKeyDestructionUnavailable
	}
	sum := sha256.Sum256([]byte(identity))
	return "orch.database.host." + hex.EncodeToString(sum[:]) + ".destroy-key", nil
}

type HostKeyAdapterConfig struct {
	Connection *nats.Conn
	Scope      keylease.DatabaseScope
	// HostIdentities is the complete immutable inventory, including retired holders.
	HostIdentities       []string
	Authority            NATSStateStoreConfig
	CheckEffectAuthority func(context.Context) error
}
type HostKeyAdapter struct {
	config HostKeyAdapterConfig
	closed atomic.Bool
}

var _ KeyAdapter = (*HostKeyAdapter)(nil)

type keyDestructionRequest struct {
	HostIdentity   string                 `json:"host_identity"`
	Scope          keylease.DatabaseScope `json:"scope"`
	OperationKey   string                 `json:"operation_key"`
	CandidateID    string                 `json:"candidate_id"`
	AuthorityEpoch uint64                 `json:"authority_epoch"`
	LeaseID        string                 `json:"lease_id"`
}
type keyDestructionReply struct {
	HostIdentity string                      `json:"host_identity"`
	Receipt      *keylease.DatabaseTombstone `json:"receipt,omitempty"`
	Error        string                      `json:"error,omitempty"`
}

var destructionULID = regexp.MustCompile(`^[0-7][0-9A-HJKMNP-TV-Z]{25}$`)
var destructionEnvironment = regexp.MustCompile(`^[a-z][a-z0-9-]{0,31}$`)

func validDestructionScope(s keylease.DatabaseScope) bool {
	return destructionEnvironment.MatchString(s.Environment) && destructionULID.MatchString(s.TenantID) && destructionULID.MatchString(s.ProjectID) && destructionULID.MatchString(s.DatabaseID)
}
func NewHostKeyAdapter(c HostKeyAdapterConfig) (*HostKeyAdapter, error) {
	if reaperTransport(c.Connection) != nil || !validDestructionScope(c.Scope) || len(c.HostIdentities) == 0 || c.CheckEffectAuthority == nil {
		return nil, ErrKeyDestructionUnavailable
	}
	c.Authority.Connection = c.Connection
	if _, err := NewNATSStateStore(c.Authority); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, host := range c.HostIdentities {
		if _, err := KeyDestructionSubject(host); err != nil || seen[host] || !strings.HasPrefix(host, "spiffe://terrascale.tech/"+c.Scope.Environment+"/") {
			return nil, ErrKeyDestructionUnavailable
		}
		seen[host] = true
	}
	c.HostIdentities = slices.Clone(c.HostIdentities)
	return &HostKeyAdapter{config: c}, nil
}
func (a *HostKeyAdapter) Close() error {
	if a != nil {
		a.closed.Store(true)
	}
	return nil
}
func (a *HostKeyAdapter) DestroyDEK(ctx context.Context, databaseID, operationKey string) error {
	if a == nil || ctx == nil || ctx.Err() != nil || a.closed.Load() || databaseID != a.config.Scope.DatabaseID || operationKey == "" || len(operationKey) > 256 || strings.ContainsAny(operationKey, "\x00\r\n") || reaperTransport(a.config.Connection) != nil {
		return ErrKeyDestructionUnavailable
	}
	c := a.config
	var horizon time.Time
	for _, host := range c.HostIdentities {
		if err := c.CheckEffectAuthority(ctx); err != nil {
			return err
		}
		subject, _ := KeyDestructionSubject(host)
		request := keyDestructionRequest{host, c.Scope, operationKey, c.Authority.CandidateID, c.Authority.AuthorityEpoch, c.Authority.LeaseID}
		data, err := json.Marshal(request)
		if err != nil {
			return ErrKeyDestructionUnavailable
		}
		opctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		message, err := c.Connection.RequestWithContext(opctx, subject, data)
		cancel()
		if err != nil || len(message.Data) > 16<<10 {
			return ErrKeyDestructionUnavailable
		}
		var reply keyDestructionReply
		if json.Unmarshal(message.Data, &reply, json.RejectUnknownMembers(true)) != nil || reply.Error != "" || reply.HostIdentity != host || reply.Receipt == nil {
			return ErrKeyDestructionUnavailable
		}
		receipt := reply.Receipt
		if receipt.Scope != c.Scope || receipt.OperationKey != operationKey || receipt.DestroyedAt.IsZero() || receipt.DestroyedAt.After(time.Now().UTC()) || receipt.LeasesExpireAt.Sub(receipt.DestroyedAt) != 1800*time.Second {
			return ErrKeyDestructionUnavailable
		}
		if receipt.LeasesExpireAt.After(horizon) {
			horizon = receipt.LeasesExpireAt
		}
	}
	if err := c.CheckEffectAuthority(ctx); err != nil {
		return err
	}
	if time.Now().UTC().Before(horizon) {
		return ErrKeyLeasesPending
	}
	return nil
}

type KeyDestructionHostConfig struct {
	Connection *nats.Conn
	// AuthorityConnection reads the global R3 reaper fence. Nil uses Connection.
	AuthorityConnection *nats.Conn
	ServerIdentity      string
	CatalogPath         string
	Scopes              []keylease.DatabaseScope
}
type KeyDestructionHost struct{ close func() error }

func (h *KeyDestructionHost) Close() error {
	if h == nil {
		return nil
	}
	return h.close()
}
func StartKeyDestructionHost(ctx context.Context, c KeyDestructionHostConfig) (*KeyDestructionHost, error) {
	if ctx == nil || ctx.Err() != nil || reaperTransport(c.Connection) != nil {
		return nil, ErrKeyDestructionUnavailable
	}
	if c.AuthorityConnection == nil {
		c.AuthorityConnection = c.Connection
	}
	if reaperTransport(c.AuthorityConnection) != nil {
		return nil, ErrKeyDestructionUnavailable
	}
	subject, err := KeyDestructionSubject(c.ServerIdentity)
	if err != nil {
		return nil, err
	}
	for _, scope := range c.Scopes {
		if !validDestructionScope(scope) || !strings.HasPrefix(c.ServerIdentity, "spiffe://terrascale.tech/"+scope.Environment+"/") {
			return nil, ErrKeyDestructionUnavailable
		}
	}
	if _, err := keylease.ReadCatalog(c.CatalogPath); err != nil {
		return nil, err
	}
	c.Scopes = slices.Clone(c.Scopes)
	sub, err := c.Connection.Subscribe(subject, func(message *nats.Msg) {
		if message.Reply == "" || len(message.Data) > 16<<10 {
			return
		}
		reply := keyDestructionReply{HostIdentity: c.ServerIdentity, Error: "unavailable"}
		var request keyDestructionRequest
		if json.Unmarshal(message.Data, &request, json.RejectUnknownMembers(true)) == nil && request.HostIdentity == c.ServerIdentity && destructionScopeAdmitted(c, request.Scope) {
			opctx, cancel := context.WithTimeout(ctx, 20*time.Second)
			if err := checkKeyDestructionFence(opctx, c.AuthorityConnection, request); err == nil {
				receipt, err := keylease.DestroyDatabase(opctx, c.CatalogPath, request.Scope, request.OperationKey)
				if err == nil {
					reply.Receipt = &receipt
					reply.Error = ""
				}
			}
			cancel()
		}
		data, _ := json.Marshal(reply)
		_ = message.Respond(data)
	})
	if err != nil {
		return nil, err
	}
	if err := sub.SetPendingLimits(128, 2<<20); err != nil {
		_ = sub.Unsubscribe()
		return nil, err
	}
	if err := c.Connection.FlushTimeout(5 * time.Second); err != nil {
		_ = sub.Unsubscribe()
		return nil, err
	}
	h := &KeyDestructionHost{close: sync.OnceValue(sub.Unsubscribe)}
	context.AfterFunc(ctx, func() { _ = h.Close() })
	return h, nil
}
func checkKeyDestructionFence(ctx context.Context, nc *nats.Conn, r keyDestructionRequest) error {
	store, err := NewNATSStateStore(NATSStateStoreConfig{Connection: nc, CandidateID: r.CandidateID, AuthorityEpoch: r.AuthorityEpoch, LeaseID: r.LeaseID})
	if err != nil {
		return err
	}
	state, err := store.Load(ctx)
	if err != nil {
		return err
	}
	entry, ok := state.Entries[r.Scope.DatabaseID]
	if !ok || entry.DatabaseID != r.Scope.DatabaseID || entry.Plan != PlanFree || entry.Phase != PhaseDeleting || entry.SecondNoticeAt.IsZero() {
		return ErrStateFenced
	}
	name := (&Reconciler{}).operationName(entry, "delete/crypto-shred")
	if r.OperationKey != name+"/"+entry.DatabaseID || entry.Operations[name].Status != operationStarted {
		return ErrStateFenced
	}
	return ctx.Err()
}

// Empty Scopes supports dynamic admission: only an already installed exact scope
// or permanent local tombstone authorizes this host to accept destruction.
func destructionScopeAdmitted(c KeyDestructionHostConfig, scope keylease.DatabaseScope) bool {
	if !validDestructionScope(scope) || !strings.HasPrefix(c.ServerIdentity, "spiffe://terrascale.tech/"+scope.Environment+"/") {
		return false
	}
	if len(c.Scopes) > 0 {
		return slices.Contains(c.Scopes, scope)
	}
	catalog, err := keylease.ReadCatalog(c.CatalogPath)
	if err != nil {
		return false
	}
	for _, entry := range catalog.Entries {
		if entry.Binding.Scope() == scope {
			return true
		}
	}
	for _, tombstone := range catalog.Tombstones {
		if tombstone.Scope == scope {
			return true
		}
	}
	return false
}

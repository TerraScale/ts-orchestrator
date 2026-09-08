// Package brokeradmission owns signed, generation-bound member NATS grants.
package brokeradmission

import (
	"errors"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/databaseadmission"
	"terrascale.tech/orchestrator/src/orchestrator/enrollment"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/placementpublisher"
)

var ErrInvalid = errors.New("broker admission: invalid signed membership or policy")
var ErrRollback = errors.New("broker admission: stale or conflicting desired grants")

const MaximumBytes = 4 << 20

var Roles = []string{"placement", "database", "lifecycle", "node", "reader", "regional"}

type Member struct {
	NodeID      string            `json:"node_id"`
	MemberID    string            `json:"member_id"`
	Region      string            `json:"region"`
	Slot        int               `json:"slot"`
	Generation  uint64            `json:"generation"`
	OperationID string            `json:"operation_id"`
	PublicKeys  map[string]string `json:"public_keys"`
}
type Retired struct {
	Member             Member `json:"member"`
	RemovalOperationID string `json:"removal_operation_id"`
	ResourceID         string `json:"resource_id"`
}
type Desired struct {
	Version        int       `json:"version"`
	Environment    string    `json:"environment"`
	Cluster        string    `json:"cluster"`
	Revision       uint64    `json:"revision"`
	AuthorityEpoch uint64    `json:"authority_epoch"`
	LeaseID        string    `json:"lease_id"`
	Members        []Member  `json:"members"`
	Retired        []Retired `json:"retired"`
}
type Accounts struct{ Global, Regional, Node string }
type Policy struct {
	// ManagedBaselineNKeys is independently owner-admitted initial member
	// inventory. Signed desired state cannot designate baseline keys as managed.
	ManagedBaselineNKeys []string `json:"-"`
	// ProtectedNKeys belong to independently admitted broker readers and cannot
	// be revoked or repurposed by the delegated enrollment signer.
	ProtectedNKeys []string `json:"-"`
	// RegionalPermissions is the admitted regional runtime permission producer;
	// callers bind its exact non-provisioner role, never desired JSON subjects.
	RegionalPermissions  func(region, nodeID string) (publish, subscribe []string, err error) `json:"-"`
	Environment, Cluster string
	Regions              map[string]Accounts
}

func validToken(s string) bool {
	return s != "" && len(s) <= 256 && !strings.ContainsAny(s, "\x00\r\n\t *>")
}
func canonicalRegion(region string) bool { _, err := hostagent.NewNodeId(region); return err == nil }
func Validate(d Desired) error {
	if d.Version != 1 || !validToken(d.Environment) || !validToken(d.Cluster) || d.Revision == 0 || d.AuthorityEpoch == 0 || !validToken(d.LeaseID) || len(d.Members) > 1024 || len(d.Retired) > 4096 {
		return ErrInvalid
	}
	nodes := map[string]bool{}
	identities, keys, slots := map[string]bool{}, map[string]bool{}, map[string]map[int]bool{}
	validateMember := func(m Member, active bool) error {
		if !validToken(m.MemberID) || !validToken(m.NodeID) || !validToken(m.OperationID) || !canonicalRegion(m.Region) || m.Slot < 1 || m.Slot > 1024 || m.Generation == 0 || identities[m.MemberID] || len(m.PublicKeys) != len(Roles) {
			return ErrInvalid
		}
		if _, err := hostagent.NewNodeId(m.NodeID); err != nil || !strings.HasPrefix(m.NodeID, m.Region+"-") {
			return ErrInvalid
		}
		identities[m.MemberID] = true
		if active {
			if nodes[m.NodeID] {
				return ErrInvalid
			}
			nodes[m.NodeID] = true
			if slots[m.Region] == nil {
				slots[m.Region] = map[int]bool{}
			}
			if slots[m.Region][m.Slot] {
				return ErrInvalid
			}
			slots[m.Region][m.Slot] = true
		}
		for _, role := range Roles {
			key := m.PublicKeys[role]
			if !nkeys.IsValidPublicUserKey(key) || keys[key] {
				return ErrInvalid
			}
			keys[key] = true
		}
		return nil
	}
	for _, m := range d.Members {
		if err := validateMember(m, true); err != nil {
			return err
		}
	}
	seenRemovals := map[string]bool{}
	for _, r := range d.Retired {
		if !validToken(r.RemovalOperationID) || !validToken(r.ResourceID) || seenRemovals[r.RemovalOperationID] {
			return ErrInvalid
		}
		seenRemovals[r.RemovalOperationID] = true
		if err := validateMember(r.Member, false); err != nil {
			return err
		}
	}
	return nil
}

// FromEnrollment copies only the six broker public keys from a published
// enrollment. Receipt keys and private material can never become broker grants.
func FromEnrollment(r enrollment.Record) (Member, error) {
	if r.Public == nil || r.IdentityReference == "" || len(r.Public.Grant) == 0 {
		return Member{}, ErrInvalid
	}
	m := Member{NodeID: r.NodeID, MemberID: r.MemberID, Region: r.Region, Slot: r.Slot, Generation: r.Generation, OperationID: r.OperationID, PublicKeys: map[string]string{}}
	for _, role := range Roles {
		m.PublicKeys[role] = r.Public.PublicKeys[role]
	}
	return m, nil
}

// ApplyOptions rebuilds managed identities from an immutable admitted baseline.
// Retired public keys are removed even if present in the original bootstrap.
func ApplyOptions(baseline *server.Options, d Desired, p Policy) (*server.Options, error) {
	if baseline == nil || Validate(d) != nil || d.Environment != p.Environment || d.Cluster != p.Cluster || p.RegionalPermissions == nil {
		return nil, ErrInvalid
	}
	managed := map[string]bool{}
	for _, m := range d.Members {
		if _, ok := p.Regions[m.Region]; !ok {
			return nil, ErrInvalid
		}
		for _, key := range m.PublicKeys {
			managed[key] = true
		}
	}
	for _, r := range d.Retired {
		if _, ok := p.Regions[r.Member.Region]; !ok {
			return nil, ErrInvalid
		}
		for _, key := range r.Member.PublicKeys {
			managed[key] = true
		}
	}
	allowedBaseline := map[string]bool{}
	for _, key := range p.ManagedBaselineNKeys {
		if !nkeys.IsValidPublicUserKey(key) || allowedBaseline[key] {
			return nil, ErrInvalid
		}
		allowedBaseline[key] = true
	}
	seenBaseline := map[string]bool{}
	for _, user := range baseline.Nkeys {
		if user == nil {
			continue
		}
		seenBaseline[user.Nkey] = true
		if managed[user.Nkey] && !allowedBaseline[user.Nkey] {
			return nil, ErrInvalid
		}
	}
	for key := range allowedBaseline {
		if !seenBaseline[key] {
			return nil, ErrInvalid
		}
	}
	for _, key := range p.ProtectedNKeys {
		if !nkeys.IsValidPublicUserKey(key) || managed[key] || allowedBaseline[key] {
			return nil, ErrInvalid
		}
	}
	result := baseline.Clone()
	result.Nkeys = slices.DeleteFunc(slices.Clone(baseline.Nkeys), func(u *server.NkeyUser) bool { return u != nil && managed[u.Nkey] })
	for _, m := range d.Members {
		accounts, ok := p.Regions[m.Region]
		if !ok {
			return nil, ErrInvalid
		}
		for _, account := range []string{accounts.Global, accounts.Regional, accounts.Node} {
			if !validToken(account) || account == "$SYS" || strings.Contains(account, ".") {
				return nil, ErrInvalid
			}
		}
		record := enrollment.Record{Environment: d.Environment, Cluster: d.Cluster, MemberID: m.MemberID}
		var err error
		result, err = placementpublisher.ApplyBrokerGrants(result, []placementpublisher.BrokerGrant{{ServerIdentity: enrollment.Identity(record, "member"), PublicNKey: m.PublicKeys["placement"], Account: accounts.Global}})
		if err != nil {
			return nil, err
		}
		result, err = databaseadmission.ApplyBrokerGrants(result, []databaseadmission.BrokerGrant{{ServerIdentity: enrollment.Identity(record, "member"), PublicNKey: m.PublicKeys["database"], LifecyclePublicNKey: m.PublicKeys["lifecycle"], Account: accounts.Global}})
		if err != nil {
			return nil, err
		}
		node, _ := hostagent.NewNodeId(m.NodeID)
		heartbeat, err := hostagent.NodeHeartbeatSubject(node)
		if err != nil {
			return nil, err
		}
		var commands []string
		for _, subject := range []func(hostagent.NodeId) (string, error){hostagent.NodeDrainSubject, hostagent.NodeDrainStatusSubject, hostagent.NodeDeploySubject, hostagent.NodeRollbackSubject, hostagent.NodeApplyManifestSubject} {
			value, e := subject(node)
			if e != nil {
				return nil, e
			}
			commands = append(commands, value)
		}
		if err := appendUser(result, accounts.Node, m.PublicKeys["node"], []string{heartbeat}, commands, true); err != nil {
			return nil, err
		}
		pub, sub, err := nodeauthority.ReaderPermissions("ORCH_LEADERS")
		if err != nil {
			return nil, err
		}
		if err := appendUser(result, accounts.Regional, m.PublicKeys["reader"], pub, sub, false); err != nil {
			return nil, err
		}
		pub, sub, err = p.RegionalPermissions(m.Region, m.NodeID)
		if err != nil {
			return nil, err
		}
		if err := appendUser(result, accounts.Regional, m.PublicKeys["regional"], pub, sub, false); err != nil {
			return nil, err
		}
	}
	return result, nil
}
func appendUser(options *server.Options, name, key string, pub, sub []string, response bool) error {
	var account *server.Account
	if name != "$G" {
		for _, a := range options.Accounts {
			if a.Name == name {
				account = a
				break
			}
		}
		if account == nil {
			return ErrInvalid
		}
	}
	permissions := &server.Permissions{Publish: &server.SubjectPermission{Allow: pub}, Subscribe: &server.SubjectPermission{Allow: sub}}
	if response {
		permissions.Response = &server.ResponsePermission{MaxMsgs: 1, Expires: 5 * time.Second}
	}
	options.Nkeys = append(options.Nkeys, &server.NkeyUser{Nkey: key, Account: account, Permissions: permissions})
	return nil
}

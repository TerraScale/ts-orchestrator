package placementpublisher

import (
	"cmp"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

const BrokerGrantsPath = "/etc/terrascale/placement/broker-hosts.json"
const BrokerGrantsEnvironment = "TS_ORCH_PLACEMENT_BROKER_GRANTS_FILE"
const MaximumBrokerGrantsBytes = 128 << 10

// BrokerGrant binds one dedicated host NKey to exact control subjects in an
// explicit existing global broker account. It contains no caller-defined grants.
type BrokerGrant struct {
	ServerIdentity string `json:"serverIdentity"`
	PublicNKey     string `json:"publicNkey"`
	Account        string `json:"account"`
}
type brokerGrantFile struct {
	Version int           `json:"version"`
	Hosts   []BrokerGrant `json:"hosts"`
}

func validateBrokerGrants(grants []BrokerGrant) error {
	if len(grants) == 0 || len(grants) > 128 {
		return ErrInvalidConfig
	}
	identities, keys := map[string]bool{}, map[string]bool{}
	for _, grant := range grants {
		if !validIdentity(grant.ServerIdentity) || !nkeys.IsValidPublicUserKey(grant.PublicNKey) || !validToken(grant.Account) || strings.ContainsAny(grant.Account, ".*>") || grant.Account == "$SYS" || identities[grant.ServerIdentity] || keys[grant.PublicNKey] {
			return ErrInvalidConfig
		}
		identities[grant.ServerIdentity] = true
		keys[grant.PublicNKey] = true
	}
	return nil
}
func EncodeBrokerGrants(grants []BrokerGrant) ([]byte, error) {
	if err := validateBrokerGrants(grants); err != nil {
		return nil, err
	}
	grants = slices.Clone(grants)
	slices.SortFunc(grants, func(a, b BrokerGrant) int { return cmp.Compare(a.ServerIdentity, b.ServerIdentity) })
	return json.Marshal(brokerGrantFile{Version: 1, Hosts: grants})
}
func ParseBrokerGrants(data []byte) ([]BrokerGrant, error) {
	if len(data) == 0 || len(data) > MaximumBrokerGrantsBytes {
		return nil, ErrInvalidConfig
	}
	var file brokerGrantFile
	if json.Unmarshal(data, &file, json.RejectUnknownMembers(true)) != nil || file.Version != 1 {
		return nil, ErrInvalidConfig
	}
	if err := validateBrokerGrants(file.Hosts); err != nil {
		return nil, err
	}
	return file.Hosts, nil
}

// ApplyBrokerGrants clones options and installs exact role permissions before
// the broker opens any listener. An existing key must already have exactly the
// same account and grants; a broader reused authority identity is refused.
func ApplyBrokerGrants(options *natsserver.Options, grants []BrokerGrant) (*natsserver.Options, error) {
	if options == nil {
		return nil, ErrInvalidConfig
	}
	if err := validateBrokerGrants(grants); err != nil {
		return nil, err
	}
	result := options.Clone()
	result.Nkeys = slices.Clone(options.Nkeys)
	for _, grant := range grants {
		var account *natsserver.Account
		if grant.Account != "$G" {
			for _, candidate := range options.Accounts {
				if candidate.Name == grant.Account {
					account = candidate
					break
				}
			}
			if account == nil {
				return nil, errors.New("placement publisher: declared global NATS account is absent")
			}
		}
		publish, subscribe, err := HostPermissions(grant.ServerIdentity)
		if err != nil {
			return nil, err
		}
		slices.Sort(publish)
		slices.Sort(subscribe)
		found := false
		for _, user := range result.Nkeys {
			if user.Nkey != grant.PublicNKey {
				continue
			}
			found = true
			existingAccount := "$G"
			if user.Account != nil {
				existingAccount = user.Account.Name
			}
			if existingAccount != grant.Account || user.Permissions == nil || user.Permissions.Publish == nil || user.Permissions.Subscribe == nil || user.Permissions.Response != nil || len(user.Permissions.Publish.Deny) != 0 || len(user.Permissions.Subscribe.Deny) != 0 {
				return nil, errors.New("placement publisher: existing NKey is not an exact host control identity")
			}
			existingPublish := slices.Clone(user.Permissions.Publish.Allow)
			existingSubscribe := slices.Clone(user.Permissions.Subscribe.Allow)
			slices.Sort(existingPublish)
			slices.Sort(existingSubscribe)
			if !slices.Equal(publish, existingPublish) || !slices.Equal(subscribe, existingSubscribe) {
				return nil, errors.New("placement publisher: existing NKey has conflicting permissions")
			}
		}
		if !found {
			result.Nkeys = append(result.Nkeys, &natsserver.NkeyUser{Nkey: grant.PublicNKey, Account: account, Permissions: &natsserver.Permissions{Publish: &natsserver.SubjectPermission{Allow: publish}, Subscribe: &natsserver.SubjectPermission{Allow: subscribe}}})
		}
	}
	return result, nil
}

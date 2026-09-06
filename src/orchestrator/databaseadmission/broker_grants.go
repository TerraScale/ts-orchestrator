package databaseadmission

import (
	"cmp"
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"

	natsserver "github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

const BrokerGrantsPath = "/etc/terrascale/database/broker-hosts.json"
const BrokerGrantsEnvironment = "TS_ORCH_DATABASE_BROKER_GRANTS_FILE"
const MaximumBrokerGrantsBytes = 128 << 10

// BrokerGrant binds one dedicated host NKey to exact control subjects in an
// explicit existing global broker account. It contains no caller-defined grants.
type BrokerGrant struct {
	ServerIdentity      string `json:"serverIdentity"`
	PublicNKey          string `json:"publicNkey"`
	LifecyclePublicNKey string `json:"lifecyclePublicNkey"`
	Account             string `json:"account"`
}
type brokerGrantFile struct {
	Version int           `json:"version"`
	Hosts   []BrokerGrant `json:"hosts"`
}

func validateBrokerGrants(grants []BrokerGrant) error {
	if len(grants) == 0 || len(grants) > 128 {
		return ErrInvalid
	}
	identities, keys := map[string]bool{}, map[string]bool{}
	for _, grant := range grants {
		if !databaseGrantIdentity(grant.ServerIdentity) || !nkeys.IsValidPublicUserKey(grant.PublicNKey) || !databaseGrantAccount(grant.Account) || strings.ContainsAny(grant.Account, ".*>") || grant.Account == "$SYS" || identities[grant.ServerIdentity] || keys[grant.PublicNKey] || !nkeys.IsValidPublicUserKey(grant.LifecyclePublicNKey) || grant.LifecyclePublicNKey == grant.PublicNKey || keys[grant.LifecyclePublicNKey] {
			return ErrInvalid
		}
		identities[grant.ServerIdentity] = true
		keys[grant.PublicNKey] = true
		keys[grant.LifecyclePublicNKey] = true
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
		return nil, ErrInvalid
	}
	var file brokerGrantFile
	if json.Unmarshal(data, &file, json.RejectUnknownMembers(true)) != nil || file.Version != 1 {
		return nil, ErrInvalid
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
		return nil, ErrInvalid
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
				return nil, errors.New("database admission: declared global NATS account is absent")
			}
		}
		publish, subscribe, err := HostPermissions(grant.ServerIdentity)
		if err != nil {
			return nil, err
		}
		lifecyclePublish, lifecycleSubscribe := LifecyclePublisherPermissions()
		for _, role := range []struct {
			key                string
			publish, subscribe []string
		}{{grant.PublicNKey, publish, subscribe}, {grant.LifecyclePublicNKey, lifecyclePublish, lifecycleSubscribe}} {
			publish, subscribe = role.publish, role.subscribe
			slices.Sort(publish)
			slices.Sort(subscribe)
			found := false
			for _, user := range result.Nkeys {
				if user.Nkey != role.key {
					continue
				}
				found = true
				existingAccount := "$G"
				if user.Account != nil {
					existingAccount = user.Account.Name
				}
				if existingAccount != grant.Account || user.Permissions == nil || user.Permissions.Publish == nil || user.Permissions.Subscribe == nil || user.Permissions.Response != nil || len(user.Permissions.Publish.Deny) != 0 || len(user.Permissions.Subscribe.Deny) != 0 {
					return nil, errors.New("database admission: existing NKey is not an exact host control identity")
				}
				existingPublish := slices.Clone(user.Permissions.Publish.Allow)
				existingSubscribe := slices.Clone(user.Permissions.Subscribe.Allow)
				slices.Sort(existingPublish)
				slices.Sort(existingSubscribe)
				if !slices.Equal(publish, existingPublish) || !slices.Equal(subscribe, existingSubscribe) {
					return nil, errors.New("database admission: existing NKey has conflicting permissions")
				}
			}
			if !found {
				result.Nkeys = append(result.Nkeys, &natsserver.NkeyUser{Nkey: role.key, Account: account, Permissions: &natsserver.Permissions{Publish: &natsserver.SubjectPermission{Allow: publish}, Subscribe: &natsserver.SubjectPermission{Allow: subscribe}}})
			}
		}
	}
	return result, nil
}

func databaseGrantIdentity(identity string) bool { _, err := HostSubject(identity); return err == nil }
func databaseGrantAccount(account string) bool {
	return account != "" && len(account) <= 128 && strings.TrimSpace(account) == account && !strings.ContainsAny(account, "\r\n\x00 \t")
}

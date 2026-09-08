package brokeradmission

import (
	"slices"
	"strings"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nkeys"
)

// ReaderGrant is owner-admitted broker inventory, separate from the delegated
// member enrollment signer. It accepts no caller-defined subjects or roles.
type ReaderGrant struct {
	BrokerID   string `json:"broker_id"`
	PublicNKey string `json:"public_nkey"`
	Account    string `json:"account"`
}

func ValidateReaderGrants(grants []ReaderGrant, brokerIDs []string, policy Policy) error {
	if len(grants) == 0 || len(grants) > 1024 || len(grants) != len(brokerIDs) || len(policy.Regions) == 0 {
		return ErrInvalid
	}
	expected := map[string]bool{}
	for _, id := range brokerIDs {
		if _, _, err := ReaderPermissions(id); err != nil || expected[id] {
			return ErrInvalid
		}
		expected[id] = true
	}
	accounts := map[string]bool{}
	for _, region := range policy.Regions {
		accounts[region.Global] = true
	}
	keys := map[string]bool{}
	for _, grant := range grants {
		if !expected[grant.BrokerID] || !nkeys.IsValidPublicUserKey(grant.PublicNKey) || keys[grant.PublicNKey] || !accounts[grant.Account] || !validToken(grant.Account) || grant.Account == "$SYS" || strings.Contains(grant.Account, ".") {
			return ErrInvalid
		}
		delete(expected, grant.BrokerID)
		keys[grant.PublicNKey] = true
	}
	if len(expected) != 0 {
		return ErrInvalid
	}
	return nil
}

// ApplyReaderGrants captures the owner-pinned reader identities into the
// immutable broker baseline. It never edits or replaces an existing identity.
func ApplyReaderGrants(baseline *server.Options, grants []ReaderGrant, brokerIDs []string, policy Policy) (*server.Options, error) {
	if baseline == nil || ValidateReaderGrants(grants, brokerIDs, policy) != nil {
		return nil, ErrInvalid
	}
	result := baseline.Clone()
	result.Nkeys = slices.Clone(baseline.Nkeys)
	for _, grant := range grants {
		for _, existing := range result.Nkeys {
			if existing != nil && existing.Nkey == grant.PublicNKey {
				return nil, ErrInvalid
			}
		}
		pub, sub, err := ReaderPermissions(grant.BrokerID)
		if err != nil {
			return nil, err
		}
		if err := appendUser(result, grant.Account, grant.PublicNKey, pub, sub, false); err != nil {
			return nil, err
		}
	}
	return result, nil
}

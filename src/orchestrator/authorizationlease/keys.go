// Package authorizationlease provisions verification keys for identity-authority
// leases. It neither signs leases nor refreshes their original expiry.
package authorizationlease

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
)

type Key struct {
	ID        string `json:"keyId"`
	Key       string `json:"key"`
	NotBefore int64  `json:"notBefore"`
	NotAfter  int64  `json:"notAfter"`
}

type Ring struct {
	Keys []Key `json:"keys"`
}

var ErrInvalid = errors.New("authorization lease: invalid verification configuration")

func Parse(raw []byte) (Ring, error) {
	var ring Ring
	if len(raw) > 4096 || json.Unmarshal(raw, &ring, json.RejectUnknownMembers(true)) != nil || ring.Validate() != nil {
		return Ring{}, ErrInvalid
	}
	return ring, nil
}

func Read(path string) (Ring, error) {
	raw, err := bootstrapcredentials.ReadFile(path, true, 4096)
	if err != nil {
		return Ring{}, ErrInvalid
	}
	defer clear(raw)
	return Parse(raw)
}

func (r Ring) Validate() error {
	if len(r.Keys) < 1 || len(r.Keys) > 2 {
		return ErrInvalid
	}
	ids, material := map[string]bool{}, map[string]bool{}
	for _, key := range r.Keys {
		if len(key.ID) < 1 || len(key.ID) > 32 || ids[key.ID] || material[key.Key] || len(key.Key) != 64 || key.Key != strings.ToLower(key.Key) || key.NotBefore < 0 || key.NotAfter <= key.NotBefore || key.NotAfter > 9007199254740991 {
			return ErrInvalid
		}
		for _, ch := range key.ID {
			if !(ch >= 'A' && ch <= 'Z' || ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '_' || ch == '-') {
				return ErrInvalid
			}
		}
		if _, err := hex.DecodeString(key.Key); err != nil {
			return ErrInvalid
		}
		ids[key.ID], material[key.Key] = true, true
	}
	return nil
}

// Active reports whether the ring can verify a newly issued lease now.
func (r Ring) Active(now int64) bool {
	return slices.ContainsFunc(r.Keys, func(key Key) bool { return key.NotBefore <= now && now < key.NotAfter })
}

func (r Ring) Digest() string {
	keys := slices.Clone(r.Keys)
	slices.SortFunc(keys, func(a, b Key) int { return strings.Compare(a.ID, b.ID) })
	var canonical strings.Builder
	for _, key := range keys {
		fmt.Fprintf(&canonical, "%s.%s.%d.%d\n", key.ID, key.Key, key.NotBefore, key.NotAfter)
	}
	digest := sha256.Sum256([]byte(canonical.String()))
	return hex.EncodeToString(digest[:])
}

func ValidateAudience(value string) error {
	if len(value) == 0 || len(value) > 256 {
		return ErrInvalid
	}
	for _, ch := range value {
		if ch <= 32 || ch > 126 {
			return ErrInvalid
		}
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.Opaque != "" || u.String() != value {
		return ErrInvalid
	}
	return nil
}

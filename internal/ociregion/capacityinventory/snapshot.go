// Package capacityinventory observes owned infrastructure without granting spending authority.
package capacityinventory

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"slices"
	"time"
)

type RegionScope struct {
	Cell, OCIRegion string
	CompartmentIDs  []string
}

// Scope is projected only from the caller's verified signed foundation grant.
// A Scope alone does not authorize a purchase.
type Scope struct {
	TenancyID, SHA256, Currency string
	Regions                     []RegionScope
	ExpiresAt                   time.Time
}

type Resource struct {
	ID, Cell, CompartmentID, LifecycleState string
	MonthlyCents                            uint64
}

// Snapshot keeps unsuccessful and unsupported observations visible. Only the
// SDK producer can seal it; changing exported observations invalidates its seal.
type Snapshot struct {
	ScopeSHA256, Currency string
	ObservedAt, ExpiresAt time.Time
	MonthlyCents          uint64
	Resources             []Resource
	CoveredCompartments   []string
	Pending               []string
	seal                  [32]byte
}

func (s Snapshot) digest() [32]byte {
	wire, _ := json.Marshal(s, json.Deterministic(true))
	return sha256.Sum256(wire)
}

func (s Snapshot) Validate(scope Scope, now time.Time) error {
	if s.seal == ([32]byte{}) || s.seal != s.digest() {
		return errors.New("infrastructure snapshot lacks intact SDK producer evidence")
	}
	if s.ScopeSHA256 != scope.SHA256 || s.Currency != scope.Currency || len(s.Pending) != 0 {
		return errors.New("infrastructure snapshot is incomplete or outside signed scope")
	}
	if s.ObservedAt.After(now) || now.Sub(s.ObservedAt) > 2*time.Minute || !now.Before(s.ExpiresAt) || s.ExpiresAt.After(scope.ExpiresAt) {
		return errors.New("infrastructure snapshot is stale or outside authority validity")
	}
	want := []string{}
	for _, region := range scope.Regions {
		for _, compartment := range region.CompartmentIDs {
			want = append(want, region.Cell+"/"+compartment)
		}
	}
	slices.Sort(want)
	got := slices.Clone(s.CoveredCompartments)
	slices.Sort(got)
	if len(want) == 0 || !slices.Equal(want, got) {
		return errors.New("infrastructure snapshot does not cover every authorized compartment")
	}
	return nil
}

func (s Scope) validate(now time.Time) error {
	digest, err := hex.DecodeString(s.SHA256)
	if err != nil || len(digest) != 32 || s.TenancyID == "" || (s.Currency != "USD" && s.Currency != "BRL") || len(s.Regions) == 0 || !now.Before(s.ExpiresAt) {
		return errors.New("verified infrastructure scope is absent, expired or incomplete")
	}
	seen := map[string]bool{}
	for _, region := range s.Regions {
		if region.Cell == "" || region.OCIRegion == "" || len(region.CompartmentIDs) == 0 {
			return errors.New("infrastructure scope lacks a regional compartment")
		}
		for _, compartment := range region.CompartmentIDs {
			key := region.Cell + "/" + compartment
			if compartment == "" || seen[key] {
				return fmt.Errorf("infrastructure scope repeats or omits a compartment: %s", key)
			}
			seen[key] = true
		}
	}
	return nil
}

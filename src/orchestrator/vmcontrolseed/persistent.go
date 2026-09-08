package vmcontrolseed

import (
	"encoding/json/v2"
	"errors"
	"slices"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/qualificationstate"
)

type persistedGRU struct {
	Version        int                 `json:"version"`
	RunID          string              `json:"runId"`
	GuestSHA256    string              `json:"guestSha256"`
	MaterialSHA256 string              `json:"materialSha256"`
	Materials      map[string]Material `json:"materials"`
}

// LoadOrCreateGRU retains the exact random credential and broker bytes before
// any initial host grant is issued. Reopening a run never invokes create when a
// committed or recoverable pending material record already exists.
func LoadOrCreateGRU(directory, runID string, guests []Guest, create func() (map[string]Material, error)) (map[string]Material, error) {
	bad := errors.New("vmcontrolseed: persisted initial material does not match run inventory")
	if !identifierPattern.MatchString(runID) || len(guests) == 0 || len(guests) > 3 || create == nil {
		return nil, bad
	}
	ordered := slices.Clone(guests)
	slices.SortFunc(ordered, func(a, b Guest) int { return strings.Compare(a.ID, b.ID) })
	guestBytes, err := json.Marshal(ordered, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	guestDigest := digest(guestBytes)
	parse := func(raw []byte) (map[string]Material, error) {
		var saved persistedGRU
		if json.Unmarshal(raw, &saved, json.RejectUnknownMembers(true)) != nil || saved.Version != 1 || saved.RunID != runID || saved.GuestSHA256 != guestDigest || len(saved.Materials) != len(ordered) {
			for _, m := range saved.Materials {
				m.Clear()
			}
			return nil, bad
		}
		valid := false
		defer func() {
			if !valid {
				for _, m := range saved.Materials {
					m.Clear()
				}
			}
		}()
		materialBytes, err := json.Marshal(saved.Materials, json.Deterministic(true))
		if err != nil {
			return nil, err
		}
		defer clear(materialBytes)
		if digest(materialBytes) != saved.MaterialSHA256 {
			return nil, bad
		}
		for _, guest := range ordered {
			m, exists := saved.Materials[guest.ID]
			if !exists || m.HostID != guest.ID || m.Address != guest.Address || m.Validate() != nil {
				return nil, bad
			}
			config, err := initialgrant.ParseConfig([]byte(m.Settings))
			if err != nil || config.Membership.PublicKey != guest.MembershipPublicKey || len(config.Peers) != len(ordered) {
				return nil, bad
			}
			for i, peer := range config.Peers {
				if peer.Instance != ordered[i].ID || peer.MembershipPublicKey != ordered[i].MembershipPublicKey {
					return nil, bad
				}
			}
		}
		valid = true
		return saved.Materials, nil
	}
	store, err := qualificationstate.Open(directory)
	if err != nil {
		return nil, err
	}
	defer store.Close()
	raw, err := store.LoadOrCreate("initial-control.json", 1<<20, func() ([]byte, error) {
		materials, err := create()
		if err != nil {
			for _, m := range materials {
				m.Clear()
			}
			return nil, err
		}
		defer func() {
			for _, m := range materials {
				m.Clear()
			}
		}()
		materialBytes, err := json.Marshal(materials, json.Deterministic(true))
		if err != nil {
			return nil, err
		}
		defer clear(materialBytes)
		return json.Marshal(persistedGRU{Version: 1, RunID: runID, GuestSHA256: guestDigest, MaterialSHA256: digest(materialBytes), Materials: materials}, json.Deterministic(true))
	}, func(raw []byte) error {
		materials, err := parse(raw)
		for _, m := range materials {
			m.Clear()
		}
		return err
	})
	if err != nil {
		return nil, err
	}
	defer clear(raw)
	return parse(raw)
}

package callerkey

import (
	"encoding/json/v2"
	"fmt"
	"maps"
	"math"
	"slices"
)

const registryLimit = 16 * 1024
const recoveryHeadroom = 2 * 1024
const orphanLimit = 8

func registryBytes(registry Registry) ([]byte, error) {
	if registry.Intent != nil && registry.Intent.Operation == "add" && registry.Intent.Entry != nil && slices.ContainsFunc(registry.Callers, func(c Caller) bool { return sameJSON(c, *registry.Intent.Entry) }) {
		intent := *registry.Intent
		intent.Entry = nil
		registry.Intent = &intent
	}
	return json.Marshal(registry, json.Deterministic(true))
}

func operationCapacity(targets []Target, registries []Registry, callers map[string]Caller, highWater map[string]uint64, intent *Intent, current string, state PrivateState) error {
	water := maps.Clone(highWater)
	advance(water, intent.Kid)
	entries := maps.Clone(callers)
	if intent.Operation == "retire" || intent.Operation == "cancel" || intent.Operation == "activate" {
		delete(entries, intent.Kid)
	}
	stored := slices.ContainsFunc(state.Versions, func(version KeyVersion) bool {
		kid, _ := privateKid(version.Snapshot)
		return kid == intent.Kid
	})
	cancel := *intent
	cancel.Operation, cancel.Replacement, cancel.PrivateVersion = "cancel", current, math.MaxInt64
	for i, target := range targets {
		limit := registryLimit - recoveryHeadroom
		if intent.Operation == "retire" || intent.Operation == "cancel" {
			limit = registryLimit
		}
		initial := registries[i]
		initial.Intent = intent
		candidates := []Registry{initial, mergedRegistry(callers, water, intent), mergedRegistry(callers, water, nil), mergedRegistry(entries, water, intent), mergedRegistry(entries, water, nil)}
		if intent.Operation == "retire" {
			initial.Callers = slices.DeleteFunc(slices.Clone(initial.Callers), func(c Caller) bool { return c.Kid == intent.Kid })
			candidates = []Registry{initial, mergedRegistry(entries, water, intent), mergedRegistry(entries, water, nil)}
		}
		if intent.Operation == "activate" || intent.Operation == "retire" && !stored {
			initial = registries[i]
			initial.Intent = &cancel
			candidates = append(candidates, initial, mergedRegistry(callers, water, &cancel), mergedRegistry(entries, water, &cancel))
		}
		for _, registry := range candidates {
			value, err := registryBytes(registry)
			if err != nil {
				return err
			}
			if len(value) > limit {
				return fmt.Errorf("registry capacity in region %s: intermediate document needs %d bytes, limit %d (%d bytes recovery headroom); retire entries with a current replacement", target.Cell, len(value), limit, recoveryHeadroom)
			}
		}
	}
	return nil
}

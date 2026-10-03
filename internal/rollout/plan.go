package rollout

import (
	"cmp"
	"fmt"
	"slices"
)

// PlanWaves orders units into quorum-aware waves. The first wave holds the
// canary units, later waves hold at most BatchSize units, and no wave holds
// two units of the same group, so a TerraBase pair keeps one serving seat and
// three controllers keep a majority. The seed unit is always last and alone.
// The result depends only on the input set, never on its order.
func PlanWaves(units []Unit, policy Policy) ([][]string, error) {
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	if len(units) == 0 || len(units) > MaxUnits {
		return nil, fmt.Errorf("%w: unit count", ErrInvalid)
	}
	ordered := slices.Clone(units)
	slices.SortFunc(ordered, func(a, b Unit) int { return cmp.Compare(a.ID, b.ID) })
	var seeds, rest []Unit
	seen := make(map[string]struct{}, len(ordered))
	for _, unit := range ordered {
		if !tokenRE.MatchString(unit.ID) || !tokenRE.MatchString(unit.Group) {
			return nil, fmt.Errorf("%w: unit identity %q", ErrInvalid, unit.ID)
		}
		if _, duplicate := seen[unit.ID]; duplicate {
			return nil, fmt.Errorf("%w: duplicate unit %q", ErrInvalid, unit.ID)
		}
		seen[unit.ID] = struct{}{}
		if unit.Seed {
			seeds = append(seeds, unit)
		} else {
			rest = append(rest, unit)
		}
	}
	if len(seeds) > 1 {
		return nil, fmt.Errorf("%w: more than one seed unit", ErrInvalid)
	}
	var waves [][]string
	first := true
	for len(rest) > 0 {
		limit := policy.BatchSize
		if first {
			limit = policy.CanaryUnits
		}
		wave, remaining := takeWave(rest, limit)
		waves = append(waves, wave)
		rest = remaining
		first = false
	}
	for _, seed := range seeds {
		waves = append(waves, []string{seed.ID})
	}
	return waves, nil
}

// takeWave greedily selects up to limit units with pairwise distinct groups,
// preserving order for the units it leaves behind.
func takeWave(units []Unit, limit int) ([]string, []Unit) {
	groups := map[string]struct{}{}
	var wave []string
	var remaining []Unit
	for _, unit := range units {
		if _, taken := groups[unit.Group]; len(wave) < limit && !taken {
			groups[unit.Group] = struct{}{}
			wave = append(wave, unit.ID)
			continue
		}
		remaining = append(remaining, unit)
	}
	return wave, remaining
}

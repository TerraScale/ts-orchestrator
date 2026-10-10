package capacitysim

import (
	"math"
	"math/rand/v2"
	"slices"
	"time"
)

// demand is one region's load in node units: a base level, step changes and a daily swing.
type demand struct {
	base, swing, phase float64
	steps              []demandStep // sorted by at
}

type demandStep struct {
	at time.Time
	to float64
}

// newDemand draws one region's profile from rng. The ramp region climbs past the 12-node ceiling and stays there.
func newDemand(rng *rand.Rand, start time.Time, ramp bool) demand {
	d := demand{base: 3 + 3.5*rng.Float64(), swing: 0.5 + rng.Float64(), phase: 2 * math.Pi * rng.Float64()}
	if ramp {
		for i := range 13 {
			at := start.Add(4*time.Hour + time.Duration(i)*30*time.Minute)
			d.steps = append(d.steps, demandStep{at: at, to: 4 + float64(i)*10/12})
		}
		return d
	}
	for range 2 {
		at := start.Add(time.Duration(rng.Int64N(int64(40 * time.Hour))))
		d.steps = append(d.steps, demandStep{at: at, to: 1.5 + 6*rng.Float64()})
	}
	slices.SortFunc(d.steps, func(a, b demandStep) int { return a.at.Compare(b.at) })
	return d
}

// levelAt is the demand at now, never below 0.2 node.
func (d demand) levelAt(now time.Time) float64 {
	level := d.base
	for _, step := range d.steps {
		if !now.Before(step.at) {
			level = step.to
		}
	}
	day := 2 * math.Pi * float64(now.Unix()) / (24 * 3600)
	return max(0.2, level+d.swing*math.Sin(day+d.phase))
}

package ocicost

import (
	"time"
)

func validReport() Report {
	return Report{
		Version:    Version,
		Cell:       "gru",
		OCIRegion:  "sa-saopaulo-1",
		Currency:   "BRL",
		ObservedAt: time.Date(2026, time.October, 10, 19, 0, 0, 0, time.UTC),
		Through:    time.Date(2026, time.October, 8, 0, 0, 0, 0, time.UTC),
		Days:       []Day{{Day: time.Date(2026, time.October, 1, 0, 0, 0, 0, time.UTC), Cents: 267}},
		Services:   []Line{{Name: "Block Storage", Cents: 807}},
		Components: []Line{{Name: "terrabase", Cents: 437}},
	}
}

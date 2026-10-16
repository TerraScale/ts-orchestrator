package hostload

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
)

func validWANReport() Report {
	return Report{SchemaVersion: SchemaVersion, Roles: []RoleUsage{{Role: terrabase.Role,
		WAN: &terrabase.WANObservation{ObservedAt: time.Now().UTC(), ReceiverRegion: "gru-1", Sources: []terrabase.WANSource{{
			SourceRegion: "sfo-1", LagGroups: new(0.0), StalenessSeconds: new(1.5),
			Members: new(3.0), Unregistered: new(0.0), Conflicts: new(0.0), AheadFailuresTotal: new(1.0),
		}}}}}}
}

func TestReportValidatesSeparateWANObservation(t *testing.T) {
	if err := validWANReport().Validate(); err != nil {
		t.Fatal(err)
	}
	for name, change := range map[string]func(*RoleUsage){
		"different role":   func(role *RoleUsage) { role.Role = "api" },
		"missing gauge":    func(role *RoleUsage) { role.WAN.Sources[0].Members = nil },
		"NaN":              func(role *RoleUsage) { role.WAN.Sources[0].StalenessSeconds = new(math.NaN()) },
		"infinity":         func(role *RoleUsage) { role.WAN.Sources[0].LagGroups = new(math.Inf(1)) },
		"negative":         func(role *RoleUsage) { role.WAN.Sources[0].Conflicts = new(-1.0) },
		"fractional count": func(role *RoleUsage) { role.WAN.Sources[0].Members = new(1.5) },
		"invalid counter":  func(role *RoleUsage) { role.WAN.Sources[0].AheadFailuresTotal = new(math.Inf(1)) },
		"invalid region":   func(role *RoleUsage) { role.WAN.Sources[0].SourceRegion = "sfo.*" },
		"invalid receiver": func(role *RoleUsage) { role.WAN.ReceiverRegion = "GRU" },
		"missing receiver": func(role *RoleUsage) { role.WAN.ReceiverRegion = "" },
		"duplicate source": func(role *RoleUsage) { role.WAN.Sources = append(role.WAN.Sources, role.WAN.Sources[0]) },
		"no sources":       func(role *RoleUsage) { role.WAN.Sources = nil },
		"source bound":     func(role *RoleUsage) { role.WAN.Sources = make([]terrabase.WANSource, terrabase.MaxWANRegions+1) },
		"zero time":        func(role *RoleUsage) { role.WAN.ObservedAt = time.Time{} },
		"non UTC":          func(role *RoleUsage) { role.WAN.ObservedAt = role.WAN.ObservedAt.In(time.FixedZone("offset", 3600)) },
	} {
		t.Run(name, func(t *testing.T) {
			report := validWANReport()
			change(&report.Roles[0])
			if err := report.Validate(); !errors.Is(err, ErrInvalidReport) {
				t.Fatalf("invalid WAN report accepted: %v", err)
			}
		})
	}
	// Zero answering members is valid failure telemetry, never measured success.
	report := validWANReport()
	report.Roles[0].WAN.Sources[0].Members = new(0.0)
	report.Roles[0].WAN.Sources[0].AheadFailuresTotal = nil
	if err := report.Validate(); err != nil {
		t.Fatalf("unanswered telemetry rejected: %v", err)
	}
}

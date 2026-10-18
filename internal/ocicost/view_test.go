package ocicost

import (
	"time"
)

// viewReport is October 2026 through the 9th, with October 9th partial.
func viewReport() Report {
	report := Report{Version: Version, Cell: "gru", OCIRegion: "sa-saopaulo-1", Currency: "USD",
		ObservedAt: time.Date(2026, 10, 10, 10, 0, 0, 0, time.UTC),
		Through:    time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC),
		Services:   []Line{{Name: "compute", Cents: 500}, {Name: "storage", Cents: 300}},
		Components: []Line{{Name: "controller", Cents: 300}, {Name: "terrabase", Cents: 200}}}
	for day := 1; day <= 8; day++ {
		report.Days = append(report.Days, Day{Day: time.Date(2026, 10, day, 0, 0, 0, 0, time.UTC), Cents: 100})
	}
	report.Days = append(report.Days, Day{Day: time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC), Cents: 40})
	return report
}

var viewNow = time.Date(2026, 10, 10, 12, 0, 0, 0, time.UTC)




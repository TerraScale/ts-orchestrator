package observability

import (
	"log/slog"
	"strings"
	"testing"
	"time"
)

func TestLogRedactionTypedTimeZones(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name      string
		zone      string
		truncated bool
	}{
		{"credential", "Bearer timeFixtureSecret123", false},
		{"oversized", strings.Repeat("x", 8<<20), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			at := time.Date(2026, 10, 9, 12, 0, 0, 0, time.FixedZone(tc.zone, 3600))
			for _, format := range []string{"json", "logfmt"} {
				t.Run(format, func(t *testing.T) {
					logger, output, bus := redactionLogger(t, format)
					logger.Warn("timestamp", slog.Time("at", at))
					assertNoLogSecrets(t, output, bus, "timeFixtureSecret123")
					events := bus.Recent(0)
					if len(events) != 1 || len(events[0].Attrs["at"]) > maxLogValueBytes {
						t.Fatal("typed time attribute was not bounded")
					}
					if marked := events[0].Attrs[logTruncatedKey] == "true"; marked != tc.truncated {
						t.Fatal("typed time truncation marker disagrees with lost detail")
					}
				})
			}
			capture := new(recordCapture)
			handler := &redactingHandler{next: capture}
			record := slog.NewRecord(time.Now().UTC(), slog.LevelWarn, "timestamp", 0)
			record.AddAttrs(slog.Time("at", at))
			if err := handler.Handle(t.Context(), record); err != nil {
				t.Fatal(err)
			}
			found := false
			capture.record.Attrs(func(attr slog.Attr) bool {
				if attr.Key == "at" {
					found = true
					frozen := attr.Value.Time()
					zone, offset := frozen.Zone()
					if !frozen.Equal(at) || offset != 3600 || len(zone) > maxLogNameBytes || strings.Contains(zone, "timeFixtureSecret123") {
						t.Fatal("typed time redaction changed its instant/offset or retained unsafe zone metadata")
					}
				}
				return true
			})
			if !found {
				t.Fatal("typed time attribute disappeared")
			}
			if capture.record.Time != record.Time {
				t.Fatal("record timestamp changed")
			}
		})
	}
}

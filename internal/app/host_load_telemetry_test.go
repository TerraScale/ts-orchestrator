package app

import (
	"io"
	"strings"
	"testing"
	"time"
)

func TestEffectiveLoadTelemetryInterval(t *testing.T) {
	for _, tt := range []struct {
		name    string
		seconds *int
		want    time.Duration
		invalid bool
	}{
		{name: "omitted", want: 15 * time.Second},
		{name: "off", seconds: new(0)},
		{name: "minimum", seconds: new(5), want: 5 * time.Second},
		{name: "explicit default", seconds: new(15), want: 15 * time.Second},
		{name: "custom", seconds: new(60), want: time.Minute},
		{name: "maximum", seconds: new(3600), want: time.Hour},
		{name: "negative", seconds: new(-1), invalid: true},
		{name: "below minimum", seconds: new(4), invalid: true},
		{name: "above maximum", seconds: new(3601), invalid: true},
		{name: "overflow to zero", seconds: new(1 << 55), invalid: true},
		{name: "maximum integer", seconds: new(int(^uint(0) >> 1)), invalid: true},
	} {
		t.Run(tt.name, func(t *testing.T) {
			got, err := effectiveLoadTelemetryInterval(tt.seconds)
			if (err != nil) != tt.invalid || got != tt.want {
				t.Fatalf("effective interval = %v, %v; want %v, invalid=%v", got, err, tt.want, tt.invalid)
			}
			if tt.invalid {
				err := runHost(t.Context(), Config{Host: HostConfig{LoadTelemetrySeconds: tt.seconds}}, "", io.Discard)
				if err == nil || !strings.Contains(err.Error(), "load_telemetry_seconds") {
					t.Fatalf("runHost did not reject the interval before startup: %v", err)
				}
			}
		})
	}
}

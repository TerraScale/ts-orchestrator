package observability

import (
	"io"
	"math"
	"strconv"
	"strings"

	"github.com/VictoriaMetrics/metrics"
)

// Series formats a metric name with label pairs, escaping label values the
// way the Prometheus text format requires. Pairs are name, value, name,
// value; a trailing unpaired name is ignored. Label names must be constant
// identifiers chosen by the caller, never input data.
func Series(name string, pairs ...string) string {
	if len(pairs) < 2 {
		return name
	}
	var builder strings.Builder
	builder.WriteString(name)
	builder.WriteByte('{')
	for index := 0; index+1 < len(pairs); index += 2 {
		if index > 0 {
			builder.WriteByte(',')
		}
		builder.WriteString(pairs[index])
		builder.WriteString(`="`)
		builder.WriteString(escapeLabelValue(pairs[index+1]))
		builder.WriteByte('"')
	}
	builder.WriteByte('}')
	return builder.String()
}

func escapeLabelValue(value string) string {
	if !strings.ContainsAny(value, "\\\"\n") {
		return value
	}
	var builder strings.Builder
	for _, character := range value {
		switch character {
		case '\\':
			builder.WriteString(`\\`)
		case '"':
			builder.WriteString(`\"`)
		case '\n':
			builder.WriteString(`\n`)
		default:
			builder.WriteRune(character)
		}
	}
	return builder.String()
}

// WriteGauge writes one gauge sample for scrape-time writers.
func WriteGauge(w io.Writer, series string, value float64) {
	writeSample(w, series, "gauge", value)
}

// WriteCounter writes one cumulative counter sample for scrape-time writers.
func WriteCounter(w io.Writer, series string, value float64) {
	writeSample(w, series, "counter", value)
}

// writeSample prints integral values without an exponent, so byte and
// message counts stay exact and readable in the exposition.
func writeSample(w io.Writer, series, kind string, value float64) {
	metrics.WriteMetadataIfNeeded(w, series, kind)
	formatted := strconv.FormatFloat(value, 'g', -1, 64)
	if value == math.Trunc(value) && math.Abs(value) < 1<<53 {
		formatted = strconv.FormatInt(int64(value), 10)
	}
	_, _ = io.WriteString(w, series+" "+formatted+"\n")
}

// Bool converts a flag into a 0/1 gauge value.
func Bool(value bool) float64 {
	if value {
		return 1
	}
	return 0
}

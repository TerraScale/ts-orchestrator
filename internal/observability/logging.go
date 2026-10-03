package observability

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"maps"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/VictoriaMetrics/metrics"
)

const (
	// EventKey marks a record below WARN as a notable event, for example
	// slog.Info("member serving", observability.EventKey, true).
	EventKey = "event"
	// ComponentKey names the feature slice that emitted a record.
	ComponentKey = "component"
)

// LogConfig selects the process-wide structured log format.
type LogConfig struct {
	// Format is "json" (default) or "logfmt".
	Format string
	// Level is "debug", "info" (default), "warn" or "error".
	Level string
}

// ParseLogConfig validates a format and level and fills the defaults.
func ParseLogConfig(format, level string) (LogConfig, slog.Level, error) {
	config := LogConfig{Format: strings.ToLower(format), Level: strings.ToLower(level)}
	if config.Format == "" {
		config.Format = "json"
	}
	if config.Format != "json" && config.Format != "logfmt" {
		return LogConfig{}, 0, errors.New("log format must be json or logfmt")
	}
	if config.Level == "" {
		config.Level = "info"
	}
	var parsed slog.Level
	switch config.Level {
	case "debug":
		parsed = slog.LevelDebug
	case "info":
		parsed = slog.LevelInfo
	case "warn":
		parsed = slog.LevelWarn
	case "error":
		parsed = slog.LevelError
	default:
		return LogConfig{}, 0, errors.New("log level must be debug, info, warn or error")
	}
	return config, parsed, nil
}

// NewLogger builds the structured logger for one runtime role. Records at
// WARN and above, and records carrying EventKey=true, are also published to
// bus when it is non-nil. Static attributes such as cell, member and role are
// attached to every record.
func NewLogger(output io.Writer, config LogConfig, bus *EventBus, attrs ...slog.Attr) (*slog.Logger, error) {
	config, level, err := ParseLogConfig(config.Format, config.Level)
	if err != nil {
		return nil, err
	}
	options := &slog.HandlerOptions{Level: level}
	var handler slog.Handler
	if config.Format == "logfmt" {
		handler = slog.NewTextHandler(output, options)
	} else {
		handler = slog.NewJSONHandler(output, options)
	}
	if bus != nil {
		handler = &EventTee{next: handler, bus: bus, counters: newLogCounters(), repeats: newEventRepeats()}
	}
	if len(attrs) > 0 {
		handler = handler.WithAttrs(attrs)
	}
	return slog.New(handler), nil
}

// ConfigureDefault installs logger as the process default. The standard
// library log package then writes through the same structured handler.
func ConfigureDefault(logger *slog.Logger) {
	if logger != nil {
		slog.SetDefault(logger)
	}
}

// EventTee forwards every record to the next handler and publishes notable
// records to an EventBus. Static attributes such as cell and role stay on
// the log line but are not copied into each event.
type EventTee struct {
	next     slog.Handler
	bus      *EventBus
	counters *logCounters
	repeats  *eventRepeats
	scoped   []slog.Attr
	groups   []string
}

// LogMetrics is the counter set of records emitted by level. It is shared by
// every EventTee in the process, because slog has one default logger.
var LogMetrics = metrics.NewSet()

type logCounters struct {
	byLevel map[slog.Level]*metrics.Counter
}

var sharedLogCounters atomic.Pointer[logCounters]

func newLogCounters() *logCounters {
	if existing := sharedLogCounters.Load(); existing != nil {
		return existing
	}
	counters := &logCounters{byLevel: map[slog.Level]*metrics.Counter{}}
	for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		counters.byLevel[level] = LogMetrics.GetOrCreateCounter(
			Series(MetricPrefix+"log_records_total", "level", strings.ToLower(level.String())))
	}
	if !sharedLogCounters.CompareAndSwap(nil, counters) {
		return sharedLogCounters.Load()
	}
	return counters
}

func (counters *logCounters) count(level slog.Level) {
	switch {
	case level >= slog.LevelError:
		counters.byLevel[slog.LevelError].Inc()
	case level >= slog.LevelWarn:
		counters.byLevel[slog.LevelWarn].Inc()
	case level >= slog.LevelInfo:
		counters.byLevel[slog.LevelInfo].Inc()
	default:
		counters.byLevel[slog.LevelDebug].Inc()
	}
}

// Enabled admits every record at INFO and above even when the log level is
// stricter, because an INFO record tagged EventKey=true or a WARN record under
// log_level=error still belongs on the event bus. Handle forwards to the log
// output only what its own level admits.
func (tee *EventTee) Enabled(ctx context.Context, level slog.Level) bool {
	return level >= slog.LevelInfo || tee.next.Enabled(ctx, level)
}

func (tee *EventTee) Handle(ctx context.Context, record slog.Record) error {
	if record.Level >= slog.LevelWarn || tee.marked(record) {
		event := eventFromRecord(record, tee.eventScope(), tee.groups)
		if tee.repeats.admit(event, record.Time) {
			tee.bus.Publish(event)
		}
	}
	if !tee.next.Enabled(ctx, record.Level) {
		return nil
	}
	tee.counters.count(record.Level)
	return tee.next.Handle(ctx, record)
}

// eventScope keeps only a scoped component attribute; static identity
// attributes are the same for every event of this process.
func (tee *EventTee) eventScope() []slog.Attr {
	for _, attr := range slices.Backward(tee.scoped) {
		if attr.Key == ComponentKey {
			return []slog.Attr{attr}
		}
	}
	return nil
}

func (tee *EventTee) marked(record slog.Record) bool {
	marked := false
	record.Attrs(func(attr slog.Attr) bool {
		if attr.Key == EventKey && attr.Value.Kind() == slog.KindBool && attr.Value.Bool() {
			marked = true
			return false
		}
		return true
	})
	return marked
}

func (tee *EventTee) WithAttrs(attrs []slog.Attr) slog.Handler {
	clone := *tee
	clone.next = tee.next.WithAttrs(attrs)
	if len(tee.groups) == 0 {
		clone.scoped = append(slices.Clone(tee.scoped), attrs...)
	}
	return &clone
}

func (tee *EventTee) WithGroup(name string) slog.Handler {
	clone := *tee
	clone.next = tee.next.WithGroup(name)
	clone.groups = append(slices.Clone(tee.groups), name)
	return &clone
}

// eventRepeatWindow is how long an identical event is kept off the bus after
// it was published. A loop that logs the same warning every tick still writes
// every log line, but the bounded ring keeps one copy per window instead of
// being flushed of every other event within hours.
const (
	eventRepeatWindow = 5 * time.Minute
	maxEventRepeats   = 512
)

// eventRepeats remembers when each distinct event was last published. It is
// shared by every clone of one EventTee.
type eventRepeats struct {
	mu         sync.Mutex
	last       map[string]time.Time
	suppressed atomic.Uint64
}

func newEventRepeats() *eventRepeats {
	return &eventRepeats{last: map[string]time.Time{}}
}

// admit reports whether event should be published at now, recording it if
// so. Events differing in level, component, message or any attribute are
// distinct.
func (repeats *eventRepeats) admit(event Event, now time.Time) bool {
	if repeats == nil {
		return true
	}
	if now.IsZero() {
		now = time.Now()
	}
	key := eventRepeatKey(event)
	repeats.mu.Lock()
	defer repeats.mu.Unlock()
	if last, ok := repeats.last[key]; ok && now.Sub(last) >= 0 && now.Sub(last) < eventRepeatWindow {
		repeats.suppressed.Add(1)
		return false
	}
	if len(repeats.last) >= maxEventRepeats {
		for existing, at := range repeats.last {
			if now.Sub(at) >= eventRepeatWindow {
				delete(repeats.last, existing)
			}
		}
		if len(repeats.last) >= maxEventRepeats {
			clear(repeats.last)
		}
	}
	repeats.last[key] = now
	return true
}

func eventRepeatKey(event Event) string {
	var key strings.Builder
	key.WriteString(event.Level)
	key.WriteByte(0)
	key.WriteString(event.Component)
	key.WriteByte(0)
	key.WriteString(event.Message)
	for _, name := range slices.Sorted(maps.Keys(event.Attrs)) {
		key.WriteByte(0)
		key.WriteString(name)
		key.WriteByte('=')
		key.WriteString(event.Attrs[name])
	}
	return key.String()
}

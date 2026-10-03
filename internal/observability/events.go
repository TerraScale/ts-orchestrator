package observability

import (
	"context"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"
)

// DefaultEventCapacity bounds the in-memory event ring.
const DefaultEventCapacity = 2048

// Event is one notable occurrence a dashboard can list or stream. Attributes
// are flattened to strings so a subscriber never holds a reference into a
// producer's state.
type Event struct {
	Sequence  uint64            `json:"sequence"`
	Time      time.Time         `json:"time"`
	Level     string            `json:"level"`
	Component string            `json:"component,omitempty"`
	Message   string            `json:"message"`
	Attrs     map[string]string `json:"attrs,omitempty"`
}

// EventBus is a bounded ring of recent events with non-blocking fan-out.
// Publish never waits for a subscriber: a full subscriber channel drops the
// event for that subscriber and counts it, so a slow dashboard cannot delay
// the controller or authority paths that log.
type EventBus struct {
	mu          sync.Mutex
	ring        []Event
	start       int
	size        int
	sequence    uint64
	subscribers map[*eventSubscriber]struct{}
	published   atomic.Uint64
	dropped     atomic.Uint64
}

type eventSubscriber struct {
	events chan Event
}

// NewEventBus returns a ring holding at most capacity events. A non-positive
// capacity selects DefaultEventCapacity.
func NewEventBus(capacity int) *EventBus {
	if capacity <= 0 {
		capacity = DefaultEventCapacity
	}
	return &EventBus{ring: make([]Event, capacity), subscribers: map[*eventSubscriber]struct{}{}}
}

// initLocked gives a zero-value EventBus the default ring and subscriber set,
// so a bus that was declared rather than built with NewEventBus cannot divide
// by zero on the log path. bus.mu must be held.
func (bus *EventBus) initLocked() {
	if len(bus.ring) == 0 {
		bus.ring = make([]Event, DefaultEventCapacity)
	}
	if bus.subscribers == nil {
		bus.subscribers = map[*eventSubscriber]struct{}{}
	}
}

// Publish stores an event, assigning its sequence and a missing timestamp,
// and offers it to every subscriber. It returns the stored event.
func (bus *EventBus) Publish(event Event) Event {
	if bus == nil {
		return event
	}
	if event.Time.IsZero() {
		event.Time = time.Now().UTC()
	}
	bus.mu.Lock()
	bus.initLocked()
	bus.sequence++
	event.Sequence = bus.sequence
	index := (bus.start + bus.size) % len(bus.ring)
	if bus.size == len(bus.ring) {
		bus.start = (bus.start + 1) % len(bus.ring)
	} else {
		bus.size++
	}
	bus.ring[index] = event
	for subscriber := range bus.subscribers {
		select {
		case subscriber.events <- event:
		default:
			bus.dropped.Add(1)
		}
	}
	bus.mu.Unlock()
	bus.published.Add(1)
	return event
}

// Recent returns up to limit of the newest events, oldest first. A
// non-positive limit returns the whole ring.
func (bus *EventBus) Recent(limit int) []Event {
	return bus.Since(0, limit)
}

// Since returns up to limit events with a sequence greater than after, oldest
// first, keeping the newest when more are available. A dashboard reconnecting
// with its last seen sequence uses it to resume without duplicates.
func (bus *EventBus) Since(after uint64, limit int) []Event {
	if bus == nil {
		return nil
	}
	bus.mu.Lock()
	defer bus.mu.Unlock()
	events := make([]Event, 0, bus.size)
	for offset := range bus.size {
		event := bus.ring[(bus.start+offset)%len(bus.ring)]
		if event.Sequence > after {
			events = append(events, event)
		}
	}
	if limit > 0 && len(events) > limit {
		events = events[len(events)-limit:]
	}
	return events
}

// Subscribe streams events published after the call until ctx ends, when the
// channel is closed. buffer bounds how far a subscriber may fall behind
// before it loses events.
func (bus *EventBus) Subscribe(ctx context.Context, buffer int) <-chan Event {
	if buffer <= 0 {
		buffer = 64
	}
	subscriber := &eventSubscriber{events: make(chan Event, buffer)}
	if bus == nil {
		close(subscriber.events)
		return subscriber.events
	}
	bus.mu.Lock()
	bus.initLocked()
	bus.subscribers[subscriber] = struct{}{}
	bus.mu.Unlock()
	context.AfterFunc(ctx, func() {
		bus.mu.Lock()
		delete(bus.subscribers, subscriber)
		bus.mu.Unlock()
		close(subscriber.events)
	})
	return subscriber.events
}

// Stats returns cumulative published and subscriber-dropped event counts.
func (bus *EventBus) Stats() (published, dropped uint64) {
	if bus == nil {
		return 0, 0
	}
	return bus.published.Load(), bus.dropped.Load()
}

// eventFromRecord flattens a slog record and its handler-scoped attributes.
func eventFromRecord(record slog.Record, scoped []slog.Attr, groups []string) Event {
	event := Event{Time: record.Time.UTC(), Level: record.Level.String(), Message: record.Message}
	attrs := make(map[string]string, record.NumAttrs()+len(scoped))
	add := func(attr slog.Attr) {
		prefix := ""
		for _, group := range groups {
			prefix += group + "."
		}
		flattenAttr(attrs, prefix, attr)
	}
	for _, attr := range scoped {
		add(attr)
	}
	record.Attrs(func(attr slog.Attr) bool {
		add(attr)
		return true
	})
	if component, ok := attrs[ComponentKey]; ok {
		event.Component = component
		delete(attrs, ComponentKey)
	}
	delete(attrs, EventKey)
	if len(attrs) > 0 {
		event.Attrs = attrs
	}
	return event
}

const (
	maxEventAttrs     = 32
	maxEventAttrBytes = 512
)

func flattenAttr(attrs map[string]string, prefix string, attr slog.Attr) {
	attr.Value = attr.Value.Resolve()
	if attr.Equal(slog.Attr{}) || len(attrs) >= maxEventAttrs {
		return
	}
	if attr.Value.Kind() == slog.KindGroup {
		nested := prefix
		if attr.Key != "" {
			nested += attr.Key + "."
		}
		for _, child := range attr.Value.Group() {
			flattenAttr(attrs, nested, child)
		}
		return
	}
	value := attr.Value.String()
	if len(value) > maxEventAttrBytes {
		// Cut on a rune boundary so a long non-ASCII value never carries a
		// split UTF-8 sequence into the event.
		cut := maxEventAttrBytes
		for cut > 0 && !utf8.RuneStart(value[cut]) {
			cut--
		}
		value = value[:cut] + "..."
	}
	attrs[prefix+attr.Key] = value
}

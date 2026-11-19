package apppull

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"os"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/releasefailure"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const EventBucket = "TS_ORCH_APP_EVENTS"

type notice struct {
	Stage   string              `json:"stage"`
	Release string              `json:"release"`
	Reason  string              `json:"reason"`
	Event   observability.Event `json:"event"`
}

type Events struct {
	mu        sync.Mutex
	region    string
	node      string
	bus       *observability.EventBus
	kv        jetstream.KeyValue
	states    map[string]notice
	pending   map[string]notice
	published map[string]time.Time
}

func NewEvents(region string, bus *observability.EventBus) *Events {
	node, _ := os.Hostname()
	return &Events{region: region, node: node, bus: bus, states: map[string]notice{}, pending: map[string]notice{}, published: map[string]time.Time{}}
}

func (e *Events) Attach(ctx context.Context, conn *nats.Conn) (func(), error) {
	js, err := jetstream.New(conn)
	if err != nil {
		return nil, err
	}
	kv, err := js.CreateKeyValue(ctx, jetstream.KeyValueConfig{Bucket: EventBucket, Replicas: mesh.StoreReplicas(e.region), History: 1, MaxValueSize: 16 << 10, Storage: jetstream.FileStorage})
	if err != nil {
		return nil, err
	}
	watch, err := kv.WatchAll(ctx)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	e.kv = kv
	for key, state := range e.pending {
		if state.Event.Time.IsZero() {
			continue
		}
		if _, err := e.save(ctx, key, state); err != nil {
			e.kv = nil
			e.mu.Unlock()
			_ = watch.Stop()
			return nil, err
		}
		delete(e.pending, key)
	}
	e.mu.Unlock()
	go func() {
		for entry := range watch.Updates() {
			if entry == nil || entry.Operation() != jetstream.KeyValuePut || !strings.HasPrefix(entry.Key(), e.region+".") {
				continue
			}
			var state notice
			if json.Unmarshal(entry.Value(), &state) != nil || state.Event.Time.IsZero() {
				continue
			}
			e.mu.Lock()
			if e.published[entry.Key()].Before(state.Event.Time) {
				e.published[entry.Key()] = state.Event.Time
				e.bus.Publish(state.Event)
			}
			e.mu.Unlock()
		}
	}()
	return func() {
		e.mu.Lock()
		if e.kv == kv {
			e.kv = nil
		}
		e.mu.Unlock()
		_ = watch.Stop()
	}, nil
}

func (e *Events) Report(ctx context.Context, level slog.Level, message, service, release, stage string, err error) {
	failure := releasefailure.At(stage, err).(*releasefailure.Failure)
	key := e.key(service, failure.Stage)
	next := notice{Stage: failure.Stage, Release: release, Reason: failure.Error(), Event: observability.Event{Time: time.Now().UTC(),
		Level: level.String(), Component: "apppull", Message: message, Attrs: map[string]string{"service": service, "region": e.region, "release": release, "reason": failure.Error(), "node": e.node}}}
	e.mu.Lock()
	defer e.mu.Unlock()
	before := e.states[key]
	e.pending[key] = next
	if e.kv != nil {
		changed, writeErr := e.save(ctx, key, next)
		if writeErr != nil {
			e.storeFailure(ctx, writeErr)
		} else if !changed {
			delete(e.pending, key)
			return
		} else {
			delete(e.pending, key)
		}
	}
	e.states[key] = next
	if before.Release == next.Release && before.Reason == next.Reason {
		return
	}
	e.published[key] = next.Event.Time
	e.bus.Publish(next.Event)
	slog.InfoContext(ctx, message, observability.ComponentKey, "apppull", "service", service,
		"region", e.region, "release", release, "reason", failure.Error(), "node", e.node, "outcome_level", level.String())
}

func (e *Events) Recover(ctx context.Context, service string, stages ...string) {
	e.mu.Lock()
	defer e.mu.Unlock()
	keys := []string{}
	for _, stage := range stages {
		keys = append(keys, e.key(service, stage))
	}
	if len(stages) == 0 {
		for key := range e.states {
			keys = append(keys, key)
		}
		if e.kv != nil {
			stored, err := e.kv.Keys(ctx)
			if err != nil && !errors.Is(err, jetstream.ErrNoKeysFound) {
				e.storeFailure(ctx, err)
				return
			}
			keys = append(keys, stored...)
		}
		slices.Sort(keys)
		keys = slices.Compact(keys)
	}
	for _, key := range keys {
		if !strings.HasPrefix(key, e.region+"."+service+".") {
			continue
		}
		state := e.states[key]
		var revision uint64
		if e.kv != nil {
			entry, err := e.kv.Get(ctx, key)
			if errors.Is(err, jetstream.ErrKeyNotFound) {
				continue
			}
			if err != nil {
				e.storeFailure(ctx, err)
				continue
			}
			if err := json.Unmarshal(entry.Value(), &state); err != nil {
				e.storeFailure(ctx, err)
				continue
			}
			revision = entry.Revision()
		}
		if state.Reason == "" || len(stages) != 0 && !slices.Contains(stages, state.Stage) {
			continue
		}
		state.Reason = ""
		e.states[key] = state
		e.pending[key] = state
		if e.kv != nil {
			data, err := json.Marshal(state)
			if err == nil {
				_, err = e.kv.Update(ctx, key, data, revision)
			}
			if err != nil {
				e.storeFailure(ctx, err)
			} else {
				delete(e.pending, key)
			}
		}
	}
}

func (e *Events) key(service, stage string) string {
	if service == "apps" {
		return e.region + "." + service + "." + e.node + "." + strings.ReplaceAll(stage, " ", "-")
	}
	return e.region + "." + service + "." + strings.ReplaceAll(stage, " ", "-")
}

func (e *Events) save(ctx context.Context, key string, next notice) (bool, error) {
	entry, err := e.kv.Get(ctx, key)
	if err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		return false, err
	}
	data, encodeErr := json.Marshal(next)
	if encodeErr != nil {
		return false, encodeErr
	}
	if err != nil {
		_, err = e.kv.Create(ctx, key, data)
	} else {
		var before notice
		if err := json.Unmarshal(entry.Value(), &before); err != nil {
			return false, err
		}
		if before.Release == next.Release && before.Reason == next.Reason {
			e.states[key] = before
			return false, nil
		}
		_, err = e.kv.Update(ctx, key, data, entry.Revision())
	}
	return err == nil, err
}

func (e *Events) storeFailure(ctx context.Context, err error) {
	key := e.key("apps", "event store")
	reason := releasefailure.At("event store", err).Error()
	if e.states[key].Reason == reason {
		return
	}
	event := observability.Event{Time: time.Now().UTC(), Level: "ERROR", Component: "apppull", Message: "app-pull event store failed",
		Attrs: map[string]string{"service": "apps", "region": e.region, "release": "release", "reason": reason, "node": e.node}}
	e.states[key] = notice{Stage: "event store", Release: "release", Reason: reason, Event: event}
	e.pending[key] = e.states[key]
	e.published[key] = event.Time
	e.bus.Publish(event)
	slog.InfoContext(ctx, event.Message, observability.ComponentKey, "apppull", "service", "apps", "region", e.region,
		"release", "release", "reason", reason, "outcome_level", "ERROR")
}

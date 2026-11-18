package releasegate

import (
	"errors"
	"io"
	"maps"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type Origin string

const (
	Leader   Origin = "leader"
	Receiver Origin = "receiver"
	Launch   Origin = "launch"
)

type blockKey struct {
	source Origin
	region string
}

type block struct {
	since time.Time
	code  string
}

var blocking = struct {
	sync.Mutex
	records map[blockKey]block
}{records: map[blockKey]block{}}

func RecordBlock(source Origin, region string, err error) {
	key := blockKey{source, region}
	blocking.Lock()
	defer blocking.Unlock()
	if err == nil {
		delete(blocking.records, key)
		return
	}
	held, found := blocking.records[key]
	if !found {
		held.since = time.Now()
	}
	held.code = GateUnreadable
	var refusal *Refusal
	if errors.As(err, &refusal) {
		held.code = refusal.Code
	}
	blocking.records[key] = held
}

func WriteBlockedMetrics(w io.Writer, source Origin) {
	blocking.Lock()
	records := maps.Clone(blocking.records)
	blocking.Unlock()
	for key, held := range records {
		if key.source != source {
			continue
		}
		observability.WriteGauge(w, observability.Series("ts_orch_release_staging_gate_blocked_seconds", "region", key.region, "reason", held.code, "source", string(source)), time.Since(held.since).Seconds())
	}
}

package decisionlog

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

const (
	// DefaultQueueSize bounds decisions waiting to be published.
	DefaultQueueSize = 1024
	// DefaultCapacity bounds the in-memory index of recent decisions.
	DefaultCapacity = 8192
	// DefaultPublishTimeout bounds one publish attempt.
	DefaultPublishTimeout = 3 * time.Second
	publishAttempts       = 3
	// maxArchiveScan bounds how many stored decisions one query reads from
	// the durable stream beyond the in-memory window.
	maxArchiveScan = 20000
	// archiveFirstWindow is the first archive window a query searches
	// back from the in-memory window.
	archiveFirstWindow = time.Hour
)

// Sink durably stores published decisions. Stream implements it.
type Sink interface {
	Publish(ctx context.Context, decision Decision) error
}

// Archive reads stored decisions older than the in-memory window. Stream
// implements it.
type Archive interface {
	// Scan visits stored decisions recorded at or after since, oldest
	// first, until visit returns false or maxScan records were read.
	// complete is false when the scan stopped at maxScan.
	Scan(ctx context.Context, since time.Time, maxScan int, visit func(Decision) bool) (complete bool, err error)
}

// Source is the read side the dashboard, insights and remote regions use.
// Journal and Federation implement it.
type Source interface {
	Query(ctx context.Context, query Query) (Result, error)
	Chain(ctx context.Context, id string) (Chain, error)
}

// LiveSource streams decisions as they are recorded or ingested.
type LiveSource interface {
	Subscribe(ctx context.Context, buffer int) <-chan Decision
}

// ErrNotFound reports a chain lookup for an unknown decision.
var ErrNotFound = errors.New("decision not found")

// ErrUnavailable reports that part of the journal (the durable archive or a
// linked region) could not be searched, so a lookup is neither found nor
// proven absent.
var ErrUnavailable = errors.New("decision journal unavailable")

// JournalConfig wires one member's journal.
type JournalConfig struct {
	// Region and Member fill Decision.Region and Actor.Member when a caller
	// leaves them empty.
	Region string
	Member string
	// QueueSize and Capacity default to DefaultQueueSize and
	// DefaultCapacity.
	QueueSize int
	Capacity  int
	// Sink and Archive are optional; without them the journal keeps only
	// its in-memory window. They are usually the same *Stream, and may be
	// attached later with Attach once the regional broker is open.
	Sink    Sink
	Archive Archive
	// Log also writes every recorded decision to the structured log, which
	// feeds the observability event bus.
	Log            bool
	PublishTimeout time.Duration
	Now            func() time.Time
}

// Journal is one member's decision recorder and regional index. Record never
// blocks: the decision is indexed in memory at once and queued for the
// background writer started by Run. Decisions recorded by other members of
// the region arrive through Ingest from the stream tail.
type Journal struct {
	config  JournalConfig
	queue   chan Decision
	storage atomic.Pointer[storageHolder]

	mu    sync.RWMutex
	ring  []Decision
	start int
	size  int
	// ids indexes the ring by decision ID. The value reports whether the
	// decision is known to be durable: published by this journal or read
	// back from the stream.
	ids         map[string]bool
	coveredFrom time.Time
	subscribers map[*subscriber]struct{}

	recorded  atomic.Uint64
	dropped   atomic.Uint64
	published atomic.Uint64
	failed    atomic.Uint64
	// replaying is set while the stream tail replays the stored history
	// into memory, so queries report the index as partial.
	replaying atomic.Bool
}

type storageHolder struct {
	sink    Sink
	archive Archive
}

type subscriber struct{ decisions chan Decision }

// NewJournal returns a journal over the given storage.
func NewJournal(config JournalConfig) *Journal {
	if config.QueueSize <= 0 {
		config.QueueSize = DefaultQueueSize
	}
	if config.Capacity <= 0 {
		config.Capacity = DefaultCapacity
	}
	if config.PublishTimeout <= 0 {
		config.PublishTimeout = DefaultPublishTimeout
	}
	if config.Now == nil {
		config.Now = time.Now
	}
	journal := &Journal{config: config, queue: make(chan Decision, config.QueueSize),
		ring: make([]Decision, config.Capacity), ids: map[string]bool{},
		subscribers: map[*subscriber]struct{}{}}
	journal.Attach(config.Sink, config.Archive)
	return journal
}

// Attach sets the durable sink and archive. Decisions recorded before a sink
// is attached stay queued (up to the queue bound) and are published once it
// is.
func (journal *Journal) Attach(sink Sink, archive Archive) {
	if sink == nil && archive == nil {
		return
	}
	journal.storage.Store(&storageHolder{sink: sink, archive: archive})
}

func (journal *Journal) currentStorage() (Sink, Archive) {
	if holder := journal.storage.Load(); holder != nil {
		return holder.sink, holder.archive
	}
	return nil, nil
}

// Record indexes the decision, queues it for publishing and returns its ID.
// A full queue drops the durable copy and counts it; the in-memory copy and
// the log line are kept.
func (journal *Journal) Record(ctx context.Context, decision Decision) string {
	if decision.Region == "" {
		decision.Region = journal.config.Region
	}
	if decision.Actor.Member == "" {
		decision.Actor.Member = journal.config.Member
	}
	decision = decision.Normalize(journal.config.Now())
	// A decision with a caller-chosen ID that is already indexed (an
	// idempotent replay) is indexed and logged once. Its durable copy is
	// queued again unless it is known to be stored, since the first attempt
	// may have been dropped from a full queue or failed to publish; the
	// stream deduplicates a copy that did land by its message ID.
	if fresh, durable := journal.ingest(decision, false); !fresh {
		if !durable {
			journal.enqueue(decision)
		}
		return decision.ID
	}
	journal.recorded.Add(1)
	recordedTotal.Inc()
	if journal.config.Log {
		LogRecorder{}.Record(ctx, decision)
	}
	journal.enqueue(decision)
	return decision.ID
}

func (journal *Journal) enqueue(decision Decision) {
	select {
	case journal.queue <- decision:
		queueDepth.Add(1)
	default:
		journal.dropped.Add(1)
		droppedQueueFull.Inc()
	}
}

// markDurable records that an indexed decision is stored in the stream.
func (journal *Journal) markDurable(id string) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if _, indexed := journal.ids[id]; indexed {
		journal.ids[id] = true
	}
}

// Run publishes queued decisions until ctx ends. A publish is retried a few
// times with the same message ID, so the stream deduplicates a retry whose
// first attempt was stored; a decision that still fails is dropped and
// counted.
func (journal *Journal) Run(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case decision := <-journal.queue:
			queueDepth.Add(-1)
			journal.publish(ctx, decision)
		}
	}
}

func (journal *Journal) publish(ctx context.Context, decision Decision) {
	backoff := 250 * time.Millisecond
	for attempt := 1; ; attempt++ {
		sink, _ := journal.currentStorage()
		if sink == nil {
			// No stream yet: wait for one without holding up shutdown.
			select {
			case <-ctx.Done():
				return
			case <-time.After(backoff):
			}
			backoff = min(backoff*2, 5*time.Second)
			attempt = 0
			continue
		}
		publishCtx, cancel := context.WithTimeout(ctx, journal.config.PublishTimeout)
		err := sink.Publish(publishCtx, decision)
		cancel()
		if err == nil {
			journal.published.Add(1)
			publishedTotal.Inc()
			journal.markDurable(decision.ID)
			return
		}
		if ctx.Err() != nil || attempt >= publishAttempts {
			journal.failed.Add(1)
			droppedPublish.Inc()
			return
		}
		publishRetries.Inc()
		select {
		case <-ctx.Done():
			journal.failed.Add(1)
			droppedPublish.Inc()
			return
		case <-time.After(backoff):
		}
		backoff *= 2
	}
}

// Ingest adds a decision read from the durable stream to the in-memory index
// and notifies subscribers. A decision already indexed is ignored, so the
// stream tail can replay what this member recorded itself. It reports whether
// the decision was new.
func (journal *Journal) Ingest(decision Decision) bool {
	fresh, _ := journal.ingest(decision, true)
	return fresh
}

// ingest indexes decision. durable marks it as stored in the stream. It
// reports whether the decision was new and whether it is known durable.
func (journal *Journal) ingest(decision Decision, durable bool) (bool, bool) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if known, seen := journal.ids[decision.ID]; seen {
		if durable && !known {
			journal.ids[decision.ID] = true
		}
		return false, known || durable
	}
	ingestedTotal.Inc()
	capacity := len(journal.ring)
	if journal.size == capacity {
		evicted := journal.ring[journal.start]
		delete(journal.ids, evicted.ID)
		if evicted.Time.After(journal.coveredFrom) {
			journal.coveredFrom = evicted.Time
		}
		journal.ring[journal.start] = decision
		journal.start = (journal.start + 1) % capacity
	} else {
		journal.ring[(journal.start+journal.size)%capacity] = decision
		journal.size++
	}
	journal.ids[decision.ID] = durable
	for subscriber := range journal.subscribers {
		select {
		case subscriber.decisions <- decision:
		default:
		}
	}
	return true, durable
}

// MarkCoveredFrom records that decisions older than at may exist in the
// archive but not in memory, for example after a bounded warm start.
func (journal *Journal) MarkCoveredFrom(at time.Time) {
	journal.mu.Lock()
	defer journal.mu.Unlock()
	if at.After(journal.coveredFrom) {
		journal.coveredFrom = at
	}
}

// snapshot returns the indexed decisions, unordered, and the time from which
// the index is complete.
func (journal *Journal) snapshot() ([]Decision, time.Time) {
	journal.mu.RLock()
	defer journal.mu.RUnlock()
	decisions := make([]Decision, 0, journal.size)
	for offset := range journal.size {
		decisions = append(decisions, journal.ring[(journal.start+offset)%len(journal.ring)])
	}
	return decisions, journal.coveredFrom
}

// Query returns matching decisions newest first. A range older than the
// in-memory window is read from the archive when one is attached, and
// reported Partial otherwise.
func (journal *Journal) Query(ctx context.Context, query Query) (Result, error) {
	query = query.Normalized()
	// The replay flag is read before the snapshot: a replay that ends in
	// between leaves the result conservatively partial, never the reverse.
	replaying := journal.replaying.Load()
	decisions, coveredFrom := journal.snapshot()
	result := Result{}
	seen := make(map[string]struct{}, len(decisions))
	// fresh counts matches newer than coveredFrom. Memory evicts by arrival,
	// not by time, so only those are known to outrank everything evicted.
	fresh := 0
	for _, decision := range decisions {
		if query.Matches(decision) {
			result.Decisions = append(result.Decisions, decision)
			seen[decision.ID] = struct{}{}
			if decision.Time.After(coveredFrom) {
				fresh++
			}
		}
	}
	// While the stream tail is still replaying, memory does not hold the
	// region's history yet.
	if replaying {
		result.Partial = true
	}
	// Older decisions only matter when memory did not fill the page with
	// decisions newer than anything it evicted.
	older := !coveredFrom.IsZero() && (query.Since.IsZero() || query.Since.Before(coveredFrom))
	exhausted := !older
	if older && fresh < query.Limit {
		_, archive := journal.currentStorage()
		if archive == nil {
			result.Partial = true
		} else if complete, reachedFloor := journal.scanArchive(ctx, archive, query, coveredFrom, seen, &result); !complete {
			result.Partial = true
		} else {
			exhausted = reachedFloor
		}
	}
	SortNewestFirst(result.Decisions)
	switch {
	case len(result.Decisions) > query.Limit:
		result.Decisions = result.Decisions[:query.Limit]
		result.Truncated = true
	case len(result.Decisions) == query.Limit && !exhausted:
		// A full page with older history left unsearched may not be all:
		// say so rather than look exhaustive.
		result.Truncated = true
	}
	return result, nil
}

// archiveClockSkew is how far past the in-memory coverage a record's own
// time may lie while older archived records still follow it: the stream is
// ordered by publication, records are timed by the recording controller's
// clock and published asynchronously.
const archiveClockSkew = 5 * time.Minute

// scanArchive adds matching archived decisions recorded at or before
// coveredFrom to result. The archive is read oldest first from a start time,
// so it is searched in windows reaching back from coveredFrom that widen
// fourfold until the page is full or the query's start (or the retention)
// is reached. A page is then the newest matches, not the oldest ones a
// single scan from the start would return when the range holds more than
// maxArchiveScan records. It reports whether the search was complete and
// whether it reached the query's start (so nothing older remains).
func (journal *Journal) scanArchive(ctx context.Context, archive Archive, query Query, coveredFrom time.Time,
	seen map[string]struct{}, result *Result,
) (complete, reachedFloor bool) {
	// The search reaches back from the earlier of coveredFrom and the
	// query's end, so a historical query does not spend its scan budget on
	// newer records that cannot match.
	upper := coveredFrom
	if !query.Until.IsZero() && query.Until.Before(upper) {
		upper = query.Until
	}
	floor := query.Since
	if floor.IsZero() {
		floor = upper.Add(-DefaultRetention)
	}
	if floor.After(upper) {
		return true, true
	}
	budget := maxArchiveScan
	for width := archiveFirstWindow; ; width *= 4 {
		since := upper.Add(-width)
		if !since.After(floor) {
			since = floor
		}
		scanned := 0
		complete, err := archive.Scan(ctx, since, budget, func(decision Decision) bool {
			// Memory is complete only after coveredFrom, and nothing after
			// upper matches. The archive is in publication order, so a
			// record timed after upper is skipped, not a stopping point,
			// until well past any clock skew.
			if decision.Time.After(upper) {
				return !decision.Time.After(upper.Add(archiveClockSkew))
			}
			scanned++
			if _, dup := seen[decision.ID]; !dup && query.Matches(decision) {
				seen[decision.ID] = struct{}{}
				result.Decisions = append(result.Decisions, decision)
			}
			return true
		})
		if err != nil || !complete {
			return false, false
		}
		if since.Equal(floor) {
			return true, true
		}
		if len(result.Decisions) >= query.Limit {
			return true, false
		}
		if budget -= max(scanned, 1); budget <= 0 {
			return false, false
		}
	}
}

// Chain returns the decision chain containing id. When the chain reaches
// before the in-memory window it is completed from the archive, starting at
// the time encoded in the root's ID.
func (journal *Journal) Chain(ctx context.Context, id string) (Chain, error) {
	// While the tail replays, later steps of an indexed chain (a completion
	// or a rollback) may still be pending, so every answer is partial.
	replaying := journal.replaying.Load()
	decisions, coveredFrom := journal.snapshot()
	chain, ok := BuildChain(decisions, id)
	needArchive := !ok || (!coveredFrom.IsZero() && !chain.Root.Time.After(coveredFrom)) ||
		(ok && chain.Root.ParentID != "")
	if !needArchive {
		chain.Partial = replaying
		return chain, nil
	}
	_, archive := journal.currentStorage()
	if archive == nil {
		if ok {
			// Part of the chain lies before memory and nothing can read it.
			chain.Partial = true
			return chain, nil
		}
		if replaying {
			return Chain{}, ErrUnavailable
		}
		return Chain{}, ErrNotFound
	}
	since, valid := IDTime(id)
	if ok {
		since = chain.Root.Time
		valid = true
	}
	retentionFloor := journal.config.Now().Add(-DefaultRetention)
	if !valid {
		// A caller-chosen ID (for example a managed update admission)
		// encodes no time: search the archive's whole retention.
		since = retentionFloor.Add(24 * time.Hour)
	}
	seen := make(map[string]struct{}, len(decisions))
	for _, decision := range decisions {
		seen[decision.ID] = struct{}{}
	}
	// A parent is recorded before its child; look back a little for roots
	// that the in-memory window no longer holds, then further back to the
	// time a missing parent's ID encodes, within retention.
	since = since.Add(-24 * time.Hour)
	partial := false
	for range 4 {
		complete, err := archive.Scan(ctx, since, maxArchiveScan, func(decision Decision) bool {
			if _, dup := seen[decision.ID]; !dup {
				seen[decision.ID] = struct{}{}
				decisions = append(decisions, decision)
			}
			return true
		})
		if err != nil || !complete {
			partial = true
			break
		}
		chain, ok = BuildChain(decisions, id)
		if !ok || chain.Root.ParentID == "" {
			break
		}
		parentTime, known := IDTime(chain.Root.ParentID)
		if !known {
			// The missing parent has a caller-chosen ID: widen to the
			// retention once.
			if !since.After(retentionFloor) {
				break
			}
			since = retentionFloor
			continue
		}
		if !parentTime.Before(since) || parentTime.Before(retentionFloor) {
			break
		}
		since = parentTime.Add(-time.Minute)
	}
	chain, ok = BuildChain(decisions, id)
	switch {
	case !ok && (partial || replaying):
		// The archive could not be read: not proof of absence.
		return Chain{}, ErrUnavailable
	case !ok:
		return Chain{}, ErrNotFound
	}
	chain.Partial = partial || replaying
	return chain, nil
}

// beginReplay marks the index as incomplete until the stream tail has
// caught up with what the stream held when it started.
func (journal *Journal) beginReplay() { journal.replaying.Store(true) }

// endReplay marks the index complete from its coverage boundary on.
func (journal *Journal) endReplay() { journal.replaying.Store(false) }

// Subscribe streams decisions indexed after the call until ctx ends. A
// subscriber that falls more than buffer decisions behind loses decisions.
func (journal *Journal) Subscribe(ctx context.Context, buffer int) <-chan Decision {
	if buffer <= 0 {
		buffer = 64
	}
	sub := &subscriber{decisions: make(chan Decision, buffer)}
	journal.mu.Lock()
	journal.subscribers[sub] = struct{}{}
	journal.mu.Unlock()
	context.AfterFunc(ctx, func() {
		journal.mu.Lock()
		delete(journal.subscribers, sub)
		journal.mu.Unlock()
		close(sub.decisions)
	})
	return sub.decisions
}

// Stats is the journal's cumulative counters.
type Stats struct {
	Recorded      uint64 `json:"recorded"`
	Published     uint64 `json:"published"`
	DroppedQueue  uint64 `json:"dropped_queue"`
	PublishFailed uint64 `json:"publish_failed"`
	Indexed       int    `json:"indexed"`
	Queued        int    `json:"queued"`
}

// Stats returns cumulative counters and current sizes.
func (journal *Journal) Stats() Stats {
	journal.mu.RLock()
	indexed := journal.size
	journal.mu.RUnlock()
	return Stats{Recorded: journal.recorded.Load(), Published: journal.published.Load(),
		DroppedQueue: journal.dropped.Load(), PublishFailed: journal.failed.Load(), Indexed: indexed,
		Queued: len(journal.queue)}
}

// IDTime returns the record time encoded in a decision ID made by NewID.
func IDTime(id string) (time.Time, bool) {
	parsed, err := entityid.Parse(id)
	if err != nil || parsed.Time() == 0 {
		return time.Time{}, false
	}
	return time.UnixMilli(int64(parsed.Time())).UTC(), true
}

var (
	_ Recorder   = (*Journal)(nil)
	_ Source     = (*Journal)(nil)
	_ LiveSource = (*Journal)(nil)
)

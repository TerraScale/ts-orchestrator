package rollout

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats.go/jetstream"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/release"
)

// The cell's desired orchestrator release lives in the rollout bucket: one
// record holding the newest generation, written by CAS, plus a retained copy
// of every generation for rollback. The leader's executor derives its program
// from the record; nothing about the release is baked.
//
// ponytail: the minimum the executor needs until the cell spec (TS-556) and
// the KV store (TS-559) own the schema; move it there keeping these rules.
const (
	desiredKey = "release.desired"
	// ReleaseHistory is how many generations stay readable for rollback.
	ReleaseHistory = 64
	maxReleaseWire = 64 << 10
)

var (
	ErrReleaseUnchanged = errors.New("the desired release already names this binary")
	ErrNoRelease        = errors.New("the cell has no such release generation")
)

func generationKey(generation uint64) string {
	return "release.gen." + strconv.FormatUint(generation, 10)
}

// Release is one generation of the cell's desired orchestrator binary.
// Receipt and Delegation are the release receipt the steps carry, so a node
// can restage the binary; nodes verify them against their own roots.
// SourceRevision and RunNumber are what the verified receipt names (the run
// only for an update receipt signed after CI qualified it), so a release
// channel can refuse a run older than the cell's newest. RollbackOf names
// the earlier generation a rollback repeats.
type Release struct {
	Generation     uint64    `json:"generation"`
	Digest         string    `json:"digest"`
	SourceRevision string    `json:"source_revision,omitempty"`
	RunNumber      int64     `json:"run_number,omitzero"`
	Receipt        []byte    `json:"receipt,omitempty"`
	Delegation     []byte    `json:"delegation,omitempty"`
	RollbackOf     uint64    `json:"rollback_of,omitzero"`
	Actor          string    `json:"actor"`
	CreatedAt      time.Time `json:"created_at"`
}

func (r Release) validate() error {
	if r.Generation == 0 || !digestRE.MatchString(r.Digest) || r.RunNumber < 0 ||
		r.SourceRevision != "" && !release.ValidSourceRevision(r.SourceRevision) ||
		len(r.Receipt) > maxReleaseWire || len(r.Delegation) > maxReleaseWire ||
		len(r.Delegation) > 0 && len(r.Receipt) == 0 || r.RollbackOf >= r.Generation ||
		!tokenRE.MatchString(r.Actor) || r.CreatedAt.IsZero() {
		return fmt.Errorf("%w: release generation", ErrInvalid)
	}
	return nil
}

// Desired is the cell's newest release generation. Paused stops the executor
// from starting another rollout; a rollout already running still finishes.
type Desired struct {
	SchemaVersion int     `json:"schema_version"`
	Cell          string  `json:"cell"`
	Release       Release `json:"release,omitzero"`
	Paused        bool    `json:"paused,omitzero"`
}

// Generation is the newest generation, zero before the first release.
func (d Desired) Generation() uint64 { return d.Release.Generation }

func (d Desired) validate(cell string) error {
	if d.SchemaVersion != SchemaVersion || d.Cell != cell {
		return fmt.Errorf("%w: desired release", ErrInvalid)
	}
	if d.Release.Generation != 0 {
		return d.Release.validate()
	}
	return nil
}

// Desired returns the record and its revision (zero when absent).
func (s *Store) Desired(ctx context.Context) (Desired, uint64, error) {
	entry, err := s.kv.Get(ctx, desiredKey)
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Desired{SchemaVersion: SchemaVersion, Cell: s.cell}, 0, nil
	}
	if err != nil {
		return Desired{}, 0, err
	}
	var desired Desired
	if err := protocol.DecodeTolerant(entry.Value(), &desired, maxRecordBytes); err != nil {
		return Desired{}, 0, err
	}
	if err := desired.validate(s.cell); err != nil {
		return Desired{}, 0, err
	}
	return desired, entry.Revision(), nil
}

// ReleaseGeneration returns one retained generation.
func (s *Store) ReleaseGeneration(ctx context.Context, generation uint64) (Release, error) {
	desired, _, err := s.Desired(ctx)
	if err != nil {
		return Release{}, err
	}
	return s.generation(ctx, desired, generation)
}

// generation reads a retained copy. The copy has no schema version of its
// own: the desired record's, which every caller has validated, covers it. A
// breaking Release change raises SchemaVersion, so an older controller
// refuses the desired record and never reads a newer generation it would
// misread; a newer binary's added members are skipped, as in the desired
// record itself.
func (s *Store) generation(ctx context.Context, desired Desired, generation uint64) (Release, error) {
	if generation != 0 && generation == desired.Generation() {
		return desired.Release, nil
	}
	if generation == 0 || generation > desired.Generation() {
		return Release{}, fmt.Errorf("%w: %d", ErrNoRelease, generation)
	}
	entry, err := s.kv.Get(ctx, generationKey(generation))
	if errors.Is(err, jetstream.ErrKeyNotFound) {
		return Release{}, fmt.Errorf("%w: %d is no longer retained", ErrNoRelease, generation)
	}
	if err != nil {
		return Release{}, err
	}
	var release Release
	if err := protocol.DecodeTolerant(entry.Value(), &release, maxRecordBytes); err != nil {
		return Release{}, err
	}
	if err := release.validate(); err != nil || release.Generation != generation {
		return Release{}, fmt.Errorf("%w: stored generation %d", ErrInvalid, generation)
	}
	return release, nil
}

// PublishRelease makes release the next generation, fenced by epoch, and
// returns it. A release that repeats the newest generation's binary changes
// nothing and returns ErrReleaseUnchanged. A digest known bad in this cell is
// refused.
func (s *Store) PublishRelease(ctx context.Context, epoch uint64, release Release) (Release, error) {
	if bad, err := s.IsKnownBad(ctx, release.Digest); err != nil {
		return Release{}, err
	} else if bad {
		return Release{}, ErrKnownBad
	}
	for range cellCASAttempts {
		desired, revision, err := s.Desired(ctx)
		if err != nil {
			return Release{}, err
		}
		if desired.Generation() > 0 && desired.Release.Digest == release.Digest {
			return desired.Release, ErrReleaseUnchanged
		}
		next := desired
		next.Release = release
		next.Release.Generation = desired.Generation() + 1
		next.Release.CreatedAt = release.CreatedAt.UTC()
		if err := next.validate(s.cell); err != nil {
			return Release{}, err
		}
		// The generation being replaced is retained before the record
		// moves; a copy lost to a crash is written again by the next
		// publish, since the record still holds it.
		if desired.Generation() > 0 {
			if err := s.retain(ctx, epoch, desired.Release); err != nil {
				return Release{}, err
			}
		}
		if err := s.writeDesired(ctx, epoch, next, revision); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return Release{}, err
		}
		if newest := next.Generation(); newest > ReleaseHistory && s.fencer.Guard(ctx, epoch) == nil {
			// Best effort: a missed purge only keeps one more old copy.
			_ = s.kv.Purge(ctx, generationKey(newest-ReleaseHistory))
		}
		return next.Release, nil
	}
	return Release{}, ErrConflict
}

func (s *Store) retain(ctx context.Context, epoch uint64, release Release) error {
	encoded, err := protocol.EncodeJSON(release)
	if err != nil {
		return err
	}
	if err := s.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	if _, err := s.kv.Put(ctx, generationKey(release.Generation), encoded); err != nil {
		return fmt.Errorf("retain release generation: %w", err)
	}
	return nil
}

// RollbackRelease publishes a new generation that repeats generation to.
// History is never rewritten: a rollback is itself a generation, so a later
// one can roll it back again.
func (s *Store) RollbackRelease(ctx context.Context, epoch, to uint64, actor string, now time.Time) (Release, error) {
	desired, _, err := s.Desired(ctx)
	if err != nil {
		return Release{}, err
	}
	if to == 0 || to >= desired.Generation() {
		return Release{}, fmt.Errorf("%w: roll back to a generation before %d", ErrInvalid, desired.Generation())
	}
	target, err := s.generation(ctx, desired, to)
	if err != nil {
		return Release{}, err
	}
	repeat := target
	repeat.RollbackOf, repeat.Actor, repeat.CreatedAt = to, actor, now
	return s.PublishRelease(ctx, epoch, repeat)
}

// PauseReleases sets the cell's pause, fenced by epoch.
func (s *Store) PauseReleases(ctx context.Context, epoch uint64, paused bool) (Desired, error) {
	for range cellCASAttempts {
		desired, revision, err := s.Desired(ctx)
		if err != nil {
			return Desired{}, err
		}
		if desired.Paused == paused {
			return desired, nil
		}
		desired.Paused = paused
		if err := s.writeDesired(ctx, epoch, desired, revision); errors.Is(err, ErrConflict) {
			continue
		} else if err != nil {
			return Desired{}, err
		}
		return desired, nil
	}
	return Desired{}, ErrConflict
}

func (s *Store) writeDesired(ctx context.Context, epoch uint64, desired Desired, revision uint64) error {
	if err := desired.validate(s.cell); err != nil {
		return err
	}
	encoded, err := protocol.EncodeJSON(desired)
	if err != nil {
		return err
	}
	if err := s.fencer.Guard(ctx, epoch); err != nil {
		return err
	}
	if revision == 0 {
		_, err = s.kv.Create(ctx, desiredKey, encoded)
	} else {
		_, err = s.kv.Update(ctx, desiredKey, encoded, revision)
	}
	if errors.Is(err, jetstream.ErrKeyRevisionMismatch) || errors.Is(err, jetstream.ErrKeyExists) {
		return ErrConflict
	}
	return err
}

// Receipt returns the release receipt of digest from the newest retained
// generation that names it, so a step carries what a node needs to restage
// it. A digest no generation names (the image's baked binary) has none;
// nodes never prune their baked release.
func (s *Store) Receipt(ctx context.Context, digest string) (receipt, delegation []byte, err error) {
	desired, _, err := s.Desired(ctx)
	if err != nil {
		return nil, nil, err
	}
	newest := desired.Generation()
	for generation := newest; generation > 0 && newest-generation < ReleaseHistory; generation-- {
		release, err := s.generation(ctx, desired, generation)
		if errors.Is(err, ErrNoRelease) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		if release.Digest == digest {
			return release.Receipt, release.Delegation, nil
		}
	}
	return nil, nil, nil
}

// Releases returns up to limit retained generations, newest first.
func (s *Store) Releases(ctx context.Context, limit int) ([]Release, error) {
	desired, _, err := s.Desired(ctx)
	if err != nil {
		return nil, err
	}
	var releases []Release
	newest := desired.Generation()
	for generation := newest; generation > 0 && len(releases) < limit && newest-generation < ReleaseHistory; generation-- {
		release, err := s.generation(ctx, desired, generation)
		if errors.Is(err, ErrNoRelease) {
			continue
		}
		if err != nil {
			return nil, err
		}
		releases = append(releases, release)
	}
	return releases, nil
}

// ReleasePins returns every retained rollback generation and every durable
// known-bad digest, including entries aged out of the bounded cell list.
func (s *Store) ReleasePins(ctx context.Context) (rollback, knownBad []string, err error) {
	history, err := s.Releases(ctx, ReleaseHistory)
	if err != nil {
		return nil, nil, err
	}
	for _, release := range history {
		rollback = append(rollback, release.Digest)
	}
	state, _, err := s.Cell(ctx)
	if err != nil {
		return nil, nil, err
	}
	knownBad = slices.Clone(state.KnownBad)
	lister, err := s.kv.ListKeysFiltered(ctx, "knownbad.*")
	if err != nil && !errors.Is(err, jetstream.ErrNoKeysFound) {
		return nil, nil, err
	}
	if err == nil {
		defer lister.Stop()
		for key := range lister.Keys() {
			digest := strings.TrimPrefix(key, "knownbad.")
			if !digestRE.MatchString(digest) {
				return nil, nil, fmt.Errorf("%w: known-bad key %q", ErrInvalid, key)
			}
			knownBad = append(knownBad, digest)
		}
	}
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	// A rollout's predecessor may predate the retained generation window,
	// or be the image's baked binary, which has no generation of its own.
	if state.ActiveRolloutID != "" {
		record, _, err := s.Load(ctx, state.ActiveRolloutID)
		if err != nil {
			return nil, nil, err
		}
		rollback = append(rollback, record.FromDigest)
		knownBad = append(knownBad, record.KnownBad...)
	}
	slices.Sort(rollback)
	slices.Sort(knownBad)
	return slices.Compact(rollback), slices.Compact(knownBad), nil
}

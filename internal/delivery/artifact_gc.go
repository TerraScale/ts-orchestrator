package delivery

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/artifact"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	nats "github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const (
	// artifactGCGrace keeps an artifact whose metadata was written this
	// recently: uploaded, admitted or named by a desired (each touches it),
	// so a release between its upload and its first desired write keeps it.
	artifactGCGrace = time.Hour
	// orphanChunkGrace purges chunks no object references only once they sit
	// idle past any live upload: every upload ends within
	// artifactUploadTimeout of its start.
	orphanChunkGrace = artifactUploadTimeout + 5*time.Minute

	artifactMetaPrefix  = "$O." + ArtifactBucket + ".M."
	artifactChunkPrefix = "$O." + ArtifactBucket + ".C."
)

// ArtifactUse is an artifact a committed desired names. The collector never
// deletes it.
type ArtifactUse struct {
	Digest      string
	Role        string
	Environment string
}

// ArtifactCollection is what one collection pass removed.
type ArtifactCollection struct {
	Deleted []string `json:"deleted,omitempty"`
	Purged  []string `json:"purged,omitempty"`
}

type admittedArtifact struct {
	digest string
	at     time.Time
}

type releasedArtifact struct {
	digest     string
	generation uint64
}

// CollectArtifacts deletes the stored artifacts no host needs and purges the
// chunks of failed uploads. It keeps every artifact inUse names and every
// one an undecided delivery names; per role and environment it keeps the
// rollback target, the newest delivered digest not in use, and a role no
// delivery released keeps its two newest admissions. Anything whose
// metadata was written within artifactGCGrace stays too.
//
// The metadata is read before the references, and each deletion is a
// compare-and-set on the metadata it read: a desired commit or admission
// touches the object first (artifact.Touch), so a reference made after the
// read refuses the deletion however late it lands. guard runs before each
// effect.
func (s *Service) CollectArtifacts(ctx context.Context, inUse func(context.Context) ([]ArtifactUse, error), now time.Time,
	guard func(context.Context) error,
) (ArtifactCollection, error) {
	var collection ArtifactCollection
	if s == nil || s.config.Conn == nil || inUse == nil || guard == nil {
		return collection, errors.New("artifact collection requires the controller's NATS connection, references and guard")
	}
	legacy, err := s.config.Conn.JetStream()
	if err != nil {
		return collection, err
	}
	stream := "OBJ_" + ArtifactBucket
	metas, err := lastMessages(ctx, s.js, legacy, stream, artifactMetaPrefix+">")
	if err != nil {
		return collection, err
	}
	uses, err := inUse(ctx)
	if err != nil {
		return collection, err
	}
	keep, err := s.retainedArtifacts(ctx, legacy, uses)
	if err != nil {
		return collection, err
	}
	live := map[string]bool{}
	var garbage []*nats.RawStreamMsg
	for _, message := range metas {
		var info jetstream.ObjectInfo
		if err := json.Unmarshal(message.Data, &info); err != nil {
			return collection, fmt.Errorf("decode artifact metadata %s: %w", message.Subject, err)
		}
		if info.Deleted {
			continue
		}
		live[info.NUID] = true
		digest, ok := strings.CutPrefix(info.Name, "sha256-")
		if ok && sha256RE.MatchString(digest) && !keep[digest] && now.Sub(message.Time) >= artifactGCGrace {
			garbage = append(garbage, message)
		}
	}
	chunks, err := s.js.Stream(ctx, stream)
	if err != nil {
		return collection, err
	}
	info, err := chunks.Info(ctx, jetstream.WithSubjectFilter(artifactChunkPrefix+">"))
	if err != nil {
		return collection, err
	}
	var orphans []string
	for _, subject := range slices.Sorted(maps.Keys(info.State.Subjects)) {
		if live[strings.TrimPrefix(subject, artifactChunkPrefix)] {
			continue
		}
		last, err := legacy.GetLastMsg(stream, subject, nats.Context(ctx))
		if errors.Is(err, nats.ErrMsgNotFound) {
			continue
		}
		if err != nil {
			return collection, fmt.Errorf("inspect artifact chunks %s: %w", subject, err)
		}
		if now.Sub(last.Time) >= orphanChunkGrace {
			orphans = append(orphans, subject)
		}
	}
	for _, meta := range garbage {
		if err := guard(ctx); err != nil {
			return collection, err
		}
		err := artifact.DeleteIfUnchanged(ctx, legacy, ArtifactBucket, meta)
		if errors.Is(err, artifact.ErrChanged) {
			continue
		}
		digest := strings.TrimPrefix(objectName(meta), "sha256-")
		if err != nil {
			return collection, fmt.Errorf("delete artifact %s: %w", digest, err)
		}
		collection.Deleted = append(collection.Deleted, digest)
	}
	for _, subject := range orphans {
		if err := guard(ctx); err != nil {
			return collection, err
		}
		if err := chunks.Purge(ctx, jetstream.WithPurgeSubject(subject)); err != nil {
			return collection, fmt.Errorf("purge artifact chunks %s: %w", subject, err)
		}
		collection.Purged = append(collection.Purged, subject)
	}
	return collection, nil
}

func objectName(meta *nats.RawStreamMsg) string {
	var info jetstream.ObjectInfo
	_ = json.Unmarshal(meta.Data, &info)
	return info.Name
}

// retainedArtifacts is the keep set of CollectArtifacts.
func (s *Service) retainedArtifacts(ctx context.Context, legacy nats.JetStreamContext, inUse []ArtifactUse) (map[string]bool, error) {
	type group struct{ role, environment string }
	keep := map[string]bool{}
	used := map[group]map[string]bool{}
	for _, use := range inUse {
		keep[use.Digest] = true
		g := group{use.Role, use.Environment}
		if used[g] == nil {
			used[g] = map[string]bool{}
		}
		used[g][use.Digest] = true
	}
	// Deliveries are the role's release history: each names the digest it
	// made desired, so the newest one not in use is what a rollback returns
	// to.
	operations, err := lastMessages(ctx, s.js, legacy, "KV_"+OperationBucket, "$KV."+OperationBucket+".>")
	if err != nil {
		return nil, err
	}
	byIntent := map[Intent]operation{}
	for _, message := range operations {
		var op operation
		if len(message.Data) == 0 || message.Header.Get("KV-Operation") != "" || json.Unmarshal(message.Data, &op) != nil {
			continue
		}
		i := op.Intent
		if i.Cell != s.config.Cell || i.Container != nil {
			continue
		}
		// An exact durable decision supersedes its preparation copy; retain every distinct intent.
		previous, ok := byIntent[i]
		if ok && previous.Receipt != nil && (op.Receipt == nil || previous.Receipt.Status != "rejected") {
			continue
		}
		byIntent[i] = op
	}
	released := map[group][]releasedArtifact{}
	for i, op := range byIntent {
		switch {
		case op.Receipt == nil:
			keep[i.ArtifactDigest] = true
		case op.Receipt.Status != "rejected":
			g := group{i.Role, i.Environment}
			released[g] = append(released[g], releasedArtifact{digest: i.ArtifactDigest, generation: i.Generation})
		}
	}
	for g, history := range released {
		slices.SortFunc(history, func(a, b releasedArtifact) int { return cmp.Compare(b.generation, a.generation) })
		want := 1
		if len(used[g]) == 0 {
			want = 2
		}
		seen := map[string]bool{}
		for _, r := range history {
			if used[g][r.digest] || seen[r.digest] {
				continue
			}
			seen[r.digest] = true
			keep[r.digest] = true
			if len(seen) == want {
				break
			}
		}
	}
	admissions, err := lastMessages(ctx, s.js, legacy, "KV_"+AdmissionBucket, "$KV."+AdmissionBucket+".>")
	if err != nil {
		return nil, err
	}
	admitted := map[group][]admittedArtifact{}
	for _, message := range admissions {
		if len(message.Data) == 0 || message.Header.Get("KV-Operation") != "" {
			continue
		}
		// Only the controller writes admissions; a record it cannot read
		// admits nothing, so it protects nothing either.
		var signed signedAdmission
		if protocol.DecodeStrict(message.Data, &signed, MaxArtifactClaimBytes+4096) != nil || signed.Record.Cell != s.config.Cell {
			continue
		}
		g := group{signed.Record.Role, signed.Record.Environment}
		admitted[g] = append(admitted[g], admittedArtifact{digest: signed.Record.Digest, at: message.Time})
	}
	for g, list := range admitted {
		if len(released[g]) != 0 || len(used[g]) != 0 {
			continue
		}
		slices.SortFunc(list, func(a, b admittedArtifact) int {
			return cmp.Or(b.at.Compare(a.at), strings.Compare(a.digest, b.digest))
		})
		for _, a := range list[:min(2, len(list))] {
			keep[a.digest] = true
		}
	}
	return keep, nil
}

// lastMessages reads the newest message of every subject of stream under
// filter from the stream leader.
func lastMessages(ctx context.Context, js jetstream.JetStream, legacy nats.JetStreamContext, name, filter string) ([]*nats.RawStreamMsg, error) {
	stream, err := js.Stream(ctx, name)
	if err != nil {
		return nil, err
	}
	info, err := stream.Info(ctx, jetstream.WithSubjectFilter(filter))
	if err != nil {
		return nil, err
	}
	messages := make([]*nats.RawStreamMsg, 0, len(info.State.Subjects))
	for _, subject := range slices.Sorted(maps.Keys(info.State.Subjects)) {
		message, err := legacy.GetLastMsg(name, subject, nats.Context(ctx))
		if errors.Is(err, nats.ErrMsgNotFound) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", subject, err)
		}
		messages = append(messages, message)
	}
	return messages, nil
}

// ArtifactStoreSize is the store's byte quota and the bytes it holds.
func (s *Service) ArtifactStoreSize(ctx context.Context) (maxBytes int64, usedBytes uint64, err error) {
	stream, err := s.js.Stream(ctx, "OBJ_"+ArtifactBucket)
	if err != nil {
		return 0, 0, err
	}
	info, err := stream.Info(ctx)
	if err != nil {
		return 0, 0, err
	}
	return info.Config.MaxBytes, info.State.Bytes, nil
}

// ResizeArtifactStore sets the store's byte quota. Discard-new never drops
// stored chunks: a quota below the bytes held only refuses new uploads.
func (s *Service) ResizeArtifactStore(ctx context.Context, maxBytes int64) error {
	if maxBytes <= 0 {
		return fmt.Errorf("%w: artifact store quota", ErrInvalid)
	}
	_, err := s.js.CreateOrUpdateObjectStore(ctx, artifactStoreConfig(s.config.Replicas, maxBytes))
	return err
}

func artifactStoreConfig(replicas int, maxBytes int64) jetstream.ObjectStoreConfig {
	return jetstream.ObjectStoreConfig{Bucket: ArtifactBucket, Storage: jetstream.FileStorage, Replicas: replicas, MaxBytes: maxBytes}
}

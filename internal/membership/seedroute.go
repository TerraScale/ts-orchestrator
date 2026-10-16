package membership

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"github.com/TerraScale/ts-orchestrator/internal/decisionlog"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

// Seed routing lets any authority leader drive a controller slot
// replacement, although only the seed holds the founder signer that can
// launch the successor (findings 11701 and 11995).
//
// The leader still makes the whole decision: Decide runs on the leader, and
// the request carries the leader's term (epoch, candidate and owner process)
// and the exact root-signed retirement envelope. The seed is an executor
// only. It accepts a request solely while the durable R3 lease names exactly
// that term, re-checks that same lease immediately before every durable and
// OCI mutation of the replacement, and cancels the replacement as soon as
// the term ends. The seed re-observes that the pinned prior instance is
// TERMINATED, and its founder verifies the retirement root signature and the
// exact prior ledger attempt before any HEAD change, so a forged or stale
// request can at most cost liveness. It runs one replacement at a time.

// SeedReplaceRequestVersion is the only accepted request schema.
const SeedReplaceRequestVersion = 1

// maxSeedRequestBytes bounds one request: a 64 KiB retirement envelope,
// base64 encoded inside JSON, plus the small routing fields.
const maxSeedRequestBytes = 128 << 10

// SeedReplaceRequest is one leader-to-seed replacement request.
type SeedReplaceRequest struct {
	Version           int    `json:"version"`
	Cell              string `json:"cell"`
	Slot              string `json:"slot"`
	PreviousAttempt   uint64 `json:"previous_attempt"`
	PriorInstanceOCID string `json:"prior_instance_ocid"`
	Retirement        []byte `json:"retirement"`
	Epoch             uint64 `json:"epoch"`
	CandidateID       string `json:"candidate_id"`
	OwnerID           string `json:"owner_id"`
}

// Seed reply states.
const (
	SeedAccepted   = "accepted"
	SeedInProgress = "in_progress"
	SeedDone       = "done"
	SeedFailed     = "failed"
	SeedRefused    = "refused"
)

// SeedReplaceReply is the seed's answer. Accepted, in-progress and done all
// mean the replacement is (or was) executing for this exact request; the
// leader keeps following the ledger until the successor completes.
type SeedReplaceReply struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

// ErrSeedRefused wraps a seed refusal so the leader backs off.
var ErrSeedRefused = errors.New("seed refused the controller slot replacement request")

func (request SeedReplaceRequest) key() string {
	sum := sha256.Sum256(request.Retirement)
	return fmt.Sprintf("%s/%d/%s", request.Slot, request.PreviousAttempt, hex.EncodeToString(sum[:]))
}

func (request SeedReplaceRequest) sameTerm(other SeedReplaceRequest) bool {
	return request.Epoch == other.Epoch && request.CandidateID == other.CandidateID &&
		request.OwnerID == other.OwnerID
}

func (request SeedReplaceRequest) validate(topology Topology) error {
	if request.Version != SeedReplaceRequestVersion || request.Cell != topology.Cell {
		return errors.New("request is for another schema or cell")
	}
	if !slices.Contains(topology.Slots, request.Slot) || request.Slot == topology.SeedSlot ||
		request.Slot == topology.SelfSlot {
		return errors.New("request names no replaceable non-seed peer slot")
	}
	if request.PreviousAttempt == 0 || request.PriorInstanceOCID == "" || len(request.Retirement) == 0 ||
		len(request.Retirement) > maxEvidenceBytes {
		return errors.New("request lacks the exact prior attempt or a bounded retirement envelope")
	}
	if request.Epoch == 0 || request.CandidateID == "" || request.OwnerID == "" ||
		len(request.CandidateID) > 128 || len(request.OwnerID) > 128 {
		return errors.New("request lacks the leader's authority term")
	}
	// The envelope is decoded only to route it, exactly like evidence on
	// disk; the founder verifies its root signature against the ledger.
	retirement, err := bootstrap.DecodeSlotRetirementCandidate(request.Retirement)
	if err != nil || retirement.Slot != request.Slot || retirement.PreviousAttempt != request.PreviousAttempt ||
		retirement.PriorInstanceOCID != request.PriorInstanceOCID {
		return errors.New("retirement envelope does not name the requested slot attempt and instance")
	}
	return nil
}

// LeaseVerifier is the read-only foreign-term fence: it succeeds only while
// the durable lease is held by exactly this candidate and owner at epoch.
type LeaseVerifier interface {
	VerifyLeaseHolder(ctx context.Context, epoch uint64, candidateID, ownerID string) error
}

// SeedRequester sends one encoded request to the seed and returns its reply.
type SeedRequester func(ctx context.Context, payload []byte) ([]byte, error)

// seedRequestTimeout stays under the controller credential's five-second
// response grant.
const seedRequestTimeout = 4 * time.Second

// SeedRoutedReplacer is the Replacer of a non-seed controller. It asks the
// seed to execute an action this controller's term decided.
type SeedRoutedReplacer struct {
	Cell       string
	Leadership Leadership
	Request    SeedRequester
}

func (replacer SeedRoutedReplacer) Replace(ctx context.Context, action Action) error {
	if replacer.Request == nil || replacer.Leadership == nil {
		return ErrReplacerUnavailable
	}
	snapshot := replacer.Leadership.Current()
	if !snapshot.CanMutate() || action.Epoch == 0 || snapshot.Epoch != action.Epoch {
		return errors.New("controller authority term ended before routing the replacement to the seed")
	}
	// Renew the lease first, so the seed's read-only check sees a fresh
	// record for this exact term.
	if action.Fence != nil {
		if err := action.Fence(ctx); err != nil {
			return fmt.Errorf("authority fence: %w", err)
		}
	}
	payload, err := protocol.EncodeJSON(SeedReplaceRequest{Version: SeedReplaceRequestVersion, Cell: replacer.Cell,
		Slot: action.Slot, PreviousAttempt: action.PreviousAttempt, PriorInstanceOCID: action.PriorInstanceOCID,
		Retirement: action.Retirement.Wire, Epoch: action.Epoch, CandidateID: snapshot.CandidateID,
		OwnerID: snapshot.OwnerID})
	if err != nil {
		return err
	}
	requestCtx, cancel := context.WithTimeout(ctx, seedRequestTimeout)
	defer cancel()
	wire, err := replacer.Request(requestCtx, payload)
	if err != nil {
		return fmt.Errorf("route replacement to the seed controller: %w", err)
	}
	var reply SeedReplaceReply
	if err := protocol.DecodeStrict(wire, &reply, 4<<10); err != nil {
		return fmt.Errorf("decode seed replacement reply: %w", err)
	}
	switch reply.Status {
	case SeedAccepted, SeedInProgress, SeedDone:
		return nil
	case SeedFailed:
		return fmt.Errorf("seed replacement failed: %s", reply.Error)
	case SeedRefused:
		return fmt.Errorf("%w: %s", ErrSeedRefused, reply.Error)
	}
	return fmt.Errorf("seed replacement reply has unknown status %q", reply.Status)
}

// SeedServerDependencies wires a SeedServer.
type SeedServerDependencies struct {
	Leases    LeaseVerifier
	Instances InstanceSource
	// Replacer is the seed's local founder replacer. It is shared with the
	// seed's own reconciler and must serialize its callers.
	Replacer Replacer
	Logger   *slog.Logger
}

// SeedServer executes leader-decided slot replacements on the seed.
type SeedServer struct {
	topology Topology
	deps     SeedServerDependencies
	base     context.Context
	stop     context.CancelFunc
	jobs     sync.WaitGroup
	mu       sync.Mutex
	job      *seedJob
}

type seedJob struct {
	key     string
	request SeedReplaceRequest
	running bool
	err     error
}

// seedFencePoll is how often a running routed replacement rechecks that the
// requesting term still holds the lease.
var seedFencePoll = 2 * time.Second

// NewSeedServer returns a server for the seed controller of topology. Its
// replacements run under ctx; Close cancels and joins them.
func NewSeedServer(ctx context.Context, topology Topology, deps SeedServerDependencies) (*SeedServer, error) {
	if err := topology.Validate(); err != nil {
		return nil, err
	}
	if topology.SelfSlot != topology.SeedSlot {
		return nil, errors.New("only the seed controller serves slot replacement requests")
	}
	if deps.Leases == nil || deps.Instances == nil || deps.Replacer == nil {
		return nil, errors.New("seed replacement server dependencies are incomplete")
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	base, stop := context.WithCancel(context.WithoutCancel(ctx))
	server := &SeedServer{topology: topology, deps: deps, base: base, stop: stop}
	context.AfterFunc(ctx, stop)
	return server, nil
}

// Close cancels any running replacement and waits for it, so no founder OCI
// call outlives the controller.
func (s *SeedServer) Close() {
	// Stopping under the lock orders every job start before the wait.
	s.mu.Lock()
	s.stop()
	s.mu.Unlock()
	s.jobs.Wait()
}

// Handle answers one encoded request. It never blocks on the replacement
// itself: an accepted request runs in the background and later requests for
// the same retirement report its progress.
func (s *SeedServer) Handle(ctx context.Context, payload []byte) SeedReplaceReply {
	refuse := func(err error) SeedReplaceReply {
		s.deps.Logger.Warn("seed refused a controller slot replacement request", "error", err)
		return SeedReplaceReply{Status: SeedRefused, Error: err.Error()}
	}
	if s.base.Err() != nil {
		return refuse(errors.New("seed controller is stopping"))
	}
	var request SeedReplaceRequest
	if len(payload) == 0 || len(payload) > maxSeedRequestBytes {
		return refuse(errors.New("request size is out of bounds"))
	}
	if err := protocol.DecodeStrict(payload, &request, maxSeedRequestBytes); err != nil {
		return refuse(errors.New("request is not a strict replacement request"))
	}
	if err := request.validate(s.topology); err != nil {
		return refuse(err)
	}
	if err := s.deps.Leases.VerifyLeaseHolder(ctx, request.Epoch, request.CandidateID, request.OwnerID); err != nil {
		return refuse(fmt.Errorf("requesting controller does not hold authority epoch %d: %w", request.Epoch, err))
	}
	key := request.key()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.base.Err() != nil {
		return refuse(errors.New("seed controller is stopping"))
	}
	if job := s.job; job != nil {
		switch {
		case job.key == key && job.running:
			return SeedReplaceReply{Status: SeedInProgress}
		case job.key == key && job.err != nil && !job.request.sameTerm(request):
			// The term that started the failed attempt ended (its fence
			// most likely cancelled it); the new term resumes at once.
		case job.key == key && job.err != nil:
			// Report the failure once; the leader's retry backoff decides
			// when the next request starts a fresh attempt.
			s.job = nil
			return SeedReplaceReply{Status: SeedFailed, Error: job.err.Error()}
		case job.key == key:
			return SeedReplaceReply{Status: SeedDone}
		case job.running:
			return refuse(fmt.Errorf("seed is already replacing slot %s", job.request.Slot))
		}
	}
	job := &seedJob{key: key, request: request, running: true}
	s.job = job
	s.jobs.Add(1)
	go s.run(job)
	s.deps.Logger.Info("seed accepted a routed controller slot replacement", "slot", request.Slot,
		"previous_attempt", request.PreviousAttempt, "prior_instance", request.PriorInstanceOCID,
		"epoch", request.Epoch, "leader", request.CandidateID)
	return SeedReplaceReply{Status: SeedAccepted}
}

func (s *SeedServer) run(job *seedJob) {
	defer s.jobs.Done()
	request := job.request
	fence := func(ctx context.Context) error {
		return s.deps.Leases.VerifyLeaseHolder(ctx, request.Epoch, request.CandidateID, request.OwnerID)
	}
	poll := seedFencePoll
	ctx, cancel := context.WithCancelCause(s.base)
	defer cancel(context.Canceled)
	go func() {
		ticker := time.NewTicker(poll)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := fence(ctx); err != nil && ctx.Err() == nil {
					cancel(fmt.Errorf("requesting authority term ended during slot replacement: %w", err))
					return
				}
			}
		}
	}()
	err := s.execute(ctx, request, fence)
	if err == nil && ctx.Err() != nil {
		err = context.Cause(ctx)
	}
	s.mu.Lock()
	job.running, job.err = false, err
	s.mu.Unlock()
	s.record(request, err)
	if err != nil {
		s.deps.Logger.Warn("routed controller slot replacement failed", "slot", request.Slot,
			"previous_attempt", request.PreviousAttempt, "epoch", request.Epoch, "error", err)
		return
	}
	s.deps.Logger.Info("routed controller slot replacement finished", "slot", request.Slot,
		"attempt", request.PreviousAttempt+1, "epoch", request.Epoch)
}

func (s *SeedServer) execute(ctx context.Context, request SeedReplaceRequest, fence func(context.Context) error) error {
	// Independent of the leader's observation: an instance that may still
	// run is never replaced by a routed request.
	lifecycle, err := s.deps.Instances.Lifecycle(ctx, request.PriorInstanceOCID)
	if err != nil {
		return fmt.Errorf("observe prior instance %s: %w", request.PriorInstanceOCID, err)
	}
	if lifecycle != LifecycleTerminated {
		return fmt.Errorf("prior instance %s is %s, not %s", request.PriorInstanceOCID, lifecycle, LifecycleTerminated)
	}
	if err := fence(ctx); err != nil {
		return fmt.Errorf("authority fence: %w", err)
	}
	sum := sha256.Sum256(request.Retirement)
	return s.deps.Replacer.Replace(ctx, Action{Slot: request.Slot, PreviousAttempt: request.PreviousAttempt,
		PriorInstanceOCID: request.PriorInstanceOCID, Epoch: request.Epoch,
		Retirement: Evidence{Slot: request.Slot, PreviousAttempt: request.PreviousAttempt,
			PriorInstanceOCID: request.PriorInstanceOCID, Digest: hex.EncodeToString(sum[:]), Wire: request.Retirement},
		Reason: "routed by authority leader " + request.CandidateID, Fence: fence})
}

// record journals the outcome of a routed replacement on the seed. The
// leader journals its decision; this records the seed's execution of it.
func (s *SeedServer) record(request SeedReplaceRequest, err error) {
	status, summary := decisionlog.StatusSucceeded,
		fmt.Sprintf("Seed relaunched controller slot %s as attempt %d", request.Slot, request.PreviousAttempt+1)
	attrs := map[string]string{"prior_instance": request.PriorInstanceOCID, "leader": request.CandidateID}
	if err != nil {
		status = decisionlog.StatusFailed
		summary = fmt.Sprintf("Seed could not relaunch controller slot %s as attempt %d", request.Slot,
			request.PreviousAttempt+1)
		attrs["error"] = err.Error()
	}
	decisionlog.Record(context.WithoutCancel(s.base), decisionlog.Decision{
		Region:  s.topology.Cell,
		Actor:   decisionlog.Actor{Slice: "membership"},
		Kind:    decisionlog.KindControllerReplaced,
		Subject: decisionlog.Subject{Kind: "member", ID: s.topology.ServerName(request.Slot), Name: request.Slot},
		Summary: summary,
		Reason:  "The authority leader routed a replacement for a lost slot to the seed, which holds the founder signer.",
		Rule:    "membership.seed_routed",
		Signals: []decisionlog.Signal{{Name: "prior_attempt", Value: float64(request.PreviousAttempt)}},
		Status:  status,
		Epoch:   request.Epoch,
		Attrs:   attrs,
	})
}

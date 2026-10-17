package host

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

type cycleRecord struct {
	CycleID        string    `json:"cycle_id"`
	Fence          uint64    `json:"fence"`
	Attempt        string    `json:"attempt"`
	Digest         string    `json:"digest"`
	Generation     uint64    `json:"generation"`
	AuthorityEpoch uint64    `json:"authority_epoch"`
	SessionID      string    `json:"session_id"`
	Epoch          uint64    `json:"epoch"`
	State          string    `json:"state"`
	Failures       int       `json:"failures"`
	NotBefore      time.Time `json:"not_before,omitzero"`
}

func (c *Controller) serveCycle(ctx context.Context, req request, r Registration, s session) (any, error) {
	var query cycleQuery
	if err := decodeStrict(req.Payload, &query); err != nil {
		return nil, err
	}
	if !slices.Contains(r.Roles, query.Role) || validateDigest(query.Digest) != nil || query.Generation == 0 || query.AuthorityEpoch == 0 || !entityid.Valid(query.Attempt) {
		return nil, errors.New("invalid cycle query")
	}
	if query.CycleID == "" {
		if err := c.guardNativeOwner(ctx, r.Environment, query.Role); err != nil {
			return nil, err
		}
	}
	var desired Desired
	if query.CycleID == "" {
		var exists bool
		var err error
		desired, _, exists, err = c.readDesired(ctx, req.Node, query.Role)
		if err != nil {
			return nil, err
		}
		if !exists || desired.Withdrawn || desired.Generation != query.Generation || desired.AuthorityEpoch != query.AuthorityEpoch || desired.Digest != query.Digest {
			return nil, errors.New("cycle target is no longer desired")
		}
	}
	key := cycleKey(c.cell, req.Node, query.Role)
	// granted remembers the restart gate's grant across CAS retries, so one
	// request asks the gate at most once.
	granted := false
	for range 8 {
		var old cycleRecord
		revision, exists, err := c.get(ctx, key, &old)
		if err != nil {
			return nil, err
		}
		if req.Operation != "cycle" {
			return nil, errors.New("invalid cycle operation")
		}
		if query.CycleID == "" {
			if exists && old.Generation > query.Generation {
				return nil, errors.New("cycle generation moved backward")
			}
			if exists && old.Attempt == query.Attempt && old.Digest == query.Digest && old.Generation == query.Generation && old.AuthorityEpoch == query.AuthorityEpoch && old.SessionID == s.SessionID && old.Epoch == s.Epoch {
				if _, err := c.cas(ctx, key, old, revision); err == nil {
					return cycleReply{CycleID: old.CycleID, Fence: old.Fence, State: old.State, NotBefore: old.NotBefore}, nil
				} else if casConflict(err) {
					continue
				} else {
					return nil, err
				}
			}
			if exists && old.State == "active" && old.Generation == query.Generation && old.AuthorityEpoch == query.AuthorityEpoch && old.SessionID == s.SessionID && old.Epoch == s.Epoch {
				return cycleReply{CycleID: old.CycleID, Fence: old.Fence, State: "busy"}, nil
			}
			if exists && old.State == "active" && old.Digest == query.Digest && old.Generation == query.Generation && old.AuthorityEpoch == query.AuthorityEpoch {
				abandoned := old
				abandoned.State = "failed"
				abandoned.Failures = min(old.Failures+1, 6)
				abandoned.NotBefore = time.Now().Add(backoffDuration(abandoned.Failures))
				if _, err := c.cas(ctx, key, abandoned, revision); err == nil {
					return cycleReply{CycleID: old.CycleID, Fence: old.Fence, State: "backoff", NotBefore: abandoned.NotBefore}, nil
				} else if casConflict(err) {
					continue
				} else {
					return nil, err
				}
			}
			if exists && old.Digest == query.Digest && old.Generation == query.Generation && old.AuthorityEpoch == query.AuthorityEpoch && time.Now().Before(old.NotBefore) {
				return cycleReply{CycleID: old.CycleID, Fence: old.Fence, State: "backoff", NotBefore: old.NotBefore}, nil
			}
			// Only opening a new cycle is gated: the agent's revalidation
			// resolves the cycle it already holds above. Managed members stop
			// their workload before they ask, so they are never held; their
			// drain receipts order their restarts.
			if c.restartGate != nil && desired.ManagedMember == nil && !granted {
				ok, err := c.restartGate(ctx, req.Node, desired)
				if err != nil {
					return nil, err
				}
				if !ok {
					return cycleReply{State: "held"}, nil
				}
				granted = true
			}
			id, err := randomID()
			if err != nil {
				return nil, err
			}
			next := cycleRecord{CycleID: id, Fence: 1, Attempt: query.Attempt, Digest: query.Digest, Generation: query.Generation, AuthorityEpoch: query.AuthorityEpoch, SessionID: s.SessionID, Epoch: s.Epoch, State: "active"}
			if exists {
				if old.Fence == ^uint64(0) {
					return nil, errors.New("cycle fence exhausted")
				}
				next.Fence = old.Fence + 1
				if old.Digest == query.Digest && old.Generation == query.Generation && old.AuthorityEpoch == query.AuthorityEpoch {
					next.Failures = old.Failures
				}
			}
			if _, err := c.cas(ctx, key, next, revision); err == nil {
				return cycleReply{CycleID: id, Fence: next.Fence, State: "active"}, nil
			} else if casConflict(err) {
				continue
			} else {
				return nil, err
			}
		}
		if !exists || old.CycleID != query.CycleID || old.Fence != query.Fence || old.Attempt != query.Attempt || old.SessionID != s.SessionID || old.Epoch != s.Epoch || old.Digest != query.Digest || old.Generation != query.Generation || old.AuthorityEpoch != query.AuthorityEpoch {
			return nil, errors.New("cycle outcome fence mismatch")
		}
		if old.State != "active" {
			return cycleReply{CycleID: old.CycleID, Fence: old.Fence, State: old.State, NotBefore: old.NotBefore}, nil
		}
		next := old
		if query.Succeeded {
			next.State = "succeeded"
			next.Failures = 0
		} else {
			next.State = "failed"
			next.Failures = min(old.Failures+1, 6)
			next.NotBefore = time.Now().Add(backoffDuration(next.Failures))
		}
		if _, err := c.cas(ctx, key, next, revision); err == nil {
			return cycleReply{CycleID: old.CycleID, Fence: old.Fence, State: next.State, NotBefore: next.NotBefore}, nil
		} else if casConflict(err) {
			continue
		} else {
			return nil, err
		}
	}
	return nil, errors.New("cycle contention")
}

func backoffDuration(failures int) time.Duration {
	return min(30*time.Second*time.Duration(1<<(max(1, failures)-1)), 15*time.Minute)
}

func (c *Controller) storeReport(ctx context.Context, req request, r Registration, s session) (any, error) {
	var report Report
	if err := decodeStrict(req.Payload, &report); err != nil {
		return nil, err
	}
	if report.Cell != c.cell || report.Node != req.Node || report.Environment != r.Environment || !slices.Contains(r.Roles, report.Role) || report.SessionID != s.SessionID || report.Epoch != s.Epoch ||
		report.ObservedAt.Before(req.IssuedAt.Add(-30*time.Second)) || report.ObservedAt.After(time.Now().Add(maxClockSkew)) || report.ObservedAt.IsZero() || len(report.Error) > 1024 || len(report.State) > 64 {
		return nil, errors.New("report identity or timestamp mismatch")
	}
	desired, _, exists, err := c.readDesired(ctx, req.Node, report.Role)
	if err != nil {
		return nil, err
	}
	if !exists || report.Generation != desired.Generation || report.Digest != desired.Digest {
		return nil, errors.New("report target is not current")
	}
	if err := validateManagedReportForDesired(report, desired); err != nil {
		return nil, err
	}
	key := reportKey(c.cell, req.Node, report.Role)
	for range 8 {
		current, _, exists, err := c.readDesired(ctx, req.Node, report.Role)
		if err != nil || !exists || !sameJSON(current, desired) {
			return nil, errors.New("desired changed before report commit")
		}
		if _, _, err := c.authorize(ctx, req); err != nil {
			return nil, err
		}
		var old Report
		revision, exists, err := c.get(ctx, key, &old)
		if err != nil {
			return nil, err
		}
		if exists {
			if report.Generation < old.Generation || report.Generation == old.Generation && report.ObservedAt.Before(old.ObservedAt) {
				return nil, errors.New("report ordering moved backward")
			}
			if report.Generation == old.Generation && report.ObservedAt.Equal(old.ObservedAt) && !sameJSON(report, old) {
				return nil, errors.New("report timestamp collision")
			}
		}
		_, err = c.cas(ctx, key, report, revision)
		if err == nil {
			current, _, exists, checkErr := c.readDesired(ctx, req.Node, report.Role)
			if checkErr != nil || !exists || !sameJSON(current, desired) {
				return nil, errors.New("desired changed during report commit")
			}
			return struct {
				Accepted bool `json:"accepted"`
			}{true}, nil
		}
		if !casConflict(err) {
			return nil, fmt.Errorf("store report: %w", err)
		}
	}
	return nil, errors.New("report contention")
}

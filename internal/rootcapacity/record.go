// Package rootcapacity performs finite pool operations in the protected home
// process. Regional observations and request DTOs are never creation authority.
package rootcapacity

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/drainwire"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/globalcontrol"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
	"github.com/TerraScale/ts-orchestrator/internal/rootsecret"
)

var ErrPending = errors.New("protected capacity operation is pending")

// attempt is constructed only after the home handler independently resolves
// the original durable reservation, signed source and actual home connection.
type attempt struct {
	call           rootoci.Call
	resolver       region.FoundationResolver
	store          *region.ObjectFoundationStore
	writer         *region.CapacityJournalWriter
	factory        *ociclient.Factory
	home           *globalcontrol.Reader
	leader         *authority.Reader
	credentials    *rootsecret.ControllerReader
	original       authority.Snapshot
	deadline       time.Time
	receipt        budget.Reservation
	worker         region.VerifiedWorkerRecipe
	membership     region.VerifiedPoolMembership
	lifecycle      region.VerifiedPoolLifecycle
	drain          *drainwire.PoolReceipt
	birthOperation string
	recipe         nodescale.Recipe
	record         region.FoundationRecord
	etag           string
	operation      string
	poolID         string
	leaseID        string
	observation    *rootoci.PoolChildObservation
}

func (a *attempt) guard(ctx context.Context) error {
	if err := a.guardPrincipal(ctx); err != nil {
		return err
	}
	if a.leaseID != "" {
		// This independent lease read retains the principal guard without
		// recursively asking its own SDK request to reload the same lease.
		read := ociclient.RequestContext(ociclient.WithRequestGuard(ociclient.CheckpointContext(ctx), a.guardPrincipal))
		latest, _, err := a.store.Load(read, a.record.Cell)
		if err != nil {
			return err
		}
		pool, exists := latest.CapacityPools[a.poolID]
		if !exists || pool.ActiveOperationID != a.operation || pool.LeaseID != a.leaseID || pool.Epoch != a.original.Epoch || !time.Now().Before(pool.LeaseExpiresAt) {
			return authority.ErrFenced
		}
	}
	if !time.Now().Before(a.deadline) {
		return rootoci.ErrUnauthorized
	}
	return ctx.Err()
}

func (a *attempt) guardPrincipal(ctx context.Context) error {
	if err := a.call.Guard(ctx); err != nil {
		return err
	}
	if a.deadline.IsZero() || !time.Now().Before(a.deadline) {
		return rootoci.ErrUnauthorized
	}
	if a.observation != nil {
		if a.home != nil || a.leader != nil || a.credentials != nil || a.leaseID != "" {
			return rootoci.ErrUnauthorized
		}
		return ctx.Err()
	}
	if a.home == nil || a.leader == nil || a.credentials == nil {
		return rootoci.ErrUnauthorized
	}
	if err := a.credentials.Guard(ctx); err != nil {
		return err
	}
	current, err := a.leader.CurrentLease(ctx)
	if err != nil {
		return err
	}
	if current.Epoch != a.original.Epoch || current.OwnerID != a.original.OwnerID || current.CandidateID != a.original.CandidateID || current.DeploymentID != a.original.DeploymentID {
		return authority.ErrFenced
	}
	term, err := a.home.Term(ctx)
	if err != nil || term != a.original.Epoch {
		return errors.Join(err, authority.ErrFenced)
	}
	if !time.Now().Before(a.deadline) {
		return rootoci.ErrUnauthorized
	}
	return ctx.Err()
}

func (a *attempt) proofContext(ctx context.Context) context.Context {
	return ociclient.WithRequestGuard(ociclient.CheckpointContext(ctx), a.guard)
}

func (a *attempt) readContext(ctx context.Context) context.Context {
	return ociclient.RequestContext(a.proofContext(ctx))
}

func (a *attempt) save(ctx context.Context) error {
	if a.observation != nil || a.home == nil || a.leader == nil || a.writer == nil {
		return errors.New("root observation cannot mutate protected capacity history")
	}
	if err := a.guard(ociclient.CheckpointContext(ctx)); err != nil {
		return err
	}
	a.record.UpdatedAt = time.Now().UTC()
	etag, err := a.writer.CompareAndSwap(a.readContext(ctx), a.record, a.etag)
	if err != nil {
		return err
	}
	a.etag = etag
	return nil
}

func (a *attempt) claimPool(ctx context.Context, poolID string) error {
	pool, exists := a.record.CapacityPools[poolID]
	if !exists {
		return errors.New("capacity pool has no protected original create")
	}
	if pool.ActiveOperationID != "" && pool.ActiveOperationID != a.operation &&
		!completedPoolOperation(a.record, poolID, pool.ActiveOperationID) {
		return fmt.Errorf("%w: another original operation owns this pool lifecycle", ErrPending)
	}
	if pool.LeaseID != "" && time.Now().Before(pool.LeaseExpiresAt) {
		return fmt.Errorf("%w: pool lifecycle has a live protected owner", ErrPending)
	}
	leaseID := entityid.New()
	pool.ActiveOperationID, pool.LeaseID, pool.Epoch = a.operation, leaseID, a.original.Epoch
	pool.LeaseExpiresAt = a.deadline
	a.record.CapacityPools[poolID] = pool
	if err := a.save(ctx); err != nil {
		return err
	}
	a.poolID, a.leaseID = poolID, leaseID
	return nil
}

func (a *attempt) releasePool(ctx context.Context, complete bool) error {
	if a.leaseID == "" {
		return nil
	}
	pool := a.record.CapacityPools[a.poolID]
	pool.LeaseID, pool.LeaseExpiresAt = "", time.Time{}
	if complete {
		pool.ActiveOperationID = ""
	}
	a.record.CapacityPools[a.poolID] = pool
	if err := a.save(ctx); err != nil {
		return err
	}
	a.leaseID = ""
	return nil
}

func (a *attempt) childOperation() string {
	if a.birthOperation != "" {
		return a.birthOperation
	}
	return a.receipt.OperationID
}

func (a *attempt) wire(kind string) *region.PoolWireRecord {
	child := a.record.PoolChildren[a.childOperation()]
	switch kind {
	case "launch":
		return child.Launch
	case "attach":
		return child.Attach
	case "detach":
		return child.Detach
	case "terminate":
		return child.Terminate
	case "delete-boot":
		return child.DeleteBoot
	case "quarantine":
		return a.record.PoolQuarantines[a.operation].Detach
	case "configuration", "pool":
		create, exists := a.record.CapacityCreates[a.receipt.OperationID+":"+kind]
		if !exists {
			return nil
		}
		return &create.Request
	case "point":
		point, exists := a.record.CapacityPools[a.poolID].ConfigurationUpdates[a.operation]
		if !exists {
			return nil
		}
		return &point.Request
	default:
		return nil
	}
}

func (a *attempt) setWire(kind string, wire *region.PoolWireRecord) {
	switch kind {
	case "configuration", "pool":
		key := a.receipt.OperationID + ":" + kind
		create := a.record.CapacityCreates[key]
		create.Request = *wire
		a.record.CapacityCreates[key] = create
	case "point":
		pool := a.record.CapacityPools[a.poolID]
		point := pool.ConfigurationUpdates[a.operation]
		point.Request = *wire
		pool.ConfigurationUpdates[a.operation] = point
		a.record.CapacityPools[a.poolID] = pool
	}
}

func (a *attempt) unknownStage(kind string) {
	child := a.record.PoolChildren[a.childOperation()]
	switch kind {
	case "launch":
		child.Stage = region.PoolChildLaunchUnknown
	case "attach":
		child.Stage = region.PoolChildAttachUnknown
	case "detach":
		child.Stage = region.PoolChildDetachUnknown
	default:
		return
	}
	a.record.PoolChildren[a.childOperation()] = child
}

func (a *attempt) writeContext(ctx context.Context, kind string) context.Context {
	ctx = ociclient.WithWireAttempt(ctx, func(request *http.Request) (func(*http.Response, error, bool) error, error) {
		wire := a.wire(kind)
		if wire == nil || !wire.AcceptedAt.IsZero() {
			return nil, errors.New("provider request has no unresolved protected preparation")
		}
		digest, err := wireSHA256(request)
		if err != nil || digest != wire.RequestSHA256 || request.Header.Get("opc-retry-token") != wire.RetryToken || request.Header.Get("if-match") != wire.IfMatch {
			return nil, errors.Join(err, errors.New("actual SDK wire differs from original protected request"))
		}
		if wire.PendingAttemptID != "" {
			wire.EverUnknown = true
			a.unknownStage(kind)
		}
		attemptID := entityid.New()
		wire.PendingAttemptID, wire.LastAttemptAt = attemptID, time.Now().UTC()
		wire.Attempts++
		a.setWire(kind, wire)
		if err := a.save(request.Context()); err != nil {
			return nil, err
		}
		return func(response *http.Response, dispatchErr error, sent bool) error {
			if wire.PendingAttemptID != attemptID {
				return errors.New("protected wire attempt identity changed")
			}
			wire.PendingAttemptID = ""
			if sent && (dispatchErr != nil || response == nil || response.StatusCode >= 500 || response.StatusCode >= 200 && response.StatusCode < 300) {
				wire.EverUnknown = true
				a.unknownStage(kind)
			}
			a.setWire(kind, wire)
			return a.save(request.Context())
		}, nil
	})
	ctx = ociclient.WithAdmission(ctx, func(ctx context.Context) (func(), error) {
		wire := a.wire(kind)
		if wire == nil || wire.TokenInvalidated || wire.FirstAttemptAt.IsZero() || wire.RetryToken != "" && !time.Now().Before(wire.FirstAttemptAt.Add(23*time.Hour)) {
			return nil, fmt.Errorf("%w: original provider retry token is expired or invalidated", ErrPending)
		}
		switch kind {
		case "detach", "terminate", "delete-boot":
			if err := a.lifecycle.Revalidate(a.proofContext(ctx)); err != nil {
				return nil, err
			}
		case "quarantine":
		default:
			if err := a.worker.Revalidate(a.proofContext(ctx)); err != nil {
				return nil, err
			}
		}
		if err := a.guard(ociclient.CheckpointContext(ctx)); err != nil {
			return nil, err
		}
		deadline := a.deadline
		if kind == "launch" && a.receipt.LaunchExpiresAt.Before(deadline) {
			deadline = a.receipt.LaunchExpiresAt
		}
		if err := ociclient.LimitAdmission(ctx, deadline); err != nil {
			return nil, err
		}
		return func() {}, nil
	})
	return ociclient.RequestContext(ociclient.WithRequestGuard(ctx, func(ctx context.Context) error {
		if err := a.guard(ctx); err != nil {
			return err
		}
		if a.writer == nil {
			return errors.New("capacity provider mutation lacks its original dedicated journal writer")
		}
		if err := a.writer.Guard(a.proofContext(ctx)); err != nil {
			return err
		}
		switch kind {
		case "launch":
			return a.authorizeLaunch(ctx)
		case "attach":
			return a.authorizeAttach(ctx)
		case "quarantine":
			return a.authorizeQuarantine(ctx)
		case "detach", "terminate", "delete-boot":
			return a.authorizeRetirement(ctx, kind)
		default:
			return nil
		}
	}))
}

// wireSHA256 reads the SDK's current signed bytes. Preserve GetBody, headers and
// ContentLength: the SDK's NopCloser no longer exposes its original seeker.
func wireSHA256(request *http.Request) (string, error) {
	var body []byte
	if request.Body != nil {
		original := request.Body
		var err error
		body, err = io.ReadAll(original)
		request.Body = io.NopCloser(bytes.NewReader(body))
		if err := errors.Join(err, original.Close()); err != nil {
			return "", err
		}
	}
	path := strings.TrimPrefix(request.URL.EscapedPath(), "/20160918")
	digest := sha256.New()
	_, _ = fmt.Fprintf(digest, "%s\n%s\n%s\n%s\n%s\n%s\n", request.Method, path, request.URL.RawQuery,
		request.Header.Get("Content-Type"), request.Header.Get("if-match"), request.Header.Get("opc-retry-token"))
	_, _ = digest.Write(body)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

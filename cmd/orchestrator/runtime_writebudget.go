package main

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/authorityjournal"
	"terrascale.tech/orchestrator/src/orchestrator/security"
	"terrascale.tech/orchestrator/src/orchestrator/writebudget"
)

// writeBudgetDelivery is the authenticated regional transport. Implementations
// must bind the connection to the region and writer identity before accepting
// the signed bytes; this seam carries no per-write Worker traffic.
type writeBudgetDelivery interface {
	SendAllocation(context.Context, writebudget.SignedAllocation) error
}

// writeBudgetPoolDelivery installs schema-2 refill envelopes on the one
// authenticated holder. It is separate from the retired operation-specific
// allocation transport during the producer/consumer migration.
type writeBudgetPoolDelivery interface {
	SendPoolRefill(context.Context, writebudget.SignedPoolAllocation) error
}

type runtimeWriteBudgetConfig struct {
	InitialPolicy    writebudget.PolicyEnvelope
	ValidateRequest  func(context.Context, writebudget.Request) error
	Policy           writebudget.Policy
	StateKey         string
	Signer           *security.CommandSignatureSigner
	Placement        string
	Delivery         writeBudgetDelivery
	PoolDelivery     writeBudgetPoolDelivery
	PolicyListener   net.Listener
	PolicyServiceKey string
}

type runtimeWriteBudget struct {
	validateRequest func(context.Context, writebudget.Request) error
	authority       *writebudget.Authority
	policy          writebudget.Policy
	signer          *security.CommandSignatureSigner
	placement       string
	delivery        writeBudgetDelivery
	poolDelivery    writeBudgetPoolDelivery
	policyServer    *http.Server
}

// ApplyPolicy implements the billing bridge after the billing producer has
// authenticated its envelope. The account revision/checksum pair is committed
// through the same GRU journal, making stale retries and conflicting updates
// observable instead of silently replacing policy state.
func (r *runtimeWriteBudget) ApplyPolicy(ctx context.Context, envelope writebudget.PolicyEnvelope) (writebudget.PolicyResult, error) {
	if r == nil || r.authority == nil || envelope.OrganizationID != r.policy.OrganizationID || envelope.CycleID == "" || envelope.AccountRevision == "" || envelope.Checksum == "" || envelope.Policy == nil {
		return writebudget.PolicyResult{}, errors.New("runtime write budget: invalid billing policy")
	}
	next, err := decodeWriteBudgetPolicy(r.policy, envelope)
	if err != nil {
		return writebudget.PolicyResult{}, err
	}
	if err := r.authority.ApplyPolicy(ctx, envelope.AccountRevision, envelope.Checksum, envelope.PolicyGeneration, next); err != nil {
		return writebudget.PolicyResult{}, err
	}
	pending, err := r.authority.PolicyPending(ctx)
	if err != nil {
		return writebudget.PolicyResult{}, err
	}
	status := "accepted"
	if pending {
		status = "pending"
	}
	return writebudget.PolicyResult{Status: status, AccountRevision: envelope.AccountRevision, PolicyGeneration: envelope.PolicyGeneration, CycleID: envelope.CycleID, Checksum: envelope.Checksum}, nil
}

// decodeWriteBudgetPolicy is shared by initial snapshot admission and the
// authenticated billing update path so startup cannot drop accrued charges or
// use a different allowance representation.
func decodeWriteBudgetPolicy(base writebudget.Policy, envelope writebudget.PolicyEnvelope) (writebudget.Policy, error) {
	raw, err := json.Marshal(envelope.Policy)
	if err != nil {
		return writebudget.Policy{}, err
	}
	var published struct {
		OrganizationID              string            `json:"organizationId"`
		CycleID                     string            `json:"cycleId"`
		IncludedAllowanceEndsAt     *string           `json:"includedAllowanceEndsAt"`
		IncludedWriteUnits          string            `json:"includedWriteUnits"`
		PaidExcessEnabled           bool              `json:"paidExcessEnabled"`
		OrganizationSpendNano       *int64            `json:"organizationSpendNano"`
		RateNanoDollar              int64             `json:"rateNanoDollar"`
		DatabaseSpendCapsCents      map[string]int64  `json:"databaseSpendCapsCents"`
		AccruedNonWriteNano         string            `json:"accruedNonWriteNano"`
		DatabaseAccruedNonWriteNano map[string]string `json:"databaseAccruedNonWriteNano"`
	}
	if err := json.Unmarshal(raw, &published); err != nil || published.OrganizationID != envelope.OrganizationID || published.CycleID != envelope.CycleID {
		return writebudget.Policy{}, errors.New("runtime write budget: invalid policy payload")
	}
	included, err := strconv.ParseInt(published.IncludedWriteUnits, 10, 64)
	if err != nil || included < 0 || strconv.FormatInt(included, 10) != published.IncludedWriteUnits {
		return writebudget.Policy{}, errors.New("runtime write budget: invalid allowance")
	}
	parseAccrued := func(value string) (int64, error) {
		if value == "" {
			return 0, nil
		}
		parsed, err := strconv.ParseInt(value, 10, 64)
		if err != nil || parsed < 0 || strconv.FormatInt(parsed, 10) != value {
			return 0, errors.New("runtime write budget: invalid accrued spend")
		}
		return parsed, nil
	}
	next := base
	next.IncludedAllowanceEndsAt = time.Time{}
	if _, present := envelope.Policy["includedAllowanceEndsAt"]; present && published.IncludedAllowanceEndsAt == nil {
		return writebudget.Policy{}, errors.New("runtime write budget: invalid allowance deadline")
	}
	if published.IncludedAllowanceEndsAt != nil {
		cutoff, err := time.Parse(time.RFC3339Nano, *published.IncludedAllowanceEndsAt)
		if err != nil || cutoff.IsZero() || !strings.HasSuffix(*published.IncludedAllowanceEndsAt, "Z") {
			return writebudget.Policy{}, errors.New("runtime write budget: invalid allowance deadline")
		}
		next.IncludedAllowanceEndsAt = cutoff.UTC()
	}
	next.AccruedNonWriteNano, err = parseAccrued(published.AccruedNonWriteNano)
	if err != nil {
		return writebudget.Policy{}, err
	}
	next.DatabaseAccruedNonWriteNano = make(map[string]int64, len(published.DatabaseAccruedNonWriteNano))
	for database, value := range published.DatabaseAccruedNonWriteNano {
		if value == "" {
			return writebudget.Policy{}, errors.New("runtime write budget: missing database accrued spend")
		}
		accrued, err := parseAccrued(value)
		if err != nil {
			return writebudget.Policy{}, err
		}
		next.DatabaseAccruedNonWriteNano[database] = accrued
	}
	next.CycleID, next.IncludedAllowanceUnits, next.RateNanoDollar = envelope.CycleID, included, published.RateNanoDollar
	next.PaidExcessEnabled = published.PaidExcessEnabled
	if published.OrganizationSpendNano != nil {
		cap := *published.OrganizationSpendNano
		next.OrganizationSpendCap = &cap
	} else {
		next.OrganizationSpendCap = nil
	}
	next.DatabaseSpendCaps = nil
	if published.DatabaseSpendCapsCents != nil {
		next.DatabaseSpendCaps = make(map[string]*int64, len(published.DatabaseSpendCapsCents))
		for database, cap := range published.DatabaseSpendCapsCents {
			if cap < 0 {
				return writebudget.Policy{}, errors.New("runtime write budget: invalid database cap")
			}
			if cap > (1<<63-1)/10_000_000 {
				return writebudget.Policy{}, errors.New("runtime write budget: database cap overflow")
			}
			nano := cap * 10_000_000
			next.DatabaseSpendCaps[database] = &nano
		}
	}
	return next, nil
}

// newRuntimeWriteBudget binds the authority to the exact live current GRU
// lease. Callers invoke this only from the lease-owned global worker
// constructor, after globalWorkerSession has validated the lease.
func newRuntimeWriteBudget(session globalWorkerSession, config runtimeWriteBudgetConfig) (*runtimeWriteBudget, error) {
	if session.Connection == nil || session.Lease.CandidateId == "" || session.Lease.Epoch <= 0 || session.Lease.LeaseId == "" || config.StateKey == "" || config.Signer == nil || config.Placement == "" || config.Delivery == nil || config.ValidateRequest == nil || config.InitialPolicy.OrganizationID != config.Policy.OrganizationID || config.InitialPolicy.CycleID != config.Policy.CycleID || config.InitialPolicy.AccountRevision == "" || config.InitialPolicy.PolicyGeneration <= 0 || config.InitialPolicy.Checksum == "" {
		return nil, errors.New("runtime write budget: incomplete live authority or delivery configuration")
	}
	journal, err := authorityjournal.New(authorityjournal.Config{
		Connection: session.Connection, CandidateID: session.Lease.CandidateId,
		AuthorityEpoch: uint64(session.Lease.Epoch), LeaseID: session.Lease.LeaseId,
		StateKey: config.StateKey,
	}, func() writebudget.State {
		return writebudget.State{ActivePolicy: config.Policy, AccountRevision: config.InitialPolicy.AccountRevision, PolicyChecksum: config.InitialPolicy.Checksum, PolicyGeneration: config.InitialPolicy.PolicyGeneration, CycleID: config.Policy.CycleID, PolicyEpoch: config.Policy.PolicyEpoch, ConsentEpoch: config.Policy.ConsentEpoch}
	}, func(writebudget.State) error { return nil })
	if err != nil {
		return nil, fmt.Errorf("runtime write budget journal: %w", err)
	}
	authority, err := writebudget.NewJournalAuthority(journal, config.Policy)
	if err != nil {
		return nil, fmt.Errorf("runtime write budget authority: %w", err)
	}
	runtime := &runtimeWriteBudget{validateRequest: config.ValidateRequest, authority: authority, policy: config.Policy, signer: config.Signer, placement: config.Placement, delivery: config.Delivery, poolDelivery: config.PoolDelivery}
	if config.PolicyListener != nil {
		if len(config.PolicyServiceKey) < 32 {
			return nil, errors.New("runtime write budget: policy service key is required")
		}
		handler, err := writebudget.NewPolicyHandler(runtime, config.PolicyServiceKey)
		if err != nil {
			return nil, err
		}
		runtime.policyServer = &http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second, MaxHeaderBytes: 16 << 10}
	}
	return runtime, nil
}

// RefillPool reserves a bounded aggregate tranche in GRU, signs the exact
// schema-2 pool document, and asynchronously installs it on the holder. A
// delivery error is unknown: retrying the unchanged refill operation replays
// the durable GRU reservation and never bills unused credits.
func (r *runtimeWriteBudget) RefillPool(ctx context.Context, request writebudget.PoolRefillRequest) (writebudget.PoolGrant, error) {
	if r == nil || r.authority == nil || r.signer == nil || r.poolDelivery == nil {
		return writebudget.PoolGrant{}, errors.New("runtime write budget: pool refill unavailable")
	}
	grant, err := r.authority.ReservePool(ctx, request)
	if err != nil {
		return writebudget.PoolGrant{}, err
	}
	signed, err := writebudget.SignPoolRefill(r.signer, grant)
	if err != nil {
		return writebudget.PoolGrant{}, err
	}
	if err := r.poolDelivery.SendPoolRefill(ctx, signed); err != nil {
		return grant, fmt.Errorf("runtime write budget pool delivery: %w", err)
	}
	return grant, nil
}

func (r *runtimeWriteBudget) Start(ctx context.Context, listener net.Listener) error {
	if r == nil || r.policyServer == nil || listener == nil {
		return errors.New("runtime write budget: policy listener is unavailable")
	}
	go func() { _ = r.policyServer.Serve(listener) }()
	return nil
}

func (r *runtimeWriteBudget) Close() error {
	if r == nil || r.policyServer == nil {
		return nil
	}
	return r.policyServer.Close()
}

// Allocate reserves once in GRU, signs the exact persisted grant, and hands it
// to the regional writer. A delivery failure leaves the operation discoverable
// and safely retryable by its unchanged operation ID.
func (r *runtimeWriteBudget) Allocate(ctx context.Context, request writebudget.Request) (writebudget.Grant, error) {
	if r == nil || r.authority == nil || r.signer == nil || r.delivery == nil || r.validateRequest == nil {
		return writebudget.Grant{}, errors.New("runtime write budget: unavailable")
	}
	if err := r.validateRequest(ctx, request); err != nil {
		return writebudget.Grant{}, err
	}
	grant, err := r.authority.Allocate(ctx, request)
	if err != nil {
		return writebudget.Grant{}, err
	}
	if !grant.ExpiresAt.After(time.Now().UTC()) || grant.Revoked || grant.Fenced {
		return writebudget.Grant{}, writebudget.ErrInvalid
	}
	signed, err := writebudget.SignAllocation(r.signer, grant, grant.CycleID, grant.RateNanoDollar, r.placement)
	if err != nil {
		return writebudget.Grant{}, err
	}
	if err := r.delivery.SendAllocation(ctx, signed); err != nil {
		return grant, fmt.Errorf("runtime write budget delivery: %w", err)
	}
	return grant, nil
}

func (r *runtimeWriteBudget) Revoke(ctx context.Context, operationID string) error {
	if r == nil || r.authority == nil {
		return errors.New("runtime write budget: unavailable")
	}
	return r.authority.Revoke(ctx, operationID)
}

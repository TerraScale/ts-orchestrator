package hostenroll

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json/v2"
	"errors"
	"fmt"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/nats-io/nats.go/jetstream"
)

const GrantBucket = "TS_HOST_ENROLLMENT"

var ErrGrantInProgress = errors.New("host enrollment is in progress")
var ErrTerminalFenceConflict = errors.New("host enrollment grant changed during terminal fencing")
var ErrGrantMutationNotApplied = errors.New("host enrollment grant mutation was not applied")

type grantMutationNotAppliedError struct {
	err error
}

func (err *grantMutationNotAppliedError) Error() string {
	return fmt.Sprintf("%v: %v", ErrGrantMutationNotApplied, err.err)
}

func (err *grantMutationNotAppliedError) Unwrap() error { return err.err }

func (err *grantMutationNotAppliedError) Is(target error) bool {
	return target == ErrGrantMutationNotApplied
}

func mutationNotApplied(err error) error {
	if err == nil {
		return nil
	}
	return &grantMutationNotAppliedError{err: err}
}

// IsGrantMutationNotApplied reports errors returned only after the store has
// established that the requested KV mutation could not have been committed.
// Callers may settle an effect only after an exact unchanged readback.
func IsGrantMutationNotApplied(err error) bool {
	return errors.Is(err, ErrGrantMutationNotApplied)
}

// Grant pins the first successful private-network enrollment to one exact
// instance and request. Response is set durably before it is sent to the host.
type Grant struct {
	SchemaVersion       int       `json:"schema_version"`
	InstanceID          string    `json:"instance_id"`
	CreateKey           string    `json:"create_key"`
	DescriptorSHA256    string    `json:"descriptor_sha256"`
	Request             []byte    `json:"request"`
	Response            []byte    `json:"response,omitempty"`
	Disabled            bool      `json:"disabled,omitzero"`
	OwnerToken          string    `json:"owner_token,omitempty"`
	LeaseUntil          time.Time `json:"lease_until,omitzero"`
	RenewalRequest      []byte    `json:"renewal_request,omitempty"`
	RenewalResponse     []byte    `json:"renewal_response,omitempty"`
	RenewalToken        string    `json:"renewal_token,omitempty"`
	RenewalLeaseUntil   time.Time `json:"renewal_lease_until,omitzero"`
	TerminalOperationID string    `json:"terminal_operation_id,omitempty"`
}

type GrantStore struct {
	kv jetstream.KeyValue
}

func OpenGrantStore(ctx context.Context, js jetstream.JetStream, replicas int) (*GrantStore, error) {
	if js == nil || replicas < 1 || replicas > 5 {
		return nil, errors.New("host enrollment requires replicated JetStream")
	}
	kv, err := js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
		Bucket: GrantBucket, History: 2, MaxValueSize: 64 << 10,
		MaxBytes: 64 << 20, Storage: jetstream.FileStorage, Replicas: replicas,
	})
	if err != nil {
		return nil, fmt.Errorf("open host enrollment grants: %w", err)
	}
	status, err := kv.Status(ctx)
	if err != nil || status.Config().Replicas != replicas {
		return nil, errors.New("host enrollment grant replication differs from regional quorum")
	}
	return &GrantStore{kv: kv}, nil
}

func grantKey(instanceID string) string {
	return entityid.Derive("host-enrollment", instanceID)
}

// Claim creates a grant once, or returns a completed exact replay. A changed
// key, nonce, CSR, or descriptor for the same OCI instance is held.
func (store *GrantStore) Claim(ctx context.Context, candidate Grant) (Grant, uint64, error) {
	if store == nil || store.kv == nil || candidate.SchemaVersion != 1 || candidate.InstanceID == "" ||
		!entityid.Valid(candidate.CreateKey) || len(candidate.DescriptorSHA256) != 64 ||
		len(candidate.Request) == 0 || len(candidate.Request) > 16<<10 || len(candidate.Response) != 0 || candidate.Disabled ||
		candidate.OwnerToken != "" || !candidate.LeaseUntil.IsZero() {
		return Grant{}, 0, mutationNotApplied(errors.New("host enrollment grant candidate is invalid"))
	}
	claimToken := make([]byte, 32)
	if _, err := rand.Read(claimToken); err != nil {
		return Grant{}, 0, mutationNotApplied(err)
	}
	candidate.OwnerToken = base64.RawURLEncoding.EncodeToString(claimToken)
	candidate.LeaseUntil = time.Now().UTC().Add(time.Minute)
	wire, err := json.Marshal(candidate)
	if err != nil {
		return Grant{}, 0, mutationNotApplied(err)
	}
	key := grantKey(candidate.InstanceID)
	if revision, err := store.kv.Create(ctx, key, wire); err == nil {
		return candidate, revision, nil
	} else if !errors.Is(err, jetstream.ErrKeyExists) {
		return Grant{}, 0, fmt.Errorf("create host enrollment grant: %w", err)
	}
	entry, err := store.kv.Get(ctx, key)
	if err != nil {
		return Grant{}, 0, mutationNotApplied(fmt.Errorf("read host enrollment grant: %w", err))
	}
	var current Grant
	if len(entry.Value()) > 64<<10 || json.Unmarshal(entry.Value(), &current, json.RejectUnknownMembers(true)) != nil ||
		current.SchemaVersion != 1 || current.InstanceID != candidate.InstanceID || current.CreateKey != candidate.CreateKey ||
		current.DescriptorSHA256 != candidate.DescriptorSHA256 || !bytes.Equal(current.Request, candidate.Request) || current.Disabled {
		return Grant{}, 0, mutationNotApplied(errors.New("host enrollment grant differs from the immutable first request or is disabled"))
	}
	if len(current.Response) != 0 {
		return current, entry.Revision(), nil
	}
	if time.Now().Before(current.LeaseUntil) {
		return Grant{}, 0, mutationNotApplied(ErrGrantInProgress)
	}
	current.OwnerToken = candidate.OwnerToken
	current.LeaseUntil = candidate.LeaseUntil
	wire, err = json.Marshal(current)
	if err != nil {
		return Grant{}, 0, mutationNotApplied(err)
	}
	revision, err := store.kv.Update(ctx, key, wire, entry.Revision())
	if err != nil {
		wrapped := fmt.Errorf("recover host enrollment grant ownership: %w", err)
		if errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
			return Grant{}, 0, mutationNotApplied(wrapped)
		}
		return Grant{}, 0, wrapped
	}
	return current, revision, nil
}

// Forget deletes instanceID's grant, so the instance enrolls afresh: ts-orch
// node rename re-enrolls a renamed static host under its new name (TS-609).
func (store *GrantStore) Forget(ctx context.Context, instanceID string) error {
	if store == nil || store.kv == nil || instanceID == "" {
		return mutationNotApplied(errors.New("host enrollment grant store is unavailable"))
	}
	if err := store.kv.Delete(ctx, grantKey(instanceID)); err != nil && !errors.Is(err, jetstream.ErrKeyNotFound) {
		return fmt.Errorf("forget host enrollment grant: %w", err)
	}
	return nil
}

// Finish persists exact signed bytes before any network response. A lost reply
// returns the identical response on the next exact request.
func (store *GrantStore) Finish(ctx context.Context, expected Grant, revision uint64, response []byte) (Grant, error) {
	if store == nil || store.kv == nil || revision == 0 || expected.Disabled || len(expected.Response) != 0 ||
		expected.OwnerToken == "" || !time.Now().Before(expected.LeaseUntil) ||
		len(response) == 0 || len(response) > 32<<10 {
		return Grant{}, mutationNotApplied(errors.New("host enrollment response cannot be committed"))
	}
	expected.Response = bytes.Clone(response)
	wire, err := json.Marshal(expected)
	if err != nil {
		return Grant{}, mutationNotApplied(err)
	}
	if _, err := store.kv.Update(ctx, grantKey(expected.InstanceID), wire, revision); err != nil {
		wrapped := fmt.Errorf("commit host enrollment response: %w", err)
		if errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
			return Grant{}, mutationNotApplied(wrapped)
		}
		return Grant{}, wrapped
	}
	return expected, nil
}

func (store *GrantStore) Read(ctx context.Context, instanceID string) (Grant, uint64, error) {
	if store == nil || store.kv == nil || instanceID == "" {
		return Grant{}, 0, errors.New("host enrollment grant store is unavailable")
	}
	entry, err := store.kv.Get(ctx, grantKey(instanceID))
	if err != nil {
		return Grant{}, 0, err
	}
	var grant Grant
	if len(entry.Value()) > 64<<10 || json.Unmarshal(entry.Value(), &grant, json.RejectUnknownMembers(true)) != nil || grant.InstanceID != instanceID {
		return Grant{}, 0, errors.New("host enrollment grant is corrupt")
	}
	return grant, entry.Revision(), nil
}

func (store *GrantStore) Disable(ctx context.Context, instanceID string) (uint64, error) {
	for range 4 {
		grant, revision, err := store.Read(ctx, instanceID)
		if err != nil {
			return 0, err
		}
		if grant.Disabled {
			return revision, nil
		}
		grant.Disabled = true
		wire, err := json.Marshal(grant)
		if err != nil {
			return 0, err
		}
		next, err := store.kv.Update(ctx, grantKey(instanceID), wire, revision)
		if err == nil {
			return next, nil
		}
		if !errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
			return 0, err
		}
	}
	return 0, errors.New("host enrollment grant changed during disable")
}

// TerminalFence durably prevents a pinned instance from creating or completing
// an enrollment grant after a terminal operation is admitted. A zero revision
// creates a disabled tombstone for an instance that has not enrolled. A
// nonzero revision must identify the exact grant snapshot supplied by the
// caller and is disabled with a per-key CAS.
func (store *GrantStore) TerminalFence(ctx context.Context, expected Grant, expectedRevision uint64,
	operationID string,
) (Grant, uint64, error) {
	if store == nil || store.kv == nil || expected.SchemaVersion != 1 || expected.InstanceID == "" ||
		expected.CreateKey == "" || !validTerminalOperationID(operationID) {
		return Grant{}, 0, errors.New("terminal enrollment grant fence identity is invalid")
	}
	if expectedRevision == 0 {
		if expected.DescriptorSHA256 != "" || len(expected.Request) != 0 || len(expected.Response) != 0 ||
			expected.Disabled || expected.OwnerToken != "" || !expected.LeaseUntil.IsZero() ||
			len(expected.RenewalRequest) != 0 || len(expected.RenewalResponse) != 0 ||
			expected.RenewalToken != "" || !expected.RenewalLeaseUntil.IsZero() || expected.TerminalOperationID != "" {
			return Grant{}, 0, errors.New("absent terminal grant fence contains enrollment state")
		}
		tombstone := Grant{SchemaVersion: 1, InstanceID: expected.InstanceID,
			CreateKey: expected.CreateKey, Disabled: true, TerminalOperationID: operationID}
		wire, err := json.Marshal(tombstone)
		if err != nil {
			return Grant{}, 0, err
		}
		revision, err := store.kv.Create(ctx, grantKey(expected.InstanceID), wire)
		if err == nil {
			return tombstone, revision, nil
		}
		if !errors.Is(err, jetstream.ErrKeyExists) {
			return Grant{}, 0, fmt.Errorf("create terminal enrollment grant tombstone: %w", err)
		}
		current, revision, readErr := store.Read(ctx, expected.InstanceID)
		if readErr != nil {
			return Grant{}, 0, readErr
		}
		if isTerminalTombstone(current, expected.InstanceID, expected.CreateKey, operationID) {
			return current, revision, nil
		}
		return Grant{}, 0, ErrTerminalFenceConflict
	}
	if isTerminalTombstone(expected, expected.InstanceID, expected.CreateKey, operationID) {
		current, revision, err := store.Read(ctx, expected.InstanceID)
		if err != nil {
			return Grant{}, 0, err
		}
		if revision == expectedRevision && isTerminalTombstone(current, expected.InstanceID,
			expected.CreateKey, operationID) && sameGrant(current, expected) {
			return current, revision, nil
		}
		return Grant{}, 0, ErrTerminalFenceConflict
	}

	if len(expected.Request) == 0 || len(expected.DescriptorSHA256) != 64 ||
		expected.TerminalOperationID != "" && expected.TerminalOperationID != operationID {
		return Grant{}, 0, errors.New("existing terminal grant fence lacks exact grant pins")
	}
	current, revision, err := store.Read(ctx, expected.InstanceID)
	if err != nil {
		return Grant{}, 0, err
	}
	if isTerminalTombstone(current, expected.InstanceID, expected.CreateKey, operationID) {
		if current.DescriptorSHA256 == expected.DescriptorSHA256 && bytes.Equal(current.Request, expected.Request) {
			return current, revision, nil
		}
		return Grant{}, 0, ErrTerminalFenceConflict
	}
	if current.Disabled && current.TerminalOperationID == operationID &&
		current.InstanceID == expected.InstanceID && current.CreateKey == expected.CreateKey &&
		current.DescriptorSHA256 == expected.DescriptorSHA256 && bytes.Equal(current.Request, expected.Request) {
		return current, revision, nil
	}
	if revision != expectedRevision || !sameGrant(current, expected) {
		return Grant{}, 0, ErrTerminalFenceConflict
	}
	current.Disabled = true
	current.TerminalOperationID = operationID
	wire, err := json.Marshal(current)
	if err != nil {
		return Grant{}, 0, err
	}
	nextRevision, err := store.kv.Update(ctx, grantKey(expected.InstanceID), wire, expectedRevision)
	if err == nil {
		return current, nextRevision, nil
	}
	if !errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		return Grant{}, 0, fmt.Errorf("disable terminal enrollment grant: %w", err)
	}
	current, revision, readErr := store.Read(ctx, expected.InstanceID)
	if readErr != nil {
		return Grant{}, 0, readErr
	}
	if isTerminalTombstone(current, expected.InstanceID, expected.CreateKey, operationID) &&
		current.DescriptorSHA256 == expected.DescriptorSHA256 && bytes.Equal(current.Request, expected.Request) {
		return current, revision, nil
	}
	return Grant{}, 0, ErrTerminalFenceConflict
}

func isTerminalTombstone(grant Grant, instanceID, createKey, operationID string) bool {
	return grant.SchemaVersion == 1 && grant.InstanceID == instanceID && grant.CreateKey == createKey &&
		grant.Disabled && grant.TerminalOperationID == operationID && len(grant.Request) == 0 &&
		grant.DescriptorSHA256 == "" && len(grant.Response) == 0 && grant.OwnerToken == "" &&
		grant.LeaseUntil.IsZero() && len(grant.RenewalRequest) == 0 && len(grant.RenewalResponse) == 0 &&
		grant.RenewalToken == "" && grant.RenewalLeaseUntil.IsZero()
}

func sameGrant(left, right Grant) bool {
	return left.SchemaVersion == right.SchemaVersion && left.InstanceID == right.InstanceID &&
		left.CreateKey == right.CreateKey && left.DescriptorSHA256 == right.DescriptorSHA256 &&
		bytes.Equal(left.Request, right.Request) && bytes.Equal(left.Response, right.Response) &&
		left.Disabled == right.Disabled && left.OwnerToken == right.OwnerToken &&
		left.LeaseUntil.Equal(right.LeaseUntil) && bytes.Equal(left.RenewalRequest, right.RenewalRequest) &&
		bytes.Equal(left.RenewalResponse, right.RenewalResponse) && left.RenewalToken == right.RenewalToken &&
		left.RenewalLeaseUntil.Equal(right.RenewalLeaseUntil) &&
		left.TerminalOperationID == right.TerminalOperationID
}

func validTerminalOperationID(value string) bool { return entityid.Valid(value) }

// ClaimRenew serializes renewal and caches the exact signed response.
func (store *GrantStore) ClaimRenew(ctx context.Context, instanceID string, request []byte,
	now time.Time,
) (Grant, uint64, error) {
	if len(request) == 0 || len(request) > 16<<10 {
		return Grant{}, 0, mutationNotApplied(errors.New("host enrollment renewal request is invalid"))
	}
	grant, revision, err := store.Read(ctx, instanceID)
	if err != nil {
		return Grant{}, 0, mutationNotApplied(err)
	}
	if grant.Disabled || len(grant.Response) == 0 {
		return Grant{}, 0, mutationNotApplied(errors.New("host enrollment grant is disabled or incomplete"))
	}
	if bytes.Equal(grant.RenewalRequest, request) && len(grant.RenewalResponse) != 0 {
		return grant, revision, nil
	}
	if len(grant.RenewalRequest) != 0 && len(grant.RenewalResponse) == 0 && now.Before(grant.RenewalLeaseUntil) {
		return Grant{}, 0, mutationNotApplied(ErrGrantInProgress)
	}
	var previous Response
	if len(grant.RenewalResponse) != 0 {
		if json.Unmarshal(grant.RenewalResponse, &previous, json.RejectUnknownMembers(true)) != nil ||
			now.Before(previous.ExpiresAt.Add(-24*time.Hour)) {
			return Grant{}, 0, mutationNotApplied(errors.New("host enrollment renewal is not due"))
		}
	} else if len(grant.RenewalRequest) == 0 {
		if json.Unmarshal(grant.Response, &previous, json.RejectUnknownMembers(true)) != nil ||
			now.Before(previous.ExpiresAt.Add(-24*time.Hour)) {
			return Grant{}, 0, mutationNotApplied(errors.New("host enrollment renewal is not due"))
		}
	}
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return Grant{}, 0, mutationNotApplied(err)
	}
	grant.RenewalRequest = bytes.Clone(request)
	grant.RenewalResponse = nil
	grant.RenewalToken = base64.RawURLEncoding.EncodeToString(token)
	grant.RenewalLeaseUntil = now.Add(time.Minute)
	wire, err := json.Marshal(grant)
	if err != nil {
		return Grant{}, 0, mutationNotApplied(err)
	}
	next, err := store.kv.Update(ctx, grantKey(instanceID), wire, revision)
	if err != nil {
		wrapped := fmt.Errorf("claim host enrollment renewal: %w", err)
		if errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
			return Grant{}, 0, mutationNotApplied(wrapped)
		}
		return Grant{}, 0, wrapped
	}
	return grant, next, nil
}

func (store *GrantStore) FinishRenew(ctx context.Context, expected Grant, revision uint64,
	response []byte, now time.Time,
) error {
	if store == nil || store.kv == nil || revision == 0 || expected.Disabled ||
		expected.RenewalToken == "" || !now.Before(expected.RenewalLeaseUntil) ||
		len(expected.RenewalRequest) == 0 || len(expected.RenewalResponse) != 0 ||
		len(response) == 0 || len(response) > 32<<10 {
		return mutationNotApplied(errors.New("host enrollment renewal cannot be committed"))
	}
	expected.RenewalResponse = bytes.Clone(response)
	wire, err := json.Marshal(expected)
	if err != nil {
		return mutationNotApplied(err)
	}
	_, err = store.kv.Update(ctx, grantKey(expected.InstanceID), wire, revision)
	if errors.Is(err, jetstream.ErrKeyRevisionMismatch) {
		return mutationNotApplied(err)
	}
	return err
}

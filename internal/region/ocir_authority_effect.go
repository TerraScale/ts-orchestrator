package region

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/oracle/oci-go-sdk/v65/identity"
)

type ocirAuthorityJournal struct {
	resolver FoundationResolver
	cell     string
	writer   FoundationWriterRecord
	original OCIRAuthorityRecord
	guard    func(context.Context) error
	home     string
}

func (journal *ocirAuthorityJournal) read(ctx context.Context) (FoundationRecord, string, error) {
	if err := journal.guard(ctx); err != nil {
		return FoundationRecord{}, "", err
	}
	record, etag, err := journal.resolver.Store.Load(ctx, journal.cell)
	if err != nil {
		return FoundationRecord{}, "", err
	}
	if !sameFoundationWriterOriginal(&journal.writer, record.FoundationWriter) || record.FoundationWriter.OCIRAuthority == nil || !sameOCIRAuthorityOrigin(journal.original, *record.FoundationWriter.OCIRAuthority) || record.FoundationWriter.OCIRAuthority.validate(*record.FoundationWriter) != nil {
		return FoundationRecord{}, "", ErrFoundationFenced
	}
	return record, etag, nil
}

func (journal *ocirAuthorityJournal) update(ctx context.Context, apply func(*OCIRAuthorityRecord) error) error {
	record, etag, err := journal.read(ctx)
	if err != nil {
		return err
	}
	writer := *record.FoundationWriter
	reservation := *writer.OCIRAuthority
	reservation.Policies = slices.Clone(reservation.Policies)
	for index := range reservation.Policies {
		reservation.Policies[index].Dispatches = slices.Clone(reservation.Policies[index].Dispatches)
	}
	if err := apply(&reservation); err != nil {
		return err
	}
	writer.OCIRAuthority = &reservation
	record.FoundationWriter = &writer
	record.UpdatedAt = time.Now().UTC()
	if err := journal.guard(ctx); err != nil {
		return err
	}
	// The existing protected object write must not recursively journal itself.
	ctx = ociclient.WithWireAttempt(ctx, func(*http.Request) (func(*http.Response, error, bool) error, error) {
		return func(*http.Response, error, bool) error { return nil }, nil
	})
	_, err = journal.resolver.Store.CompareAndSwap(ctx, record, etag)
	return err
}

func (journal *ocirAuthorityJournal) begin(index int) func(*http.Request) (func(*http.Response, error, bool) error, error) {
	return func(request *http.Request) (func(*http.Response, error, bool) error, error) {
		ctx := request.Context()
		if index < 0 || index >= len(journal.original.Policies) || request.Method != http.MethodPost || request.URL == nil || request.URL.String() != "https://identity."+journal.home+".oci.oraclecloud.com/20160918/policies" || request.Header.Get("if-match") != "" || request.Header.Get("opc-retry-token") != journal.original.Policies[index].RetryToken || request.Body == nil {
			return nil, ErrFoundationFenced
		}
		wire, err := io.ReadAll(io.LimitReader(request.Body, ocirAuthorityLimit+1))
		closeErr := request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(wire))
		if err != nil || closeErr != nil || len(wire) > ocirAuthorityLimit {
			return nil, ErrFoundationFenced
		}
		var object map[string]any
		if err := json.Unmarshal(wire, &object); err != nil {
			return nil, err
		}
		canonical, err := json.Marshal(object, json.Deterministic(true))
		if err != nil || digestSource(canonical) != journal.original.Policies[index].RequestDigest {
			return nil, ErrFoundationFenced
		}
		dispatch := OCIRAuthorityDispatch{OCIRIssuerDispatch: OCIRIssuerDispatch{StartedAt: time.Now().UTC()}}
		position := 0
		if err := journal.update(ctx, func(saved *OCIRAuthorityRecord) error {
			policy := &saved.Policies[index]
			if policy.PolicyID != "" || len(policy.Dispatches) >= 16 {
				return ErrFoundationFenced
			}
			for _, previous := range policy.Dispatches {
				if previous.ObservedID != "" {
					return ErrFoundationFenced
				}
			}
			position = len(policy.Dispatches)
			policy.Dispatches = append(policy.Dispatches, dispatch)
			return nil
		}); err != nil {
			return nil, err
		}
		if err := journal.guard(ctx); err != nil {
			return nil, err
		}
		if err := ociclient.LimitAdmission(ctx, journal.original.DispatchExpiresAt); err != nil {
			return nil, err
		}
		return func(response *http.Response, _ error, sent bool) error {
			finished := dispatch
			finished.Sent, finished.FinishedAt = sent, time.Now().UTC()
			if response != nil {
				finished.Status = response.StatusCode
				if sent && (response.StatusCode == 200 || response.StatusCode == 201) && response.Body != nil {
					wire, err := io.ReadAll(io.LimitReader(response.Body, ocirAuthorityLimit+1))
					closeErr := response.Body.Close()
					response.Body = io.NopCloser(bytes.NewReader(wire))
					if err != nil || closeErr != nil || len(wire) > ocirAuthorityLimit {
						return ErrFoundationFenced
					}
					var observed identity.Policy
					policy := journal.original.Policies[index]
					if err := json.Unmarshal(wire, &observed); err != nil || observed.Id == nil || !validAuxiliaryID("controller_usage_policy", *observed.Id, "") || !matchesOCIRAuthorityPolicy(policy.Request, observed) {
						return ErrFoundationFenced
					}
					finished.ObservedID = *observed.Id
				}
			}
			return journal.update(ctx, func(saved *OCIRAuthorityRecord) error {
				policy := &saved.Policies[index]
				if len(policy.Dispatches) != position+1 || policy.Dispatches[position] != dispatch {
					return ErrFoundationFenced
				}
				policy.Dispatches[position] = finished
				return nil
			})
		}, nil
	}
}

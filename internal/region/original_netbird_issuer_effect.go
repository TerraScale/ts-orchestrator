package region

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"io"
	"maps"
	"net/http"
	"reflect"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

// BeginEffect retains public request metadata and hashes before dispatch. The
// once-returned credential body remains in memory and never enters the journal.
func (s *OriginalNetBirdIssuerJournal) BeginEffect(request *http.Request) (func(*http.Response, error, bool) error, error) {
	if s == nil || request == nil || request.URL == nil {
		return nil, ErrOriginalSourceProducerHold
	}
	ctx := request.Context()
	key, err := s.scope.JournalKey()
	if err != nil {
		return nil, err
	}
	record, etag, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	entry, ok := originalNetBirdIssuances(record)[key]
	if !ok {
		return nil, ErrOriginalSourceProducerHold
	}
	var body []byte
	if request.Body != nil {
		body, err = io.ReadAll(io.LimitReader(request.Body, (64<<10)+1))
		closeErr := request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(body))
		if err != nil || closeErr != nil || len(body) > 64<<10 {
			return nil, ErrOriginalSourceProducerHold
		}
	}
	digest := sha256.Sum256(body)
	attempt := OCIRIssuerRequest{Method: request.Method, URL: request.URL.String(), BodySHA256: hex.EncodeToString(digest[:]), IfMatch: request.Header.Get("if-match"), RetryToken: request.Header.Get("opc-retry-token")}
	identity, err := json.Marshal(attempt, json.Deterministic(true))
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(identity)
	id := hex.EncodeToString(hash[:])
	previous, found := entry.Requests[id]
	if found {
		attempt = previous
	} else {
		deadline, ok := ctx.Deadline()
		if !ok {
			return nil, ErrOriginalSourceProducerHold
		}
		attempt.FirstAttemptAt = time.Now().UTC()
		attempt.Deadline = s.session.deadline
		if entry.Origin.ExpiresAt.Before(attempt.Deadline) {
			attempt.Deadline = entry.Origin.ExpiresAt
		}
		if deadline.Before(attempt.Deadline) {
			attempt.Deadline = deadline.UTC()
		}
		attempt.GrantSHA256 = s.scope.GrantDigest()
		attempt.Epoch = record.Epoch
		attempt.LeaseID = entry.State.LeaseID
	}
	if !time.Now().Before(attempt.Deadline) || len(attempt.Dispatches) >= 16 {
		return nil, ErrOriginalSourceProducerHold
	}
	attempt.Dispatches = append(slices.Clone(attempt.Dispatches), OCIRIssuerDispatch{StartedAt: time.Now().UTC()})
	entry.Requests = maps.Clone(entry.Requests)
	if entry.Requests == nil {
		entry.Requests = map[string]OCIRIssuerRequest{}
	}
	entry.Requests[id] = attempt
	manager := record.OriginalFoundationCompartments.Regions[0].NetBirdManager
	manager.OCIRIssuances = maps.Clone(manager.OCIRIssuances)
	manager.OCIRIssuances[key] = entry
	if err := s.write(ctx, record, etag); err != nil {
		return nil, err
	}
	if !time.Now().Before(attempt.Deadline) {
		return nil, ErrOriginalSourceProducerHold
	}
	if err := ociclient.LimitAdmission(request.Context(), attempt.Deadline); err != nil {
		return nil, err
	}
	return func(response *http.Response, _ error, sent bool) error {
		current, currentETag, err := s.read(ctx)
		if err != nil {
			return err
		}
		actual := originalNetBirdIssuances(current)[key]
		original, ok := actual.Requests[id]
		if !ok || !reflect.DeepEqual(original, attempt) {
			return ErrOriginalSourceProducerHold
		}
		original.Dispatches = slices.Clone(original.Dispatches)
		dispatch := &original.Dispatches[len(original.Dispatches)-1]
		dispatch.Sent = sent
		dispatch.FinishedAt = time.Now().UTC()
		if response != nil {
			dispatch.Status = response.StatusCode
		}
		actual.Requests = maps.Clone(actual.Requests)
		actual.Requests[id] = original
		manager := current.OriginalFoundationCompartments.Regions[0].NetBirdManager
		manager.OCIRIssuances = maps.Clone(manager.OCIRIssuances)
		manager.OCIRIssuances[key] = actual
		return s.write(ctx, current, currentETag)
	}, nil
}

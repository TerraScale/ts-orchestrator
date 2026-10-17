package rootfoundation

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
	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// BeginEffect checkpoints only hashes and public request metadata. Credential
// request bodies stay in root memory and never enter the protected journal.
func (s *ocirJournal) BeginEffect(request *http.Request) (func(*http.Response, error, bool) error, error) {
	ctx := request.Context()
	key, err := s.scope.JournalKey()
	if err != nil {
		return nil, err
	}
	record, etag, err := s.read(ctx)
	if err != nil {
		return nil, err
	}
	entry, ok := record.OCIRIssuances[key]
	if !ok {
		return nil, ErrScope
	}
	var body []byte
	if request.Body != nil {
		body, err = io.ReadAll(io.LimitReader(request.Body, (64<<10)+1))
		closeErr := request.Body.Close()
		request.Body = io.NopCloser(bytes.NewReader(body))
		if err != nil || closeErr != nil || len(body) > 64<<10 {
			return nil, ErrScope
		}
	}
	digest := sha256.Sum256(body)
	attempt := region.OCIRIssuerRequest{Method: request.Method, URL: request.URL.String(), BodySHA256: hex.EncodeToString(digest[:]), IfMatch: request.Header.Get("if-match"), RetryToken: request.Header.Get("opc-retry-token")}
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
			return nil, ErrScope
		}
		attempt.FirstAttemptAt = time.Now().UTC()
		attempt.Deadline = minTime(deadline, s.deadline).UTC()
		attempt.GrantSHA256 = s.scope.GrantDigest()
		attempt.Epoch = s.original.Epoch
		attempt.LeaseID = entry.State.LeaseID
	}
	if !time.Now().Before(attempt.Deadline) {
		return nil, ErrScope
	}
	if len(attempt.Dispatches) >= 16 {
		return nil, ErrScope
	}
	attempt.Dispatches = append(slices.Clone(attempt.Dispatches), region.OCIRIssuerDispatch{StartedAt: time.Now().UTC()})
	entry.Requests = maps.Clone(entry.Requests)
	if entry.Requests == nil {
		entry.Requests = map[string]region.OCIRIssuerRequest{}
	}
	entry.Requests[id] = attempt
	record.OCIRIssuances[key] = entry
	// The underlying ObjectStore validates the whole unchanged128KiB record.
	ctx = ociclient.WithAuthority(ctx, s.guard)
	ctx = ociclient.WithWireAttempt(ctx, func(*http.Request) (func(*http.Response, error, bool) error, error) {
		return func(*http.Response, error, bool) error { return nil }, nil
	})
	if _, err := s.store.CompareAndSwap(ctx, record, etag); err != nil {
		return nil, err
	}
	if err := s.guard(ctx); err != nil {
		return nil, err
	}
	if !time.Now().Before(attempt.Deadline) {
		return nil, ErrScope
	}
	if err := ociclient.LimitAdmission(request.Context(), attempt.Deadline); err != nil {
		return nil, err
	}
	return func(response *http.Response, _ error, sent bool) error {
		current, currentETag, err := s.read(ctx)
		if err != nil {
			return err
		}
		actual := current.OCIRIssuances[key]
		original, ok := actual.Requests[id]
		if !ok || !reflect.DeepEqual(original, attempt) {
			return ErrScope
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
		current.OCIRIssuances[key] = actual
		_, err = s.store.CompareAndSwap(ctx, current, currentETag)
		return err
	}, nil
}

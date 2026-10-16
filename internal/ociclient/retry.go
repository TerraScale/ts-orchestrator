package ociclient

import (
	"context"
	"errors"
	"io"
	"math"
	"math/rand/v2"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/oracle/oci-go-sdk/v65/common"
)

// ReadContext keeps the SDK retry goroutine joined while the original context
// still cancels the actual GET/HEAD request and backoff.
func ReadContext(ctx context.Context) context.Context {
	return context.WithValue(context.WithoutCancel(ctx), readContextKey{}, ctx)
}

type readContextKey struct{}

func originalReadContext(ctx context.Context) context.Context {
	original, _ := ctx.Value(readContextKey{}).(context.Context)
	return original
}

// ConfigureReadCancellation must run after other interceptors are installed.
// It avoids the SDK Retry response race when ReadContext cancels a wire request.
func ConfigureReadCancellation(client *common.BaseClient) {
	if readCancellationConfigured(client.HTTPClient) {
		return
	}
	previous := client.Interceptor
	client.Interceptor = func(request *http.Request) error {
		if original := originalReadContext(request.Context()); original != nil {
			if request.Method != http.MethodGet && request.Method != http.MethodHead {
				return errors.New("OCI ReadContext only permits GET and HEAD")
			}
			*request = *request.WithContext(context.WithValue(original, readContextKey{}, original))
		}
		if previous != nil {
			return previous(request)
		}
		return request.Context().Err()
	}
	client.HTTPClient = readDispatcher{next: client.HTTPClient}
}

func readCancellationConfigured(dispatcher common.HTTPRequestDispatcher) bool {
	switch dispatcher := dispatcher.(type) {
	case readDispatcher:
		return true
	case *instrumentedDispatcher:
		return readCancellationConfigured(dispatcher.next)
	default:
		return false
	}
}

type readDispatcher struct{ next common.HTTPRequestDispatcher }

type readTransportError struct {
	err error
	ctx context.Context
}

func (e *readTransportError) Error() string { return e.err.Error() }
func (e *readTransportError) Unwrap() error { return e.err }

func (d readDispatcher) Do(request *http.Request) (*http.Response, error) {
	response, err := d.next.Do(request)
	if original := originalReadContext(request.Context()); original != nil && err != nil {
		return response, &readTransportError{err: err, ctx: original}
	}
	return response, err
}

func readOperationContext(response common.OCIOperationResponse) context.Context {
	if failure, ok := errors.AsType[*readTransportError](response.Error); ok {
		return failure.ctx
	}
	if response.Response != nil {
		if raw := response.Response.HTTPResponse(); raw != nil && raw.Request != nil {
			return originalReadContext(raw.Request.Context())
		}
	}
	return nil
}

func retryDelay(options RetryOptions, response common.OCIOperationResponse) time.Duration {
	delay := nextDelay(options, response)
	if ctx := readOperationContext(response); ctx != nil {
		timer := time.NewTimer(delay)
		defer timer.Stop()
		select {
		case <-ctx.Done():
		case <-timer.C:
		}
		// The SDK's own time.After cannot be canceled, so wait here instead.
		return 0
	}
	return delay
}

// RetryOptions bounds the shared 429/5xx-aware retry policy.
type RetryOptions struct {
	// MaxAttempts includes the first attempt. Zero selects the default.
	MaxAttempts uint
	// BaseDelay is the first backoff step before jitter. Zero selects the default.
	BaseDelay time.Duration
	// MaxDelay caps one backoff step, including a server Retry-After hint.
	MaxDelay time.Duration
	// Jitter returns a value in [0, 1). Nil uses math/rand/v2.
	Jitter func() float64
}

const (
	defaultMaxAttempts = 6
	defaultBaseDelay   = 500 * time.Millisecond
	defaultMaxDelay    = 30 * time.Second
)

func (o RetryOptions) normalized() RetryOptions {
	if o.MaxAttempts == 0 {
		o.MaxAttempts = defaultMaxAttempts
	}
	if o.BaseDelay <= 0 {
		o.BaseDelay = defaultBaseDelay
	}
	if o.MaxDelay <= 0 {
		o.MaxDelay = defaultMaxDelay
	}
	if o.MaxDelay < o.BaseDelay {
		o.MaxDelay = o.BaseDelay
	}
	if o.Jitter == nil {
		o.Jitter = rand.Float64
	}
	return o
}

// RetryPolicy returns the SDK retry policy shared by every TerraScale OCI
// caller. It never widens the effect of a mutation:
//
//   - 429 TooManyRequests is retried for every method, because OCI rejected
//     the request before acting on it.
//   - 5xx (except 501) and transport errors are retried only for reads (GET,
//     HEAD) and for POSTs that carry an opc-retry-token, which OCI
//     deduplicates. PUT and DELETE are not retried on 5xx because the first
//     attempt may have taken effect and callers classify that outcome
//     themselves (ETags, journals, exact-target teardown).
//
// Backoff is exponential with equal jitter and honors a Retry-After hint up to
// MaxDelay.
func RetryPolicy(options RetryOptions) common.RetryPolicy {
	options = options.normalized()
	return common.NewRetryPolicy(options.MaxAttempts, ShouldRetry, func(response common.OCIOperationResponse) time.Duration {
		return retryDelay(options, response)
	})
}

// IdempotentPutRetryPolicy is RetryPolicy that also replays PUT on 5xx. Use
// it only for request-level policies on writes the caller has made idempotent,
// such as content-addressed multipart part uploads whose commit refuses to
// overwrite (If-None-Match: *).
func IdempotentPutRetryPolicy(options RetryOptions) common.RetryPolicy {
	options = options.normalized()
	return common.NewRetryPolicy(options.MaxAttempts, func(response common.OCIOperationResponse) bool {
		return shouldRetry(response, func(request *http.Request) bool {
			return (request != nil && request.Method == http.MethodPut) || replayable(request)
		})
	}, func(response common.OCIOperationResponse) time.Duration {
		return retryDelay(options, response)
	})
}

// ShouldRetry classifies one attempt under the policy documented on RetryPolicy.
func ShouldRetry(response common.OCIOperationResponse) bool {
	return shouldRetry(response, replayable)
}

func shouldRetry(response common.OCIOperationResponse, replayable func(*http.Request) bool) bool {
	if ctx := readOperationContext(response); ctx != nil && ctx.Err() != nil {
		return false
	}
	status, request := responseStatus(response)
	if response.Error == nil {
		return false
	}
	if status == 0 {
		if serviceErr, ok := common.IsServiceError(response.Error); ok {
			status = serviceErr.GetHTTPStatusCode()
		}
	}
	if status == http.StatusTooManyRequests {
		return true
	}
	if !replayable(request) {
		return false
	}
	if status >= 500 && status != http.StatusNotImplemented && status < 600 {
		return true
	}
	if status == 0 {
		cause := response.Error
		for {
			failure, ok := errors.AsType[*readTransportError](cause)
			if !ok {
				break
			}
			cause = failure.err
		}
		return common.IsNetworkError(cause) || errors.Is(cause, io.EOF) ||
			errors.Is(cause, io.ErrUnexpectedEOF)
	}
	return false
}

func responseStatus(response common.OCIOperationResponse) (int, *http.Request) {
	var raw *http.Response
	if response.Response != nil {
		raw = response.Response.HTTPResponse()
	}
	if raw != nil {
		return raw.StatusCode, raw.Request
	}
	return 0, transportRequest(response.Error)
}

// transportRequest recovers the method of an attempt that failed before any
// HTTP response existed. The SDK then leaves the raw response nil, but
// net/http reports the method in the *url.Error it returns. The synthetic
// request carries only the method, so a POST is never treated as carrying a
// retry token and stays non-replayable.
func transportRequest(err error) *http.Request {
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return nil
	}
	method := strings.ToUpper(strings.TrimSpace(urlErr.Op))
	if method == "" {
		return nil
	}
	return &http.Request{Method: method, Header: http.Header{}}
}

// replayable reports whether repeating request cannot duplicate an effect.
// An unknown request is not replayable.
func replayable(request *http.Request) bool {
	if request == nil {
		return false
	}
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		return true
	case http.MethodPost:
		return strings.TrimSpace(request.Header.Get("opc-retry-token")) != ""
	default:
		return false
	}
}

func nextDelay(options RetryOptions, response common.OCIOperationResponse) time.Duration {
	attempt := max(response.AttemptNumber, 1)
	step := float64(options.BaseDelay) * math.Pow(2, float64(attempt-1))
	step = min(step, float64(options.MaxDelay))
	// Equal jitter (uniform in [step/2, step)) keeps a fleet of controllers
	// from retrying in lockstep without near-zero delays.
	delay := time.Duration(step/2 + options.Jitter()*step/2)
	if hint := retryAfter(response); hint > delay {
		delay = hint
	}
	return min(delay, options.MaxDelay)
}

func retryAfter(response common.OCIOperationResponse) time.Duration {
	if response.Response == nil || response.Response.HTTPResponse() == nil {
		return 0
	}
	value := strings.TrimSpace(response.Response.HTTPResponse().Header.Get("Retry-After"))
	if value == "" {
		return 0
	}
	if seconds, err := strconv.Atoi(value); err == nil && seconds > 0 {
		return time.Duration(seconds) * time.Second
	}
	if at, err := http.ParseTime(value); err == nil {
		return max(time.Until(at), 0)
	}
	return 0
}

// MutationRejected recognizes documented no-effect errors without a
// conflicting HTTP response. Callers must also exclude accepted instance IDs
// and any earlier ambiguous attempts before treating a generation as rejected.
func MutationRejected(err error, raw *http.Response) bool {
	failure, ok := common.IsServiceError(err)
	if !ok || raw != nil && raw.StatusCode != failure.GetHTTPStatusCode() {
		return false
	}
	switch failure.GetHTTPStatusCode() {
	case http.StatusBadRequest:
		switch failure.GetCode() {
		case "CannotParseRequest", "InvalidParameter", "MissingParameter", "LimitExceeded", "QuotaExceeded":
			return true
		}
	case http.StatusUnauthorized:
		return failure.GetCode() == "NotAuthenticated"
	case http.StatusForbidden:
		return failure.GetCode() == "NotAuthorized"
	case http.StatusNotFound:
		return failure.GetCode() == "NotAuthorizedOrNotFound" || failure.GetCode() == "InvalidParameter"
	case http.StatusConflict:
		return failure.GetCode() == "IncorrectState"
	case http.StatusTooManyRequests:
		return failure.GetCode() == "TooManyRequests"
	}
	return false
}

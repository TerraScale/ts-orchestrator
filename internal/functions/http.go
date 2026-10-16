package functions

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
)

// Authorizer authenticates the caller and returns its trusted tenant identity.
// Implementations must verify credentials rather than copy a tenant header.
type Authorizer func(*http.Request) (string, error)

// NewHTTPHandler binds one admitted revision. Only the bounded body reaches the
// guest; credentials, headers, URLs and host environment never enter its input.
func NewHTTPHandler(worker Invoker, authorize Authorizer) (http.Handler, error) {
	if worker == nil || authorize == nil {
		return nil, fmt.Errorf("%w: worker and authorizer required", ErrInvalid)
	}
	manifest := worker.Manifest()
	if err := manifest.Validate(); err != nil {
		return nil, err
	}
	slots := make(chan struct{}, MaxConcurrent)
	mux := http.NewServeMux()
	mux.HandleFunc("POST /", func(w http.ResponseWriter, r *http.Request) {
		select {
		case slots <- struct{}{}:
			defer func() { <-slots }()
		default:
			http.Error(w, "function worker busy", http.StatusServiceUnavailable)
			return
		}
		tenant, err := authorize(r)
		if err != nil || tenant == "" {
			http.Error(w, "authentication required", http.StatusUnauthorized)
			return
		}
		if tenant != manifest.TenantID {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		invocation := Invocation{TenantID: tenant, FunctionID: manifest.FunctionID, Revision: manifest.Revision,
			ID: r.Header.Get("Idempotency-Key"), Trigger: "http"}
		if err := invocation.Validate(manifest); err != nil {
			http.Error(w, "invalid invocation", http.StatusBadRequest)
			return
		}
		invocation.Payload, err = io.ReadAll(http.MaxBytesReader(w, r.Body, MaxPayloadBytes))
		if err != nil {
			status := http.StatusBadRequest
			if _, ok := errors.AsType[*http.MaxBytesError](err); ok {
				status = http.StatusRequestEntityTooLarge
			}
			http.Error(w, "invalid request body", status)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), InvocationTimeout)
		defer cancel()
		result, err := worker.Invoke(ctx, invocation)
		if err != nil {
			status := http.StatusBadGateway
			switch {
			case errors.Is(err, ErrScope):
				status = http.StatusForbidden
			case errors.Is(err, ErrInvalid):
				status = http.StatusBadRequest
			case errors.Is(err, ErrBusy), errors.Is(err, ErrClosed):
				status = http.StatusServiceUnavailable
			case errors.Is(err, context.DeadlineExceeded):
				status = http.StatusGatewayTimeout
			case errors.Is(err, context.Canceled):
				status = http.StatusRequestTimeout
			}
			http.Error(w, "function invocation failed", status)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Cache-Control", "no-store")
		_, _ = w.Write(result.Output)
	})
	return mux, nil
}

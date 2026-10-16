package nodescale

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func (o *OCIPool) poolWireContext(ctx context.Context, recipe Recipe, kind string) context.Context {
	var originalStarted time.Time
	var originalErr error
	switch kind {
	case oci.PoolCreateConfiguration, oci.PoolCreatePool:
		request, _, err := o.Journal.GetPoolCreateRequest(ctx, o.operationID, kind)
		originalStarted, originalErr = request.StartedAt, err
	case oci.PoolWirePoint:
		request, _, err := o.Journal.GetPoolPointRequest(ctx, o.operationID)
		originalStarted, originalErr = request.Request.StartedAt, err
	case oci.PoolWireGrowth:
		request, _, err := o.Journal.GetCapacityRequest(ctx, o.operationID)
		originalStarted, originalErr = request.StartedAt, err
	}
	ctx = ociclient.WithWireAttempt(ctx, func(request *http.Request) (func(*http.Response, error, bool) error, error) {
		if o.Journal == nil {
			return nil, errors.New("pool wire attempt requires durable journal")
		}
		if request.Body == nil {
			return nil, errors.New("pool SDK payload is unavailable")
		}
		body := request.Body
		wire, readErr := io.ReadAll(body)
		// The SDK hides seeking after signing; preserve current bytes and its original GetBody.
		request.Body = io.NopCloser(bytes.NewReader(wire))
		if err := errors.Join(readErr, body.Close()); err != nil {
			return nil, err
		}
		canonical := request.Clone(request.Context())
		canonical.URL.Path = strings.TrimPrefix(canonical.URL.Path, "/20160918")
		canonical.URL.RawPath = ""
		canonical.Body = io.NopCloser(bytes.NewReader(wire))
		digest, err := poolCreateRequestSHA256(canonical)
		if err != nil {
			return nil, err
		}
		attempt := oci.PoolWireAttempt{OperationID: o.operationID, Kind: kind, AttemptID: entityid.New(), RequestSHA256: digest, StartedAt: time.Now().UTC()}
		if err := o.Journal.RecordPoolWireAttempt(request.Context(), attempt); err != nil {
			return nil, err
		}
		return func(response *http.Response, dispatchErr error, sent bool) error {
			outcome := oci.PoolWireOutcome{OperationID: attempt.OperationID, Kind: kind, AttemptID: attempt.AttemptID, TransportError: dispatchErr != nil, NotSent: !sent}
			if response != nil {
				outcome.StatusCode, outcome.OpcRequestID = response.StatusCode, response.Header.Get("opc-request-id")
			}
			return o.Journal.RecordPoolWireOutcome(request.Context(), outcome)
		}, nil
	})
	return ociclient.RequestContext(ociclient.WithAdmission(ctx, func(ctx context.Context) (func(), error) {
		if originalErr != nil || originalStarted.IsZero() {
			return nil, errors.Join(originalErr, errors.New("original pool wire request is unavailable"))
		}
		release, err := o.admit(ctx, recipe)
		if err != nil {
			return nil, err
		}
		if time.Since(originalStarted) >= 23*time.Hour {
			release()
			return nil, errors.New("original pool wire retry window expired before dispatch")
		}
		return release, nil
	}))
}

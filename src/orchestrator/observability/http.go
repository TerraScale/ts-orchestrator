package observability

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// EncodedBatch is the wire payload produced by a protocol-specific encoder.
// Metrics encoders normally return protobuf plus snappy compression for
// Prometheus remote-write; logs encoders normally return OTLP protobuf/JSON.
type EncodedBatch struct {
	Body            []byte
	ContentType     string
	ContentEncoding string
}

// BatchEncoder is deliberately injected: this package owns bounds, routing,
// credentials, and cancellation, while protocol libraries can be selected by
// the composition root without making this boundary perform live calls.
type BatchEncoder func(batch Batch) (EncodedBatch, error)

// HTTPTransport is an injected-client Grafana Cloud transport. Constructing it
// performs no I/O; SendBatch is the only method that can issue a request.
type HTTPTransport struct {
	metricsEndpoint *url.URL
	logsEndpoint    *url.URL
	credentials     Credentials
	client          *http.Client
	metricsEncoder  BatchEncoder
	logsEncoder     BatchEncoder
}

// NewHTTPTransport validates configuration and builds an HTTP boundary. The
// client and encoders are injectable for tests and future protocol adapters.
func NewHTTPTransport(config Config, client *http.Client, metricsEncoder, logsEncoder BatchEncoder) (*HTTPTransport, error) {
	if err := ValidateConfig(config); err != nil {
		return nil, err
	}
	if metricsEncoder == nil || logsEncoder == nil {
		return nil, errors.New("metrics and logs batch encoders are required")
	}
	metricsEndpoint, err := url.Parse(config.MetricsEndpoint)
	if err != nil {
		return nil, errors.New("parse metrics endpoint")
	}
	logsEndpoint, err := url.Parse(config.LogsEndpoint)
	if err != nil {
		return nil, errors.New("parse logs endpoint")
	}
	if client == nil {
		client = &http.Client{CheckRedirect: rejectRedirect}
	} else if client.CheckRedirect == nil {
		// Do not let a Grafana endpoint redirect telemetry to an unvalidated
		// destination. Preserve the caller's transport and timeout settings.
		copyOfClient := *client
		copyOfClient.CheckRedirect = rejectRedirect
		client = &copyOfClient
	}
	return &HTTPTransport{
		metricsEndpoint: metricsEndpoint,
		logsEndpoint:    logsEndpoint,
		credentials:     config.Credentials,
		client:          client,
		metricsEncoder:  metricsEncoder,
		logsEncoder:     logsEncoder,
	}, nil
}

// SendBatch sends one already-bounded batch to its configured endpoint. Error
// responses intentionally omit the response body, which may contain a token
// or provider-specific diagnostic.
func (t *HTTPTransport) SendBatch(ctx context.Context, batch Batch) error {
	if t == nil {
		return errors.New("nil observability transport")
	}
	if ctx == nil {
		return errors.New("transport context must not be nil")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := batch.validate(); err != nil {
		return err
	}
	var endpoint *url.URL
	var encoder BatchEncoder
	switch batch.Signal {
	case SignalMetrics:
		endpoint, encoder = t.metricsEndpoint, t.metricsEncoder
	case SignalLogs:
		endpoint, encoder = t.logsEndpoint, t.logsEncoder
	default:
		return fmt.Errorf("unsupported telemetry signal %d", batch.Signal)
	}
	encoded, err := encoder(batch)
	if err != nil {
		return fmt.Errorf("encode %s telemetry: %w", batch.Signal, err)
	}
	if len(encoded.Body) == 0 || len(encoded.Body) > 16*1024*1024 {
		return errors.New("encoded telemetry batch must contain 1..16 MiB")
	}
	if !validContentType(encoded.ContentType) || !validContentEncoding(encoded.ContentEncoding) {
		return errors.New("encoded telemetry batch has invalid content headers")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.String(), bytes.NewReader(encoded.Body))
	if err != nil {
		return errors.New("build Grafana telemetry request")
	}
	request.Header.Set("Content-Type", encoded.ContentType)
	if encoded.ContentEncoding != "" {
		request.Header.Set("Content-Encoding", encoded.ContentEncoding)
	}
	request.SetBasicAuth(t.credentials.Username, t.credentials.APIKey)
	response, err := t.client.Do(request)
	if err != nil {
		return fmt.Errorf("send %s telemetry: %w", batch.Signal, err)
	}
	defer response.Body.Close()
	_, _ = io.CopyN(io.Discard, response.Body, 4096)
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return fmt.Errorf("Grafana %s telemetry returned HTTP %d", batch.Signal, response.StatusCode)
	}
	return nil
}

func rejectRedirect(*http.Request, []*http.Request) error {
	return http.ErrUseLastResponse
}

func validContentType(value string) bool {
	return value != "" && len(value) <= 128 && !strings.ContainsAny(value, "\r\n")
}

func validContentEncoding(value string) bool {
	return len(value) <= 32 && !strings.ContainsAny(value, "\r\n")
}

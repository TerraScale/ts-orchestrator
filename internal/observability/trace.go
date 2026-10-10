package observability

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"regexp"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/nats-io/nats.go"
	"github.com/oklog/ulid/v2"
)

const (
	// TraceIDKey is the record attribute that carries a trace's ID.
	TraceIDKey = "trace_id"
	// traceparentHeader is the W3C trace context header on HTTP and NATS.
	traceparentHeader = "traceparent"
)

type traceKey struct{}

// traceparentPattern accepts only the version 00 layout with lowercase hex
// fields. Zero IDs are rejected separately, because the W3C spec forbids them.
var traceparentPattern = regexp.MustCompile(`^00-([0-9a-f]{32})-([0-9a-f]{16})-[0-9a-f]{2}$`)

// StartTrace starts a new trace under ctx. The 16 bytes of a ULID make the
// trace ID, so IDs sort by time and are valid W3C trace IDs.
func StartTrace(ctx context.Context) context.Context {
	id := ulid.MustParse(entityid.New())
	return context.WithValue(ctx, traceKey{}, hex.EncodeToString(id[:]))
}

// ContinueTrace reuses the trace of a valid traceparent and starts a new trace
// otherwise.
func ContinueTrace(ctx context.Context, traceparent string) context.Context {
	match := traceparentPattern.FindStringSubmatch(traceparent)
	if match == nil || strings.Trim(match[1], "0") == "" || strings.Trim(match[2], "0") == "" {
		return StartTrace(ctx)
	}
	return context.WithValue(ctx, traceKey{}, match[1])
}

// TraceID returns the 32-character trace ID of ctx, or "" when it has none.
func TraceID(ctx context.Context) string {
	trace, _ := ctx.Value(traceKey{}).(string)
	return trace
}

// Traceparent renders the trace of ctx as a traceparent with a new random span
// ID, or "" when ctx has no trace.
func Traceparent(ctx context.Context) string {
	trace := TraceID(ctx)
	if trace == "" {
		return ""
	}
	var span [8]byte
	for span == [8]byte{} {
		_, _ = rand.Read(span[:])
	}
	return "00-" + trace + "-" + hex.EncodeToString(span[:]) + "-01"
}

// TraceHeader sets the traceparent of ctx on header, allocating it when nil.
// A context without a trace returns header unchanged.
func TraceHeader(ctx context.Context, header nats.Header) nats.Header {
	traceparent := Traceparent(ctx)
	if traceparent == "" {
		return header
	}
	if header == nil {
		header = nats.Header{}
	}
	header.Set(traceparentHeader, traceparent)
	return header
}

// TraceHTTP continues the trace of each request, or starts one, and answers
// with the traceparent so the caller can find the server's records.
func TraceHTTP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		ctx := ContinueTrace(request.Context(), request.Header.Get(traceparentHeader))
		writer.Header().Set(traceparentHeader, Traceparent(ctx))
		next.ServeHTTP(writer, request.WithContext(ctx))
	})
}

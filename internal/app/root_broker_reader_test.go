package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

func TestRootBrokerReaderAcceptsOnlyExpectedResponse(t *testing.T) {
	for _, test := range []struct {
		operation rootBrokerOperation
		wire      string
	}{
		{rootBrokerCluster, `{"cluster":{"observation":{"Running":true},"quorum_ready":true,"full_ready":true}}`},
		{rootBrokerMeta, `{"meta":{"Self":"broker-a"}}`},
		{rootBrokerMetrics, `{"metrics":{}}`},
		{rootBrokerStore, `{"store":0}`},
		{rootBrokerStreams, `{"streams":[]}`},
		{rootBrokerAccount, `{"account":{"Account":"public-account","JWT":"public-jwt","Operator":{}}}`},
	} {
		t.Run(string(test.operation), func(t *testing.T) {
			if _, err := decodeRootBrokerResponse([]byte(test.wire), test.operation); err != nil {
				t.Fatalf("decode valid %s: %v", test.operation, err)
			}
		})
	}
}

func TestRootBrokerReaderRejectsMalformedUnion(t *testing.T) {
	for _, wire := range []string{
		`null`,
		`{}`,
		`[]`,
		`{"store":0`,
		`{"store":null}`,
		`{"store":0,"store":1}`,
		`{"store":0,"error":""}`,
		`{"store":0,"cluster":null}`,
		`{"store":0,"unknown":null}`,
		`{"store":0,"meta":{}}`,
		`{"meta":{}}`,
		`{"store":"0"}`,
		`{"store":-1}`,
		`{"STORE":0}`,
		`{"store":0} {"store":1}`,
	} {
		t.Run(wire, func(t *testing.T) {
			if _, err := decodeRootBrokerResponse([]byte(wire), rootBrokerStore); !errors.Is(err, rootoci.ErrUnavailable) {
				t.Fatalf("malformed response returned %v", err)
			}
		})
	}
	for _, operation := range []rootBrokerOperation{rootBrokerCluster, rootBrokerMeta, rootBrokerMetrics, rootBrokerStreams, rootBrokerAccount} {
		t.Run(string(operation)+" null", func(t *testing.T) {
			wire := `{"` + string(operation) + `":null}`
			if _, err := decodeRootBrokerResponse([]byte(wire), operation); err == nil {
				t.Fatal("accepted missing expected response pointer")
			}
		})
	}
	for _, wire := range []string{
		`{"cluster":{"observation":{"Running":true,"private":true}}}`,
		`{"account":{"Account":"public","private_key":"secret"}}`,
		`{"account":{"Operator":{"private_key":"secret"}}}`,
		`{"streams":[{"Name":"stream","selector":"other-account"}]}`,
	} {
		t.Run(wire, func(t *testing.T) {
			for _, operation := range []rootBrokerOperation{rootBrokerCluster, rootBrokerAccount, rootBrokerStreams} {
				if _, err := decodeRootBrokerResponse([]byte(wire), operation); err == nil {
					t.Fatalf("accepted unknown nested field for %s", operation)
				}
			}
		})
	}
	if _, err := decodeRootBrokerResponse([]byte(`{"anything":{}}`), rootBrokerOperation("anything")); err == nil {
		t.Fatal("accepted an operation outside the six fixed observations")
	}
}

func TestRootBrokerReaderMapsFixedErrors(t *testing.T) {
	for _, test := range []struct {
		code string
		want error
	}{
		{"unavailable", rootoci.ErrUnavailable},
		{"unauthorized", rootoci.ErrUnauthorized},
		{"stopped", natscell.ErrEmbeddedServerStopped},
		{"disabled", natscell.ErrJetStreamDisabled},
		{"", rootoci.ErrUnavailable},
		{"unexpected internal message", rootoci.ErrUnavailable},
	} {
		t.Run(test.code, func(t *testing.T) {
			_, err := decodeRootBrokerResponse([]byte(`{"error":"`+test.code+`"}`), rootBrokerCluster)
			if !errors.Is(err, test.want) {
				t.Fatalf("code %q: got %v, want %v", test.code, err, test.want)
			}
		})
	}
	response, err := decodeRootBrokerResponse([]byte(`{"cluster":{"observation":{"Running":false},"quorum_ready":true,"full_ready":true}}`), rootBrokerCluster)
	if !errors.Is(err, natscell.ErrEmbeddedServerStopped) || response.Cluster == nil || response.Cluster.Observation.Running {
		t.Fatalf("stopped native broker: response %+v, error %v", response, err)
	}
}

func TestRootBrokerReaderContextRetainsBothLifetimes(t *testing.T) {
	for _, cancelOriginal := range []bool{false, true} {
		t.Run(map[bool]string{false: "caller", true: "original"}[cancelOriginal], func(t *testing.T) {
			parent, cancelParent := context.WithCancelCause(t.Context())
			defer cancelParent(context.Canceled)
			original, cancelOriginalContext := context.WithCancelCause(t.Context())
			defer cancelOriginalContext(context.Canceled)
			ctx, cancel := rootBrokerReaderContext(parent, original)
			defer cancel()
			cause := errors.New("original operation ended")
			if cancelOriginal {
				cancelOriginalContext(cause)
			} else {
				cancelParent(cause)
			}
			select {
			case <-ctx.Done():
				if !errors.Is(context.Cause(ctx), cause) {
					t.Fatalf("lost cancellation cause: %v", context.Cause(ctx))
				}
			case <-time.After(time.Second):
				t.Fatal("reader ignored cancellation")
			}
		})
	}
	for _, originalFirst := range []bool{false, true} {
		parentDeadline, originalDeadline := time.Now().Add(time.Minute), time.Now().Add(2*time.Minute)
		expected := parentDeadline
		if originalFirst {
			parentDeadline, originalDeadline = originalDeadline, parentDeadline
		}
		parent, cancelParent := context.WithDeadline(t.Context(), parentDeadline)
		original, cancelOriginal := context.WithDeadline(t.Context(), originalDeadline)
		ctx, cancel := rootBrokerReaderContext(parent, original)
		deadline, ok := ctx.Deadline()
		if !ok || !deadline.Equal(expected) {
			t.Errorf("deadline %v did not retain the earlier source deadline", deadline)
		}
		cancel()
		cancelParent()
		cancelOriginal()
	}
	original, cancelOriginal := context.WithCancel(t.Context())
	cancelOriginal()
	ctx, cancel := rootBrokerReaderContext(t.Context(), original)
	defer cancel()
	if !errors.Is(ctx.Err(), context.Canceled) {
		t.Fatal("already canceled original context became usable")
	}
}

func TestRootBrokerReaderDeniesMissingTransportAndReplicaMismatch(t *testing.T) {
	reader := &rootBrokerReader{ctx: t.Context(), replicas: 3}
	if reader.Ready() || reader.FullClusterReady(3) || reader.FullClusterReady(1) {
		t.Fatal("native observations replaced the ordinary transport readiness check")
	}
	if err := reader.WaitForCluster(t.Context(), 1); err == nil {
		t.Fatal("accepted caller-selected replicas")
	}
	if _, err := openControllerBrokerNative(t.Context(), Config{}, nil); err == nil {
		t.Fatal("opened native reader without the original ordinary transport")
	}
	var missing *rootBrokerReader
	if missing.Ready() || missing.FullClusterReady(3) {
		t.Fatal("missing native reader is ready")
	}
}

func TestRootBrokerReaderCanceledOriginalCannotObserve(t *testing.T) {
	original, cancel := context.WithCancelCause(t.Context())
	cause := errors.New("reader lifetime ended")
	cancel(cause)
	reader := &rootBrokerReader{ctx: original, replicas: 3}
	for _, operation := range []rootBrokerOperation{
		rootBrokerCluster, rootBrokerMeta, rootBrokerMetrics, rootBrokerStore, rootBrokerStreams, rootBrokerAccount,
	} {
		t.Run(string(operation), func(t *testing.T) {
			response, err := reader.invoke(t.Context(), operation, 30*time.Second)
			if !errors.Is(err, cause) || response.Cluster != nil || response.Meta != nil ||
				response.Metrics != nil || response.Store != nil || response.Streams != nil || response.Account != nil {
				t.Fatalf("canceled original returned response %+v, error %v", response, err)
			}
		})
	}
	if err := reader.WaitForCluster(t.Context(), 3); !errors.Is(err, cause) {
		t.Fatalf("wait lost reader cancellation: %v", err)
	}
}

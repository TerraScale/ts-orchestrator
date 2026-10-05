package cellscale

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNodePressureFresh(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		name      string
		sampledAt time.Time
		want      bool
	}{
		{"unknown", time.Time{}, false},
		{"current", now, true},
		{"recent", now.Add(-time.Minute), true},
		{"oldest allowed", now.Add(-MaxPressureAge), true},
		{"expired", now.Add(-MaxPressureAge - time.Nanosecond), false},
		{"clock skew allowed", now.Add(MaxPressureClockSkew), true},
		{"future", now.Add(MaxPressureClockSkew + time.Nanosecond), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := NodePressure{SampledAt: tc.sampledAt}
			if got := p.Fresh(now); got != tc.want {
				t.Fatalf("Fresh(%s) = %v for sample %s; want %v", now, got, p.SampledAt, tc.want)
			}
		})
	}
}

func TestHTTPSourceSampleFreshness(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	complete, err := json.Marshal(validPressure())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name      string
		sampledAt any
		want      bool
	}{
		{"zero", time.Time{}, false},
		{"stale", now.Add(-MaxPressureAge - time.Nanosecond), false},
		{"future", now.Add(MaxPressureClockSkew + time.Nanosecond), false},
		{"current", now, true},
		{"oldest allowed", now.Add(-MaxPressureAge), true},
		{"clock skew allowed", now.Add(MaxPressureClockSkew), true},
		{"malformed time", "2026-10-04", false},
		{"empty time", "", false},
		{"numeric time", now.Unix(), false},
		{"object time", map[string]any{}, false},
		{"array time", []any{}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var fields map[string]json.RawMessage
			if err := json.Unmarshal(complete, &fields); err != nil {
				t.Fatal(err)
			}
			fields["sampled_at"], err = json.Marshal(tc.sampledAt)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(fields)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write(body)
			}))
			defer server.Close()
			source := HTTPSource{Client: server.Client(), Endpoint: EndpointTemplate(server.URL), Now: func() time.Time { return now }}
			got, err := source.Pressure(t.Context(), "gru-1-db-2")
			if !tc.want {
				if !errors.Is(err, ErrInvalidPressure) || !got.SampledAt.IsZero() {
					t.Fatalf("Pressure = %+v, %v; want unknown pressure", got, err)
				}
				return
			}
			if err != nil || !got.SampledAt.Equal(tc.sampledAt.(time.Time)) {
				t.Fatalf("Pressure = %+v, %v; want sampled_at %s", got, err, tc.sampledAt)
			}
		})
	}
}

func TestHTTPSourceSampleAgesDuringResponse(t *testing.T) {
	now := time.Date(2026, 10, 4, 12, 0, 0, 0, time.UTC)
	p := validPressure()
	p.SampledAt = now.Add(-MaxPressureAge + time.Second)
	if !p.Fresh(now) {
		t.Fatal("sample should be fresh when the request starts")
	}
	body, err := json.Marshal(p)
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	}))
	defer server.Close()
	client := server.Client()
	transport := client.Transport
	client.Transport = pressureTransportFunc(func(r *http.Request) (*http.Response, error) {
		response, err := transport.RoundTrip(r)
		if err == nil {
			// Advance exactly when the body finishes, with no sleeps or races.
			response.Body = pressureCompletionBody{ReadCloser: response.Body, complete: func() { now = now.Add(2 * time.Second) }}
		}
		return response, err
	})
	source := HTTPSource{Client: client, Endpoint: EndpointTemplate(server.URL), Now: func() time.Time { return now }}
	got, err := source.Pressure(t.Context(), p.Node)
	if !errors.Is(err, ErrInvalidPressure) || !got.SampledAt.IsZero() {
		t.Fatalf("Pressure = %+v, %v; want expired pressure rejected after reading the body", got, err)
	}
}

type pressureTransportFunc func(*http.Request) (*http.Response, error)

func (f pressureTransportFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

type pressureCompletionBody struct {
	io.ReadCloser
	complete func()
}

func (b pressureCompletionBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if err == io.EOF {
		b.complete()
	}
	return n, err
}

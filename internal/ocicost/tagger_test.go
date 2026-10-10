package ocicost

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestPassCountsEachOutcome(t *testing.T) {
	api := &stubTagAPI{resources: []Resource{
		{ID: "stamped", Type: "Instance", Name: "gru-1-ctl-1"},
		{ID: "changed", Type: "Instance", Name: "gru-1-ctl-2"},
		{ID: "denied", Type: "Instance", Name: "gru-1-ctl-3"},
		{ID: "unmarked", Type: "Instance", Name: "random"},
		{ID: "unknown", Type: "Network", Name: "gru-1-ctl-4"},
	}, retagErr: map[string]error{"changed": ErrChanged, "denied": ErrNotPermitted}}
	result, err := Pass(t.Context(), api, "gru", tagsTestNow)
	if err != nil {
		t.Fatalf("Pass: %v", err)
	}
	if want := (TagResult{Stamped: 1, Changed: 1, NotPermitted: 1, Untagged: 1}); result != want {
		t.Fatalf("result = %+v, want %+v", result, want)
	}
	if len(api.retagged) != 3 {
		t.Fatalf("retagged %d resources, want 3", len(api.retagged))
	}
}

func TestPassStopsOnUnexpectedError(t *testing.T) {
	api := &stubTagAPI{resources: []Resource{
		{ID: "first", Type: "Instance", Name: "gru-1-ctl-1"},
		{ID: "broken", Type: "Instance", Name: "gru-1-ctl-2"},
		{ID: "never", Type: "Instance", Name: "gru-1-ctl-3"},
	}, retagErr: map[string]error{"broken": errors.New("throttled")}}
	result, err := Pass(t.Context(), api, "gru", tagsTestNow)
	if err == nil || !strings.Contains(err.Error(), "gru-1-ctl-2") || !strings.Contains(err.Error(), "throttled") {
		t.Fatalf("error = %v, want the failing resource named", err)
	}
	if result.Stamped != 1 || len(api.retagged) != 2 {
		t.Fatalf("result %+v after %d retags, want one stamp and two retags", result, len(api.retagged))
	}
}

func TestPassListFailureStampsNothing(t *testing.T) {
	api := &stubTagAPI{listErr: errors.New("search down")}
	if _, err := Pass(t.Context(), api, "gru", tagsTestNow); err == nil {
		t.Fatal("Pass succeeded after a failed listing")
	}
	if len(api.retagged) != 0 {
		t.Fatalf("retagged %d resources after a failed listing", len(api.retagged))
	}
}

func TestTaggerStepFollowerDoesNotConnect(t *testing.T) {
	connects := 0
	tagger := newStubTagger(&stubTagAPI{}, &connects)
	tagger.Leader = func() bool { return false }
	if wait := tagger.step(t.Context()); wait != followInterval {
		t.Fatalf("follower waits %v, want %v", wait, followInterval)
	}
	if connects != 0 {
		t.Fatalf("follower connected %d times", connects)
	}
}

func TestTaggerStepRetriesConnect(t *testing.T) {
	api := &stubTagAPI{}
	connects := 0
	tagger := newStubTagger(api, &connects)
	tagger.Connect = func(context.Context) (TagAPI, error) {
		connects++
		if connects == 1 {
			return nil, errors.New("oci down")
		}
		return api, nil
	}
	if wait := tagger.step(t.Context()); wait != retryInterval {
		t.Fatalf("failed connect waits %v, want %v", wait, retryInterval)
	}
	if wait := tagger.step(t.Context()); wait != Interval {
		t.Fatalf("connect retry waits %v, want %v", wait, Interval)
	}
	if wait := tagger.step(t.Context()); wait != Interval || connects != 2 {
		t.Fatalf("second pass waits %v after %d connects, want %v with 2 connects", wait, connects, Interval)
	}
}

func TestTaggerStepFailedPassRetries(t *testing.T) {
	api := &stubTagAPI{listErr: errors.New("search down")}
	connects := 0
	tagger := newStubTagger(api, &connects)
	if wait := tagger.step(t.Context()); wait != retryInterval {
		t.Fatalf("failed pass waits %v, want %v", wait, retryInterval)
	}
	api.listErr = nil
	if wait := tagger.step(t.Context()); wait != Interval {
		t.Fatalf("recovered pass waits %v, want %v", wait, Interval)
	}
	if tagger.failure != "" {
		t.Fatalf("failure %q kept after recovery", tagger.failure)
	}
}

func TestTaggerRunStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	connects := 0
	tagger := newStubTagger(&stubTagAPI{}, &connects)
	tagger.Leader = func() bool { cancel(); return false }
	done := make(chan error, 1)
	go func() { done <- tagger.Run(ctx) }()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop after cancel")
	}
}

func newStubTagger(api *stubTagAPI, connects *int) *Tagger {
	return &Tagger{Cell: "gru", Leader: func() bool { return true },
		Connect: func(context.Context) (TagAPI, error) { *connects++; return api, nil },
		Now:     func() time.Time { return tagsTestNow }}
}

type stubTagAPI struct {
	resources []Resource
	listErr   error
	retagErr  map[string]error
	retagged  []Resource
}

func (s *stubTagAPI) Resources(context.Context) ([]Resource, error) {
	return s.resources, s.listErr
}

func (s *stubTagAPI) Retag(_ context.Context, resource Resource, _ map[string]string) error {
	s.retagged = append(s.retagged, resource)
	return s.retagErr[resource.ID]
}

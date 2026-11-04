package ocicost

import (
	"context"
	"testing"
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

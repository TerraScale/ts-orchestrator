package app

import "testing"

func TestRootSourceCoreRequiresAcquiredCredentials(t *testing.T) {
	sources, err := connectRootControllerSources(t.Context(), Config{}, nil)
	if err == nil || sources != nil {
		t.Fatalf("missing protected credentials returned root sources %v, error %v", sources, err)
	}
	bound, err := bindOpenedRootRuntimeSources(t.Context(), Config{}, nil, nil, nil, nil, nil, new(rootControllerSources))
	if err == nil || bound != nil {
		t.Fatalf("unopened root source returned binding %v, error %v", bound, err)
	}
}

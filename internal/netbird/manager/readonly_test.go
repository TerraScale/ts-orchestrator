package manager

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestReadOnlyAPIRejectsMutationBeforeDispatch(t *testing.T) {
	var reads, writes atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			reads.Add(1)
		} else {
			writes.Add(1)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	api, err := NewReadOnlyAPI(server.URL, testPAT)
	if err != nil {
		t.Fatal(err)
	}
	defer api.Close()
	if err := api.do(t.Context(), http.MethodGet, "/groups", nil, nil); err != nil {
		t.Fatal(err)
	}
	for _, method := range []string{http.MethodPost, http.MethodPut, http.MethodPatch, http.MethodDelete} {
		if err := api.do(t.Context(), method, "/groups", nil, nil); !errors.Is(err, ErrAccountWriterUnavailable) {
			t.Fatalf("%s: expected writer denial, got %v", method, err)
		}
	}
	if reads.Load() != 1 || writes.Load() != 0 {
		t.Fatalf("dispatched reads=%d writes=%d", reads.Load(), writes.Load())
	}
}

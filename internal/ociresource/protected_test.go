package ociresource

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"slices"
	"strings"
	"testing"
	"time"
)

func TestRequestCheckpointCapsActualContextAndKeepsResponseReadable(t *testing.T) {
	store := integrationStore(t)
	desired := put(t, store, "wire", 1, PolicyEnforce, 1)
	now := time.Now().UTC()
	var err error
	desired, err = store.SaveOperation(t.Context(), desired, 7, now, false)
	if err != nil {
		t.Fatal(err)
	}
	originalDeadline := now.Add(time.Minute)
	desired.Operation.Requests = []RequestAttempt{{Method: http.MethodPut, URL: "https://iaas.example/owned", Body: []byte(`{"size":1}`), RetryToken: "original", StartedAt: now, Deadline: originalDeadline}}
	desired, err = store.SaveOperation(t.Context(), desired, 7, now, false)
	if err != nil {
		t.Fatal(err)
	}
	// These attempts use the original request loaded from the real journal.
	persisted, err := store.Get(t.Context(), desired.Key)
	if err != nil {
		t.Fatal(err)
	}
	attempt := persisted.Operation.Requests[0]
	later := attempt
	later.Deadline = now.Add(time.Hour)
	retried, index, err := beginRequest(*persisted.Operation, later, now.Add(time.Second))
	if err != nil || index != 0 || len(retried.Requests) != 1 || !retried.Requests[0].Deadline.Equal(attempt.Deadline) || !slices.Equal(retried.Requests[0].Body, attempt.Body) {
		t.Fatalf("persisted original request changed: %+v %v", retried, err)
	}
	for _, field := range []string{"body", "token", "etag", "target"} {
		t.Run(field, func(t *testing.T) {
			changed := attempt
			switch field {
			case "body":
				changed.Body = []byte(`{"rules":[]}`)
			case "token":
				changed.RetryToken = "replacement"
			case "etag":
				changed.IfMatch = "replacement"
			case "target":
				changed.URL += "/other"
			}
			if _, _, err := beginRequest(*persisted.Operation, changed, now.Add(time.Second)); err == nil {
				t.Fatal("changed uncertain persisted request admitted")
			}
		})
	}
	if _, _, err := beginRequest(*persisted.Operation, later, attempt.Deadline); err == nil {
		t.Fatal("persisted original deadline extended")
	}
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Hour))
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://iaas.example/owned", strings.NewReader(`{"size":1}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("opc-retry-token", "original")
	request.Header.Set("Authorization", "must-never-persist")
	finish, err := checkpointRequest(ctx, request, &desired, store, 7, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	if deadline, _ := request.Context().Deadline(); !deadline.Equal(originalDeadline) {
		t.Fatalf("original actual wire deadline extended: %v", deadline)
	}
	protected, err := store.Get(t.Context(), desired.Key)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(protected.Operation)
	if err != nil || bytes.Contains(wire, []byte("must-never-persist")) {
		t.Fatalf("authentication entered durable request journal: %v", err)
	}
	response := &http.Response{StatusCode: 200, Body: io.NopCloser(strings.NewReader(`{"accepted":true}`))}
	if err := finish(response, nil, true); err != nil {
		t.Fatal(err)
	}
	if err := request.Context().Err(); err != nil {
		t.Fatalf("response context canceled before OCI decoded it: %v", err)
	}
	if _, err := io.ReadAll(response.Body); err != nil {
		t.Fatal(err)
	}
	if err := response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	if request.Context().Err() != context.Canceled {
		t.Fatal("request deadline context leaked after body close")
	}
	stored, err := store.Get(t.Context(), desired.Key)
	if err != nil || len(stored.Operation.Requests) != 1 || stored.Operation.Requests[0].Status != 200 || !stored.Operation.Requests[0].Deadline.Equal(originalDeadline) {
		t.Fatalf("wire result lost: %+v %v", stored.Operation, err)
	}
}

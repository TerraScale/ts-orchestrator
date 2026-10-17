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

func TestOriginalRequestRetainsBytesTokenAndDeadline(t *testing.T) {
	now := time.Now().UTC()
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Minute))
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://iaas.example/networkSecurityGroups/owned", strings.NewReader(`{"rules":[{"port":4222}]}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Authorization", "must-never-persist")
	request.Header.Set("opc-retry-token", "original-token")
	request.Header.Set("If-Match", "original-etag")
	attempt, err := requestAttempt(request, now)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := json.Marshal(attempt)
	if err != nil || bytes.Contains(wire, []byte("must-never-persist")) {
		t.Fatalf("authentication entered request journal: %v", err)
	}
	operation := Operation{StartedAt: now, Requests: []RequestAttempt{attempt}}
	later := attempt
	later.Deadline = now.Add(time.Hour)
	retried, index, err := beginRequest(operation, later, now.Add(time.Second))
	if err != nil || index != 0 || len(retried.Requests) != 1 || !retried.Requests[0].Deadline.Equal(attempt.Deadline) || !slices.Equal(retried.Requests[0].Body, attempt.Body) {
		t.Fatalf("original request changed: %+v %v", retried, err)
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
			if _, _, err := beginRequest(operation, changed, now.Add(time.Second)); err == nil {
				t.Fatal("changed uncertain request was admitted")
			}
		})
	}
	if _, _, err := beginRequest(operation, later, attempt.Deadline); err == nil {
		t.Fatal("original deadline extended")
	}
}

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
	ctx, cancel := context.WithDeadline(t.Context(), now.Add(time.Hour))
	defer cancel()
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://iaas.example/owned", strings.NewReader(`{"size":1}`))
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("opc-retry-token", "original")
	finish, err := checkpointRequest(ctx, request, &desired, store, 7, func() time.Time { return time.Now().UTC() })
	if err != nil {
		t.Fatal(err)
	}
	if deadline, _ := request.Context().Deadline(); !deadline.Equal(originalDeadline) {
		t.Fatalf("original actual wire deadline extended: %v", deadline)
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

func TestProtectedJournalRoundTripRetainsUncertainOperation(t *testing.T) {
	now := time.Now().UTC()
	desired, err := NewDesired(Key{Region: "GRU", Kind: "nsg-rules", Name: "members"}, 1, PolicyEnforce, struct {
		ID string `json:"id"`
	}{ID: "original"})
	if err != nil {
		t.Fatal(err)
	}
	desired, err = OperationRecord(desired, 7, now, false)
	if err != nil {
		t.Fatal(err)
	}
	desired.Operation.WorkRequests = []string{"original-work-request"}
	source := ResourceSource{ControllerConfigSHA256: strings.Repeat("a", 64), GrantSHA256: strings.Repeat("b", 64)}
	journal := ProtectedJournal{Revision: 2, Source: source, Resources: map[string]ProtectedResource{desired.Key.String(): {Revision: 2, Source: source, Desired: desired}}}
	wire, err := json.Marshal(journal, json.Deterministic(true))
	if err != nil {
		t.Fatal(err)
	}
	var restarted ProtectedJournal
	if err := json.Unmarshal(wire, &restarted, json.RejectUnknownMembers(true)); err != nil {
		t.Fatal(err)
	}
	if err := restarted.Validate("GRU"); err != nil {
		t.Fatal(err)
	}
	stored := restarted.Resources[desired.Key.String()].Desired
	resumed, err := OperationRecord(stored, 8, now.Add(time.Second), false)
	if err != nil || resumed.Operation.ID != desired.Operation.ID || !resumed.Operation.StartedAt.Equal(now) || !slices.Equal(resumed.Operation.WorkRequests, desired.Operation.WorkRequests) {
		t.Fatalf("uncertain operation changed: %+v %v", resumed.Operation, err)
	}
	entry := restarted.Resources[desired.Key.String()]
	entry.Desired.Tombstone = &Tombstone{RequestedAt: now, NotBefore: now.Add(time.Hour)}
	restarted.Resources[desired.Key.String()] = entry
	if err := restarted.Validate("GRU"); err == nil {
		t.Fatal("unsigned removal provenance accepted")
	}
	if err := journal.Validate("SFO"); err == nil {
		t.Fatal("cross-cell protected journal accepted")
	}
}

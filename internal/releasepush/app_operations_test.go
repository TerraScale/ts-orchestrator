package releasepush

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func awaitAppReply(t *testing.T, h *Handler, data []byte) Reply {
	t.Helper()
	deadline := time.After(3 * time.Second)
	for {
		reply := h.app(t.Context(), data)
		if reply.State != "accepted" {
			return reply
		}
		select {
		case <-deadline:
			t.Fatal("app operation never completed")
		case <-time.After(time.Millisecond):
		}
	}
}

func TestAppOperationRefreshAndConcurrentPolls(t *testing.T) {
	now := time.Now()
	i := newIssuer(t)
	claims := goodClaims(now)
	claims["repository"] = owner + "/ts-dashboard"
	claims["job_workflow_ref"] = owner + "/ts-dashboard/.github/workflows/images-ghcr.yml@" + mainRef
	// A token about to expire and its refresh differ only in lifetime claims.
	claims["exp"] = now.Add(-clockSkew + time.Second).Unix()
	old := i.sign(t, claims)
	claims["exp"] = now.Add(5 * time.Minute).Unix()
	fresh := i.sign(t, claims)
	request := func(token string) []byte {
		data, err := json.Marshal(AppRelease{Service: "ts-dashboard", Image: "ghcr.io/terrascale/ts-dashboard@sha256:" + strings.Repeat("a", 64), Token: token})
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	started, finish := make(chan context.Context, 1), make(chan struct{})
	defer close(finish)
	var calls atomic.Int32
	h := &Handler{Verifier: i.verifier(now), App: func(ctx context.Context, _, _ string, got Claims) (json.RawMessage, error) {
		calls.Add(1)
		started <- ctx
		<-finish
		return json.RawMessage(`[{"region":"fra","error":"dependency failed"}]`), errors.New("bake held")
	}}
	ctx, cancel := context.WithCancel(t.Context())
	if reply := h.app(ctx, request(old)); reply.State != "accepted" {
		t.Fatalf("initial reply = %+v", reply)
	}
	cancel()
	var operationCtx context.Context
	select {
	case operationCtx = <-started:
	case <-time.After(3 * time.Second):
		t.Fatal("callback did not start")
	}
	if deadline, ok := operationCtx.Deadline(); operationCtx.Err() != nil || !ok || time.Until(deadline) < HandlerWait-time.Minute {
		t.Fatal("operation inherited the canceled poll or lost its own deadline")
	}
	// Advance past the first credential's admission deadline while the bake is
	// still running. Expired polls must not read even an existing operation.
	h.Verifier.Now = func() time.Time { return now.Add(2 * time.Second) }
	if reply := h.app(t.Context(), request(old)); reply.State != "rejected" || !strings.Contains(reply.Error, "expired") {
		t.Fatalf("expired token read the operation: %+v", reply)
	}
	var wg sync.WaitGroup
	for range 24 {
		wg.Go(func() {
			if reply := h.app(t.Context(), request(fresh)); reply.State != "accepted" {
				t.Errorf("concurrent poll = %+v", reply)
			}
		})
	}
	wg.Wait()
	if calls.Load() != 1 {
		t.Fatalf("refreshed duplicate applied %d times", calls.Load())
	}
	// Only an authorized workflow can read status, including after completion.
	wrong := request(i.sign(t, goodClaims(now)))
	if reply := h.app(t.Context(), wrong); reply.State != "rejected" {
		t.Fatalf("wrong workflow read operation: %+v", reply)
	}
	finish <- struct{}{}
	reply := awaitAppReply(t, h, request(fresh))
	if reply.State != "failed" || reply.Error != "bake held" || string(reply.Result) != `[{"region":"fra","error":"dependency failed"}]` {
		t.Fatalf("lost failure evidence: %+v", reply)
	}
	reply.Result[0] = 'x'
	if reply := h.app(t.Context(), request(fresh)); reply.State != "failed" || reply.Result[0] != '[' || calls.Load() != 1 {
		t.Fatalf("completed poll lost cached evidence or reran: %+v", reply)
	}
	if reply := h.app(t.Context(), wrong); reply.State != "rejected" {
		t.Fatalf("completed cache bypassed authorization: %+v", reply)
	}
	if reply := h.app(t.Context(), request(old)); reply.State != "rejected" {
		t.Fatalf("expired token read completed evidence: %+v", reply)
	}
}

func TestAppOperationIdentityAndRetention(t *testing.T) {
	var calls atomic.Int32
	h := &Handler{App: func(context.Context, string, string, Claims) (json.RawMessage, error) {
		calls.Add(1)
		return nil, nil
	}}
	release := AppRelease{Service: "terrabase", Image: "image"}
	claims := Claims{Repository: "repo", RunID: "100", SHA: testSHA, JobWorkflowRef: "workflow"}
	h.appOperations = make(map[appOperationKey]*appOperation)
	for n := range 128 {
		h.appOperations[appOperationKey{runID: fmt.Sprint(n)}] = &appOperation{reply: Reply{State: "accepted"}}
	}
	if reply := h.appOperation(release, claims); reply.State != "rejected" || calls.Load() != 0 {
		t.Fatalf("capacity evicted an active operation: %+v", reply)
	}
	// A recent completion is retained; only an old completion frees capacity.
	key := appOperationKey{runID: "0"}
	h.appOperations[key].completed = time.Now()
	if reply := h.appOperation(release, claims); reply.State != "rejected" {
		t.Fatalf("recent evidence evicted: %+v", reply)
	}
	h.appOperations[key].completed = time.Now().Add(-HandlerWait - time.Second)
	if reply := h.appOperation(release, claims); reply.State != "accepted" {
		t.Fatalf("expired completion blocked capacity: %+v", reply)
	}
	// Keep only this operation, then prove each immutable identity component
	// distinguishes a new operation; expiry and token bytes are absent by design.
	h.mu.Lock()
	for key := range h.appOperations {
		if key.repository == "" {
			delete(h.appOperations, key)
		}
	}
	h.mu.Unlock()
	for _, field := range []string{"repository", "run", "sha", "workflow", "service", "image"} {
		r, c := release, claims
		switch field {
		case "repository":
			c.Repository += "new"
		case "run":
			c.RunID += "1"
		case "sha":
			c.SHA = strings.Repeat("a", 40)
		case "workflow":
			c.JobWorkflowRef += "new"
		case "service":
			r.Service += "new"
		case "image":
			r.Image += "new"
		}
		if reply := h.appOperation(r, c); reply.State != "accepted" {
			t.Fatalf("new %s reused another operation: %+v", field, reply)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for calls.Load() != 7 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls.Load() != 7 {
		t.Fatalf("distinct identities applied %d times", calls.Load())
	}
}

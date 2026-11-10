package releasepush

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"time"
)

// Refreshed credentials identify the same operation without extending their
// lifetime: app validates every request before consulting this cache.
type appOperationKey struct {
	repository, runID, attempt, sha, workflow, service, image string
}

type appOperation struct {
	reply     Reply
	completed time.Time
}

func (h *Handler) appOperation(release AppRelease, claims Claims) Reply {
	key := appOperationKey{claims.Repository, claims.RunID, claims.RunAttempt, claims.SHA, claims.JobWorkflowRef, release.Service, release.Image}
	return h.operation(key, func(ctx context.Context, progress Progress) (json.RawMessage, error) {
		return h.App(ctx, release.Service, release.Image, claims, progress)
	})
}

type operationProgress struct {
	h         *Handler
	operation *appOperation
}

func (p operationProgress) Deadline(deadline time.Time) {
	p.h.mu.Lock()
	defer p.h.mu.Unlock()
	p.operation.reply.Deadline = deadline
}

func (p operationProgress) Event(event string) {
	p.h.mu.Lock()
	defer p.h.mu.Unlock()
	p.operation.reply.Events = append(p.operation.reply.Events, event)
}

func (h *Handler) operation(key appOperationKey, run func(context.Context, Progress) (json.RawMessage, error)) Reply {
	h.mu.Lock()
	defer h.mu.Unlock()
	for key, operation := range h.appOperations {
		if !operation.completed.IsZero() && time.Since(operation.completed) > HandlerWait {
			delete(h.appOperations, key)
		}
	}
	if operation := h.appOperations[key]; operation != nil {
		reply := operation.reply
		reply.Result = append([]byte(nil), reply.Result...)
		reply.Events = slices.Clone(reply.Events)
		return reply
	}
	// Never evict active operations or recently completed evidence to admit a
	// new release. Only authenticated, allowlisted CI requests reach this point.
	if len(h.appOperations) >= 128 {
		return rejected(errors.New("app release operation capacity reached"))
	}
	if h.appOperations == nil {
		h.appOperations = make(map[appOperationKey]*appOperation)
	}
	operation := &appOperation{reply: Reply{State: "accepted"}}
	h.appOperations[key] = operation
	go func() {
		// The rollout outlives each short poll and its OIDC connection.
		ctx, cancel := context.WithTimeout(context.Background(), HandlerWait)
		defer cancel()
		result, err := run(ctx, operationProgress{h, operation})
		h.mu.Lock()
		reply := Reply{State: "done", Result: append([]byte(nil), result...), Deadline: operation.reply.Deadline, Events: operation.reply.Events}
		if err != nil {
			reply.State, reply.Error = "failed", err.Error()
		}
		operation.reply, operation.completed = reply, time.Now()
		h.mu.Unlock()
	}()
	return Reply{State: "accepted"}
}

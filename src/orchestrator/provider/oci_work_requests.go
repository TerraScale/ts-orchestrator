package provider

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type OCIWorkRequestAdapter struct {
	Core *OCIHTTPTransport
	Wait func(context.Context, time.Duration) error
}

func NewOCIWorkRequestAdapter(core *OCIHTTPTransport) (*OCIWorkRequestAdapter, error) {
	if core == nil || core.Config.Service != OCIServiceCore {
		return nil, &InvalidOperationError{Message: "OCI work request transport is unavailable or has the wrong authority"}
	}
	return &OCIWorkRequestAdapter{Core: core, Wait: waitContext}, nil
}

func waitContext(ctx context.Context, duration time.Duration) error {
	timer := time.NewTimer(duration)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func validWorkRequestID(id string) bool {
	return len(id) > 0 && len(id) <= 256 && !strings.ContainsAny(id, "\r\n/?#%")
}

func (a *OCIWorkRequestAdapter) GetWorkRequest(ctx context.Context, id string) (WorkRequest, error) {
	if a == nil || a.Core == nil || !validWorkRequestID(id) {
		return WorkRequest{}, &ArgumentError{Message: "OCI work request identity is invalid"}
	}
	resp, err := a.Core.Do(ctx, http.MethodGet, "/20160918/workRequests/"+url.PathEscape(id), nil)
	if err != nil {
		return WorkRequest{}, err
	}
	if resp.StatusCode == http.StatusNotFound {
		drainClose(resp.Body)
		return WorkRequest{ID: id, State: WorkRequestNotVisible}, nil
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		drainClose(resp.Body)
		return WorkRequest{}, &InvalidOperationError{Message: "OCI work request read failed"}
	}
	body, err := ReadBoundedBody(resp, a.Core.Config.MaxBodyBytes)
	if err != nil {
		return WorkRequest{}, err
	}
	var document struct {
		ID              string  `json:"id"`
		Status          string  `json:"status"`
		PercentComplete float64 `json:"percentComplete"`
	}
	if json.Unmarshal(body, &document) != nil || document.ID != id || document.PercentComplete < 0 || document.PercentComplete > 100 {
		return WorkRequest{}, &InvalidDataError{Message: "OCI work request response is invalid"}
	}
	state := WorkRequestState("")
	switch document.Status {
	case "ACCEPTED":
		state = WorkRequestAccepted
	case "IN_PROGRESS", "CANCELING":
		state = WorkRequestInProgress
	case "SUCCEEDED":
		state = WorkRequestSucceeded
	case "FAILED":
		state = WorkRequestFailed
	case "CANCELED":
		state = WorkRequestCanceled
	default:
		return WorkRequest{}, &InvalidDataError{Message: "OCI work request status is invalid"}
	}
	return WorkRequest{ID: id, State: state, PercentComplete: document.PercentComplete}, nil
}

func (a *OCIWorkRequestAdapter) WaitWorkRequest(ctx context.Context, id string, policy WorkRequestWaitPolicy) (WorkRequest, error) {
	if a == nil || a.Wait == nil || policy.PollInterval < 0 || policy.PollInterval > time.Minute || policy.MaxPolls < 1 || policy.MaxPolls > 10000 || policy.MaxNotFound < 0 || policy.MaxNotFound > policy.MaxPolls {
		return WorkRequest{}, &ArgumentError{Message: "OCI work request wait policy is invalid"}
	}
	notFound := 0
	for poll := 0; poll < policy.MaxPolls; poll++ {
		request, err := a.GetWorkRequest(ctx, id)
		if err != nil {
			return WorkRequest{}, err
		}
		switch request.State {
		case WorkRequestSucceeded:
			return request, nil
		case WorkRequestFailed, WorkRequestCanceled:
			return request, &InvalidOperationError{Message: "OCI work request did not succeed"}
		case WorkRequestNotVisible:
			notFound++
			if notFound > policy.MaxNotFound {
				return request, &ProviderOutcomeUnknownError{Message: "OCI work request remained invisible"}
			}
		}
		if poll+1 < policy.MaxPolls {
			if err := a.Wait(ctx, policy.PollInterval); err != nil {
				return WorkRequest{}, err
			}
		}
	}
	return WorkRequest{ID: id, State: WorkRequestInProgress}, &ProviderOutcomeUnknownError{Message: "OCI work request did not reach a terminal state"}
}

var _ WorkRequestProvider = (*OCIWorkRequestAdapter)(nil)

package ociclient

import (
	"context"
	"net/http"
	"testing"
	"time"
)

type finalAdmissionDispatcher struct{ calls int }

func (d *finalAdmissionDispatcher) Do(*http.Request) (*http.Response, error) {
	d.calls++
	return &http.Response{StatusCode: 200, Body: http.NoBody}, nil
}

func TestFinalSourceGuardCannotExtendEarlierAdmissionDeadline(t *testing.T) {
	next := &finalAdmissionDispatcher{}
	ctx := WithAdmission(t.Context(), func(ctx context.Context) (func(), error) {
		if err := LimitAdmission(ctx, time.Now().Add(time.Minute)); err != nil {
			return nil, err
		}
		return func() {}, nil
	})
	ctx = WithRequestGuard(ctx, func(ctx context.Context) error {
		// Expire the previously admitted cap while this final guard waits.
		state := ctx.Value(admissionDeadlineKey{}).(*admissionDeadline)
		state.until = time.Now().Add(-time.Second)
		return nil
	})
	request, err := http.NewRequestWithContext(ctx, http.MethodPut, "https://iaas.example/owned", http.NoBody)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := (readDispatcher{next: next}).Do(request); err == nil || next.calls != 0 {
		t.Fatalf("expired original cap dispatched: calls=%d err=%v", next.calls, err)
	}
}

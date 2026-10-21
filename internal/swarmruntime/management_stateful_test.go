//go:build linux

package swarmruntime

import (
	"context"
	"errors"
	"testing"

	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

type statefulTestAuthorizer func(context.Context, *api.ServiceSpec, func(context.Context) error) error

func (authorize statefulTestAuthorizer) WithStatefulService(ctx context.Context, spec *api.ServiceSpec, effect func(context.Context) error) error {
	return authorize(ctx, spec, effect)
}

func TestManagementStatefulEffectBracket(t *testing.T) {
	spec := &api.ServiceSpec{Annotations: api.Annotations{Labels: map[string]string{
		LabelRegion: "sa-saopaulo-1", LabelEnvironment: "test", LabelRole: "terrabase",
		LabelIntentID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", "terrascale.stateful": "true",
	}}}
	failure := errors.New("upstream effect failed")
	canceled, cancel := context.WithCancel(t.Context())
	cancel()
	for _, tc := range []struct {
		name      string
		authorize statefulTestAuthorizer
		effectErr error
		wantErr   error
		denied    bool
		calls     int
	}{
		{name: "one synchronous effect", calls: 1, authorize: func(ctx context.Context, _ *api.ServiceSpec, effect func(context.Context) error) error {
			return effect(ctx)
		}},
		{name: "missing effect", denied: true, authorize: func(context.Context, *api.ServiceSpec, func(context.Context) error) error { return nil }},
		{name: "ignored duplicate", denied: true, calls: 1, authorize: func(ctx context.Context, _ *api.ServiceSpec, effect func(context.Context) error) error {
			_ = effect(ctx)
			_ = effect(ctx)
			return nil
		}},
		{name: "nil context", denied: true, authorize: func(_ context.Context, _ *api.ServiceSpec, effect func(context.Context) error) error {
			return effect(nil)
		}},
		{name: "canceled context", denied: true, authorize: func(_ context.Context, _ *api.ServiceSpec, effect func(context.Context) error) error {
			return effect(canceled)
		}},
		{name: "ignored effect error", effectErr: failure, wantErr: failure, calls: 1, authorize: func(ctx context.Context, _ *api.ServiceSpec, effect func(context.Context) error) error {
			_ = effect(ctx)
			return nil
		}},
		{name: "post effect veto", wantErr: failure, calls: 1, authorize: func(ctx context.Context, _ *api.ServiceSpec, effect func(context.Context) error) error {
			if err := effect(ctx); err != nil {
				return err
			}
			return failure
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &managementServer{region: "sa-saopaulo-1", environment: "test", stateful: tc.authorize}
			calls := 0
			err := s.withStatefulService(t.Context(), spec, func(context.Context) error { calls++; return tc.effectErr })
			if calls != tc.calls || tc.denied && status.Code(err) != codes.PermissionDenied || !tc.denied && !errors.Is(err, tc.wantErr) {
				t.Fatalf("effect calls=%d, error=%v; want calls=%d, denied=%t, error=%v", calls, err, tc.calls, tc.denied, tc.wantErr)
			}
		})
	}
	invoked := false
	s := &managementServer{region: "other-region", environment: "test", stateful: statefulTestAuthorizer(func(context.Context, *api.ServiceSpec, func(context.Context) error) error {
		invoked = true
		return nil
	})}
	if err := s.withStatefulService(t.Context(), spec, func(context.Context) error { t.Fatal("foreign service reached upstream"); return nil }); status.Code(err) != codes.PermissionDenied || invoked {
		t.Fatalf("foreign stateful scope reached the root verifier: %v", err)
	}
}

func TestManagementPeerPIDAdmission(t *testing.T) {
	for _, tc := range []struct {
		name     string
		identity credentials.AuthInfo
		admitted bool
		wantPID  int32
	}{
		{name: "missing peer", admitted: true},
		{name: "unadmitted kernel peer", identity: unixPeer{pid: 42}},
		{name: "invalid kernel pid", identity: unixPeer{}, admitted: true},
		{name: "admitted kernel peer", identity: unixPeer{pid: 42}, admitted: true, wantPID: 42},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.WithValue(t.Context(), managementAdmission{}, tc.admitted)
			if tc.identity != nil {
				ctx = peer.NewContext(ctx, &peer.Peer{AuthInfo: tc.identity})
			}
			pid, err := ManagementPeerPID(ctx)
			if pid != tc.wantPID || tc.wantPID == 0 && status.Code(err) != codes.PermissionDenied || tc.wantPID != 0 && err != nil {
				t.Fatalf("peer pid=%d error=%v; want pid=%d", pid, err, tc.wantPID)
			}
		})
	}
}

//go:build linux

package swarmruntime

import (
	"context"
	"errors"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/status"
	"google.golang.org/grpc/test/bufconn"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func TestManagementObservationBlockedSend(t *testing.T) {
	for _, reason := range []string{"overflow", "caller canceled", "authority revoked"} {
		t.Run(reason, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			closed := make(chan struct{})
			release := make(chan struct{})
			started := make(chan struct{})
			finished := make(chan struct{})
			result := make(chan error, 1)
			var revoked atomic.Bool
			go func() {
				result <- sendManagementObservation(ctx, closed, func() error {
					if revoked.Load() {
						return denied()
					}
					return nil
				}, func() error {
					defer close(finished)
					close(started)
					<-release
					return nil
				})
			}()
			defer close(release)
			select {
			case <-started:
			case <-ctx.Done():
				t.Fatal("send did not start")
			}
			switch reason {
			case "overflow":
				close(closed)
			case "caller canceled":
				cancel()
			case "authority revoked":
				revoked.Store(true)
			}
			select {
			case err := <-result:
				if reason == "overflow" && status.Code(err) != codes.OutOfRange || reason == "caller canceled" && !errors.Is(err, context.Canceled) || reason == "authority revoked" && status.Code(err) != codes.PermissionDenied {
					t.Fatalf("blocked send did not invalidate on %s: %v", reason, err)
				}
			case <-time.After(time.Second):
				t.Fatalf("blocked send retained handler after %s", reason)
			}
			// Emulate gRPC releasing its send when the handler has returned.
			release <- struct{}{}
			select {
			case <-finished:
			case <-time.After(time.Second):
				t.Fatal("sender did not exit after transport released it")
			}
		})
	}
}

func TestManagementObservationGRPCBlockedSend(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	listener := bufconn.Listen(64 << 10)
	defer listener.Close()
	server := grpc.NewServer()
	defer server.Stop()
	closed := make(chan struct{})
	started := make(chan struct{})
	finished := make(chan struct{})
	returned := make(chan error, 1)
	server.RegisterService(&grpc.ServiceDesc{
		ServiceName: "observation.SendFixture", HandlerType: (*interface{})(nil),
		Streams: []grpc.StreamDesc{{StreamName: "Blocked", ServerStreams: true, Handler: func(_ any, stream grpc.ServerStream) error {
			if err := stream.RecvMsg(new(wrapperspb.BytesValue)); err != nil {
				return err
			}
			err := sendManagementObservation(stream.Context(), closed, func() error { return nil }, func() error {
				defer close(finished)
				close(started)
				return stream.SendMsg(&wrapperspb.BytesValue{Value: make([]byte, 1<<20)})
			})
			returned <- err
			return err
		}}},
	}, new(struct{}))
	go func() { _ = server.Serve(listener) }()
	conn, err := grpc.NewClient("passthrough:///observation-send-fixture", grpc.WithTransportCredentials(insecure.NewCredentials()), grpc.WithContextDialer(func(ctx context.Context, _ string) (net.Conn, error) { return listener.DialContext(ctx) }))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	stream, err := conn.NewStream(ctx, &grpc.StreamDesc{ServerStreams: true}, "/observation.SendFixture/Blocked")
	if err != nil {
		t.Fatal(err)
	}
	if err := stream.SendMsg(new(wrapperspb.BytesValue)); err != nil {
		t.Fatal(err)
	}
	if err := stream.CloseSend(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-ctx.Done():
		t.Fatal("gRPC sender did not start")
	}
	select {
	case <-finished:
		t.Fatal("fixture did not produce a blocked gRPC send")
	case <-time.After(50 * time.Millisecond):
	}
	close(closed)
	select {
	case err := <-returned:
		if status.Code(err) != codes.OutOfRange {
			t.Fatalf("overflow did not return the gRPC handler: %v", err)
		}
	case <-ctx.Done():
		t.Fatal("overflow retained the gRPC handler")
	}
	select {
	case <-finished:
	case <-ctx.Done():
		t.Fatal("handler return did not release actual blocked gRPC SendMsg")
	}
}

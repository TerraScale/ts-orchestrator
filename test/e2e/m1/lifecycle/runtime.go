package main

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	containers "github.com/containerd/containerd/api/services/containers/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

type runtimeBytes struct{}

func (runtimeBytes) Name() string                      { return "proto" }
func (runtimeBytes) Marshal(value any) ([]byte, error) { return *value.(*[]byte), nil }
func (runtimeBytes) Unmarshal(data []byte, value any) error {
	*value.(*[]byte) = append([]byte(nil), data...)
	return nil
}

func runtimeProxy(ctx context.Context, state string) (func(), error) {
	client, err := grpc.NewClient("unix://"+filepath.Join(state, "containerd.sock"), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	socket := filepath.Join(state, "containerd-proxy.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		client.Close()
		return nil, err
	}
	server := grpc.NewServer(grpc.ForceServerCodec(runtimeBytes{}), grpc.UnknownServiceHandler(func(_ any, downstream grpc.ServerStream) error {
		method, _ := grpc.MethodFromServerStream(downstream)
		md, _ := metadata.FromIncomingContext(downstream.Context())
		forward, cancel := context.WithCancel(metadata.NewOutgoingContext(downstream.Context(), md))
		defer cancel()
		upstream, err := client.NewStream(forward, &grpc.StreamDesc{ServerStreams: true, ClientStreams: true}, method, grpc.ForceCodec(runtimeBytes{}))
		if err != nil {
			return err
		}
		go func() {
			for {
				var data []byte
				if err := downstream.RecvMsg(&data); err != nil {
					_ = upstream.CloseSend()
					return
				}
				if method == "/containerd.services.containers.v1.Containers/Get" {
					var request containers.GetContainerRequest
					if proto.Unmarshal(data, &request) == nil {
						target, _ := os.ReadFile(filepath.Join(state, "slow-lookup"))
						if request.ID == strings.TrimSpace(string(target)) {
							timer := time.NewTimer(12 * time.Second)
							select {
							case <-forward.Done():
								timer.Stop()
								return
							case <-timer.C:
							}
						}
					}
				}
				if upstream.SendMsg(&data) != nil {
					return
				}
			}
		}()
		for {
			var data []byte
			if err := upstream.RecvMsg(&data); err != nil {
				downstream.SetTrailer(upstream.Trailer())
				if errors.Is(err, io.EOF) {
					return nil
				}
				return err
			}
			if err := downstream.SendMsg(&data); err != nil {
				return err
			}
		}
	}))
	go func() { _ = server.Serve(listener) }()
	stop := context.AfterFunc(ctx, server.Stop)
	return func() { stop(); server.Stop(); client.Close(); _ = os.Remove(socket) }, nil
}

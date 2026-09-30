package nativerootoci

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json/v2"
	"errors"
	"io"
	"log/slog"
	"net"
	"sync"
	"time"

	"golang.org/x/sys/unix"
)

const MaxFrameBytes = 128 << 10

// Request v1 carries no OCI locator. The host compares both digests with its
// accepted signed member before deriving the single allowed object key.
type Request struct {
	Version           uint64 `json:"version"`
	Operation         string `json:"operation"`
	PublicationDigest string `json:"publication_digest"`
	TargetDigest      string `json:"target_digest"`
	IfMatch           string `json:"if_match,omitempty"`
	RootBase64        string `json:"root_base64,omitempty"`
}

type Response struct {
	Version    uint64 `json:"version"`
	Status     string `json:"status"`
	ETag       string `json:"etag,omitempty"`
	RootBase64 string `json:"root_base64,omitempty"`
}

func (request Request) valid() bool {
	if !lowerDigest.MatchString(request.PublicationDigest) || !lowerDigest.MatchString(request.TargetDigest) {
		return false
	}
	switch request.Operation {
	case "get", "probe_update":
		return request.IfMatch == "" && request.RootBase64 == ""
	case "create":
		return request.IfMatch == "" && validEncodedRoot(request.RootBase64)
	case "update":
		return validETag(request.IfMatch) && validEncodedRoot(request.RootBase64)
	default:
		return false
	}
}

func validEncodedRoot(value string) bool {
	return value != "" && len(value) <= base64.StdEncoding.EncodedLen(MaxRootBytes)
}

// Peer is the kernel's SO_PEERCRED identity for one connected Unix socket.
type Peer struct {
	PID int
	UID uint32
	GID uint32
}

// Authorize must require the current signed desired, exact live process and
// unexpired host session on every call. It returns the current execution lease
// deadline so an in-flight OCI request is canceled when that lease ends.
type Authorize func(context.Context, Peer) (time.Time, error)

// Serve handles at most two connections at once. The listener must be created
// in a verified host-owned per-member directory and removed by the host when
// that member is stopped or replaced. It has no HTTP or network listener.
func Serve(ctx context.Context, listener *net.UnixListener, service *Service, authorize Authorize) error {
	if ctx == nil || listener == nil || service == nil || authorize == nil {
		return errors.New("native OCI root IPC is incomplete")
	}
	stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stop()
	defer listener.Close()
	slots := make(chan struct{}, 2)
	var workers sync.WaitGroup
	defer workers.Wait()
	for {
		connection, err := listener.AcceptUnix()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return errors.New("native OCI root IPC accept failed")
		}
		select {
		case slots <- struct{}{}:
			workers.Go(func() {
				defer func() { <-slots }()
				serveConnection(ctx, connection, service, authorize)
			})
		default:
			_ = connection.Close()
		}
	}
}

func serveConnection(parent context.Context, connection *net.UnixConn, service *Service, authorize Authorize) {
	defer connection.Close()
	ctx, cancel := context.WithTimeout(parent, requestLimit)
	defer cancel()
	stop := context.AfterFunc(ctx, func() { _ = connection.Close() })
	defer stop()
	peer, err := peerCredential(connection)
	if err != nil {
		return
	}
	leaseDeadline, err := authorize(ctx, peer)
	if err != nil || leaseDeadline.IsZero() || !time.Now().Before(leaseDeadline) {
		cause, remaining := "authorization_rejected", time.Duration(0)
		if err == nil {
			cause = "lease_missing"
			if !leaseDeadline.IsZero() {
				cause, remaining = "lease_expired", time.Until(leaseDeadline)
			}
		}
		slog.Warn("native OCI root IPC rejected", "stage", "authorize",
			"cause", cause, "lease_remaining", remaining)
		return
	}
	ctx, leaseCancel := context.WithDeadline(ctx, leaseDeadline)
	defer leaseCancel()
	deadline := time.Now().Add(requestLimit)
	if leaseDeadline.Before(deadline) {
		deadline = leaseDeadline
	}
	_ = connection.SetDeadline(deadline)
	requestBytes, err := readFrame(connection)
	if err != nil {
		return
	}
	var request Request
	if err := json.Unmarshal(requestBytes, &request, json.RejectUnknownMembers(true)); err != nil {
		return
	}
	response := service.Execute(ctx, request, func(ctx context.Context) error {
		_, err := authorize(ctx, peer)
		return err
	})
	wire, err := json.Marshal(response)
	if err == nil {
		_ = writeFrame(connection, wire)
	}
}

func peerCredential(connection *net.UnixConn) (Peer, error) {
	raw, err := connection.SyscallConn()
	if err != nil {
		return Peer{}, err
	}
	var credentials *unix.Ucred
	var socketErr error
	if err := raw.Control(func(fd uintptr) {
		credentials, socketErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return Peer{}, err
	}
	if socketErr != nil || credentials == nil || credentials.Pid <= 0 {
		return Peer{}, errors.New("native OCI root peer credentials are unavailable")
	}
	return Peer{PID: int(credentials.Pid), UID: credentials.Uid, GID: credentials.Gid}, nil
}

func readFrame(reader io.Reader) ([]byte, error) {
	var prefix [4]byte
	if _, err := io.ReadFull(reader, prefix[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(prefix[:])
	if length == 0 || length > MaxFrameBytes {
		return nil, errors.New("native OCI root IPC frame exceeds its bound")
	}
	frame := make([]byte, length)
	_, err := io.ReadFull(reader, frame)
	return frame, err
}

func writeFrame(writer io.Writer, frame []byte) error {
	if len(frame) == 0 || len(frame) > MaxFrameBytes {
		return errors.New("native OCI root IPC response exceeds its bound")
	}
	var prefix [4]byte
	binary.BigEndian.PutUint32(prefix[:], uint32(len(frame)))
	if err := writeAll(writer, prefix[:]); err != nil {
		return err
	}
	return writeAll(writer, frame)
}

func writeAll(writer io.Writer, bytes []byte) error {
	for len(bytes) > 0 {
		written, err := writer.Write(bytes)
		if err != nil {
			return err
		}
		if written <= 0 || written > len(bytes) {
			return io.ErrShortWrite
		}
		bytes = bytes[written:]
	}
	return nil
}

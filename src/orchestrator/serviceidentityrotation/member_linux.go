//go:build linux

package serviceidentityrotation

import (
	"context"
	"encoding/json/v2"
	"golang.org/x/sys/unix"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strconv"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/serviceidentity"
	"time"
)

const MemberPath = "/internal/v1/identity/service-key"

type MemberRequest struct {
	Version    string `json:"version"`
	Generation uint64 `json:"generation"`
	Secret     string `json:"secret"`
}
type MemberReceipt struct {
	Version    string `json:"version"`
	Generation uint64 `json:"generation"`
	State      string `json:"state"`
}

// DeliverLocal authenticates the engine socket peer before transmitting bytes.
func DeliverLocal(ctx context.Context, socket string, request MemberRequest) error {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket || request.Generation == 0 || request.Version == "" || len(request.Version) > 128 || len(request.Secret) != 43 {
		return ErrRotation
	}
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
		if err != nil {
			return nil, ErrRotation
		}
		raw, err := conn.(*net.UnixConn).SyscallConn()
		if err != nil {
			conn.Close()
			return nil, ErrRotation
		}
		var cred *unix.Ucred
		var inner error
		if raw.Control(func(fd uintptr) { cred, inner = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }) != nil || inner != nil || cred == nil || cred.Uid != serviceidentity.TerraBaseUID {
			conn.Close()
			return nil, ErrRotation
		}
		return conn, nil
	}}
	defer transport.CloseIdleConnections()
	for _, v := range request.Secret {
		if !(v >= 'a' && v <= 'z' || v >= 'A' && v <= 'Z' || v >= '0' && v <= '9' || v == '_' || v == '-') {
			return ErrRotation
		}
	}
	version, err := json.Marshal(request.Version)
	if err != nil {
		return ErrRotation
	}
	buffer, err := hostsecrets.NewSecretBuffer(2048)
	if err != nil {
		return ErrRotation
	}
	defer buffer.Close()
	payload := buffer.Bytes()[:0]
	payload = append(payload, `{"version":`...)
	payload = append(payload, version...)
	payload = append(payload, `,"generation":`...)
	payload = strconv.AppendUint(payload, request.Generation, 10)
	payload = append(payload, `,"secret":"`...)
	payload = append(payload, request.Secret...)
	payload = append(payload, `"}`...)
	protected := hostsecrets.SecretRequestBody(payload)
	defer protected.Close()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://member"+MemberPath, protected)
	if err != nil {
		return ErrRotation
	}
	req.Header.Set("Content-Type", "application/json")
	client := &http.Client{Transport: transport, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	response, err := client.Do(req)
	if err != nil {
		return ErrRotation
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 2049))
	defer clear(body)
	var receipt MemberReceipt
	if err != nil || len(body) > 2048 || response.StatusCode != 200 || json.Unmarshal(body, &receipt) != nil || receipt.State != "adopted" || receipt.Version != request.Version || receipt.Generation != request.Generation {
		return ErrRotation
	}
	return nil
}

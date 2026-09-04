package sandboxvm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

// OpenAPI is intentionally limited to operations that are not consistently
// exposed by the pinned SDK. Lifecycle code uses it for the Firecracker
// version/inspection endpoints and VM state patch (not shell commands).
type OpenAPI interface {
	Version(context.Context) (string, error)
	Inspect(context.Context) (Inspection, error)
	PatchVM(context.Context, string) error
}

type UnixSocketOpenAPI struct {
	SocketPath       string
	Client           *http.Client
	MaxResponseBytes int64
}

func NewUnixSocketOpenAPI(socketPath string) (*UnixSocketOpenAPI, error) {
	if err := validateSocketName(socketPath); err != nil {
		return nil, err
	}
	return &UnixSocketOpenAPI{SocketPath: socketPath, MaxResponseBytes: 1 << 20}, nil
}

func (c *UnixSocketOpenAPI) client() *http.Client {
	if c.Client != nil {
		return c.Client
	}
	return &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "unix", c.SocketPath)
	}, DisableKeepAlives: true}, Timeout: 5 * time.Second}
}

func (c *UnixSocketOpenAPI) request(ctx context.Context, method, path string, body any, response any) error {
	if c == nil || c.SocketPath == "" {
		return errors.New("Firecracker API client is not configured")
	}
	var r io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return err
		}
		r = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, "http://firecracker"+path, r)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.client().Do(req)
	if err != nil {
		return fmt.Errorf("Firecracker API %s %s: %w", method, path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("Firecracker API %s %s: status %s", method, path, resp.Status)
	}
	if response == nil {
		return nil
	}
	limit := c.MaxResponseBytes
	if limit <= 0 {
		limit = 1 << 20
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, limit))
	if err := dec.Decode(response); err != nil {
		return fmt.Errorf("decode Firecracker API %s: %w", path, err)
	}
	return nil
}

func (c *UnixSocketOpenAPI) Version(ctx context.Context) (string, error) {
	var response struct {
		Version string `json:"firecracker_version"`
	}
	if err := c.request(ctx, http.MethodGet, "/version", nil, &response); err != nil {
		return "", err
	}
	if response.Version == "" {
		return "", errors.New("Firecracker API returned an empty version")
	}
	return response.Version, nil
}

func (c *UnixSocketOpenAPI) Inspect(ctx context.Context) (Inspection, error) {
	var response struct {
		State      string `json:"state"`
		ID         string `json:"id"`
		VMMVersion string `json:"vmm_version"`
	}
	if err := c.request(ctx, http.MethodGet, "/instance-info", nil, &response); err != nil {
		return Inspection{}, err
	}
	return Inspection{State: State(strings.ToLower(response.State)), SocketReady: true, Version: response.VMMVersion}, nil
}

func (c *UnixSocketOpenAPI) PatchVM(ctx context.Context, state string) error {
	state = strings.TrimSpace(state)
	if state != "Reboot" && state != "Paused" && state != "Resumed" {
		return fmt.Errorf("unsupported Firecracker VM state %q", state)
	}
	return c.request(ctx, http.MethodPatch, "/vm", map[string]string{"state": state}, nil)
}

// SocketReady performs the minimal host-side socket validation used before a
// direct API call. It does not imply guest readiness.
func SocketReady(path string) bool {
	info, err := os.Lstat(path)
	return err == nil && info.Mode()&os.ModeSocket != 0
}

// ValidateSocketPath rejects regular files, symlinks, and pre-existing
// sockets. Reusing any pre-existing endpoint is unsafe because it may belong
// to a different VMM; cleanup can only remove a socket after ownership has
// been established by the VM state marker.
func ValidateSocketPath(path string) error {
	if err := validateSocketName(path); err != nil {
		return err
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSocket != 0 {
			return fmt.Errorf("Firecracker API socket already exists: %s", path)
		}
		return fmt.Errorf("Firecracker API socket path exists and is not a socket: %s", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("inspect Firecracker API socket: %w", err)
	}
	return nil
}

func validateSocketName(path string) error {
	if path == "" || !strings.HasPrefix(path, "/") || strings.IndexByte(path, 0) >= 0 {
		return errors.New("Firecracker API socket must be an absolute pathname socket")
	}
	if len(path) > maxUnixSocketPathBytes {
		return fmt.Errorf("Firecracker API socket path is %d bytes; Linux permits at most %d", len(path), maxUnixSocketPathBytes)
	}
	return nil
}

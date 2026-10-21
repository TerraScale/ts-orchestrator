package host

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// MeasureIdentity observes fixed local component files and OCI IMDSv2 metadata.
// The parent must independently authenticate the instance/image relationship.
func MeasureIdentity(ctx context.Context, containerdPath, runcPath string) (Identity, error) {
	identity := Identity{Architecture: runtime.GOARCH}
	wire, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return identity, err
	}
	identity.KernelRelease = strings.TrimSpace(string(wire))
	if strings.ContainsAny(identity.KernelRelease, "/\\") {
		return identity, errors.New("invalid running kernel release")
	}
	paths := []string{"/boot/vmlinuz-" + identity.KernelRelease, "/usr/local/bin/terrascale-orchestrator", containerdPath, runcPath}
	hashes := []*string{&identity.KernelSHA256, &identity.BinarySHA256, &identity.ContainerdSHA256, &identity.RuncSHA256}
	for i, path := range paths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path {
			return identity, errors.New("component path must be absolute and clean")
		}
		wire, err := os.ReadFile(path)
		if err != nil {
			return identity, err
		}
		*hashes[i] = digest(wire)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://169.254.169.254/opc/v2/instance/", nil)
	if err != nil {
		return identity, err
	}
	req.Header.Set("Authorization", "Bearer Oracle")
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	result, err := client.Do(req)
	if err != nil {
		return identity, err
	}
	defer result.Body.Close()
	if result.StatusCode != http.StatusOK {
		return identity, errors.New("IMDSv2 instance identity unavailable")
	}
	var metadata struct {
		ID    string `json:"id"`
		Image string `json:"image"`
	}
	if err := json.UnmarshalRead(io.LimitReader(result.Body, maxFrame), &metadata); err != nil {
		return identity, err
	}
	if !strings.HasPrefix(metadata.ID, "ocid1.instance.") || !strings.HasPrefix(metadata.Image, "ocid1.image.") {
		return identity, errors.New("IMDSv2 omitted Compute or boot image identity")
	}
	identity.InstanceID, identity.ImageOCID = metadata.ID, metadata.Image
	return identity, nil
}

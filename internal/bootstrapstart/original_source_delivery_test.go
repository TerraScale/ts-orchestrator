package bootstrapstart

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestOriginalBundleDescriptor(t *testing.T) {
	digest := strings.Repeat("a", 64)
	for _, test := range []struct {
		name, body, want string
		status           int
		invalid          bool
	}{
		{name: "absent metadata", status: http.StatusNotFound},
		{name: "ordinary controller", status: http.StatusOK, body: `{"schemaVersion":1,"slot":"controller-a"}`},
		{name: "original", status: http.StatusOK, body: fmt.Sprintf(`{"schemaVersion":1,"slot":"controller-a","originalBundleSha256":%q}`, digest), want: digest},
		{name: "empty present", status: http.StatusOK, body: `{"schemaVersion":1,"slot":"controller-a","originalBundleSha256":""}`, invalid: true},
		{name: "null present", status: http.StatusOK, body: `{"schemaVersion":1,"slot":"controller-a","originalBundleSha256":null}`, invalid: true},
		{name: "uppercase", status: http.StatusOK, body: fmt.Sprintf(`{"schemaVersion":1,"slot":"controller-a","originalBundleSha256":%q}`, strings.ToUpper(digest)), invalid: true},
		{name: "short digest", status: http.StatusOK, body: `{"schemaVersion":1,"slot":"controller-a","originalBundleSha256":"ab"}`, invalid: true},
		{name: "peer", status: http.StatusOK, body: fmt.Sprintf(`{"schemaVersion":1,"slot":"controller-b","originalBundleSha256":%q}`, digest), invalid: true},
		{name: "unknown field", status: http.StatusOK, body: fmt.Sprintf(`{"schemaVersion":1,"slot":"controller-a","originalBundleSha256":%q,"bucket":"foreign"}`, digest), invalid: true},
		{name: "duplicate digest", status: http.StatusOK, body: fmt.Sprintf(`{"schemaVersion":1,"slot":"controller-a","originalBundleSha256":%q,"originalBundleSha256":%q}`, digest, digest), invalid: true},
		{name: "request refusal", status: http.StatusForbidden, body: "refused", invalid: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
				if request.Host != "169.254.169.254" || request.URL.RequestURI() != "/opc/v2/instance/metadata/terrascale-bootstrap" ||
					request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer Oracle" ||
					request.Header.Get("Forwarded") != "" || request.Header.Get("X-Forwarded-For") != "" || request.Header.Get("X-Forwarded-Host") != "" {
					t.Error("original descriptor left fixed IMDS endpoint")
					w.WriteHeader(http.StatusBadRequest)
					return
				}
				w.WriteHeader(test.status)
				io.WriteString(w, test.body)
			}))
			t.Cleanup(server.Close)
			listener, ok := server.Listener.Addr().(*net.TCPAddr)
			if !ok || !listener.IP.IsLoopback() || listener.Port == 0 {
				t.Fatal("IMDS fixture requires literal loopback HTTP")
			}
			imds := NewIMDSClient()
			transport := imds.client.Transport.(*http.Transport)
			transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
				if network != "tcp" || address != imdsAddress {
					return nil, ErrInvalidDescriptor
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp", listener.String())
			}
			t.Cleanup(transport.CloseIdleConnections)
			got, err := imds.FetchOriginalBundleSHA256(t.Context())
			if test.invalid {
				if !errors.Is(err, ErrInvalidDescriptor) || got != "" {
					t.Fatalf("invalid original descriptor accepted: %q %v", got, err)
				}
			} else if err != nil || got != test.want {
				t.Fatalf("original descriptor = %q %v, want %q", got, err, test.want)
			}
		})
	}
}

func originalPublicStore(t *testing.T) bakedStore {
	t.Helper()
	directory := filepath.Join(t.TempDir(), "bootstrap")
	if err := os.Mkdir(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(directory, 0o755); err != nil {
		t.Fatal(err)
	}
	return bakedStore{directory: directory, ownerUID: uint32(os.Getuid()), ownerGID: uint32(os.Getgid()), allowUnsafeAncestors: true}
}

func TestOriginalPublicStorePreservesExactBytes(t *testing.T) {
	store := originalPublicStore(t)
	wire := []byte(`{"public":"signed bundle"}`)
	for range 2 {
		if err := store.installOriginalFoundationPublic(wire); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(store.directory, OriginalFoundationPublicFilename)
	got, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatal("public artifact did not retain exact bytes")
	}
	info, err := os.Stat(path)
	if err != nil || info.Mode().Perm() != 0o444 {
		t.Fatal("public artifact is not read-only")
	}
	if err := store.installOriginalFoundationPublic([]byte(`{"public":"different"}`)); err == nil {
		t.Fatal("different bytes replaced original public artifact")
	}
	got, err = os.ReadFile(path)
	if err != nil || !bytes.Equal(got, wire) {
		t.Fatal("conflicting retry changed original bytes")
	}
	entries, err := os.ReadDir(store.directory)
	if err != nil || len(entries) != 1 || entries[0].Name() != OriginalFoundationPublicFilename {
		t.Fatal("public delivery wrote identity, anchor, marker or temporary artifact")
	}
}

func TestOriginalPublicStoreRejectsUnsafeFiles(t *testing.T) {
	for _, kind := range []string{"symlink", "hardlink", "writable", "directory", "empty", "oversized"} {
		t.Run(kind, func(t *testing.T) {
			store := originalPublicStore(t)
			path := filepath.Join(store.directory, OriginalFoundationPublicFilename)
			wire := []byte("public")
			var err error
			switch kind {
			case "symlink", "hardlink":
				target := filepath.Join(t.TempDir(), "target")
				if err := os.WriteFile(target, wire, 0o444); err != nil {
					t.Fatal(err)
				}
				if kind == "symlink" {
					err = os.Symlink(target, path)
				} else {
					err = os.Link(target, path)
				}
			case "writable":
				err = os.WriteFile(path, wire, 0o644)
			case "directory":
				err = os.Mkdir(path, 0o755)
			case "empty":
				wire = nil
			case "oversized":
				wire = bytes.Repeat([]byte("x"), MaxOriginalFoundationPublicBytes+1)
			}
			if err != nil {
				t.Fatal(err)
			}
			if err := store.installOriginalFoundationPublic(wire); err == nil {
				t.Fatal("unsafe original public artifact accepted")
			}
		})
	}
}

package keylease

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"testing"
	"time"
)

func fixtureEntry() Entry {
	return Entry{Binding: Binding{Environment: "production", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FAW", DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FAX", KeyVersion: "01ARZ3NDEKTSV4RRFFQ69G5FAY", Region: "GRU", Purpose: "data"}, CryptoEndpoint: "fixture-crypto.kms.sa-saopaulo-1.oraclecloud.com", KEKID: "ocid1.key.oc1.sa-saopaulo-1.fixture", KEKVersionID: "ocid1.keyversion.oc1.sa-saopaulo-1.fixture", Ciphertext: "wrapped-only", LeaseSeconds: 30, NotAfter: time.Now().Add(time.Hour)}
}
func fixture(t *testing.T) (Config, Catalog) {
	t.Helper()
	home, err := os.UserHomeDir()
	if err != nil {
		t.Fatal(err)
	}
	dir, err := os.MkdirTemp(home, ".keylease-test-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	socketDir := filepath.Join(dir, "socket")
	if err := os.Mkdir(socketDir, 0710); err != nil {
		t.Fatal(err)
	}
	entry := fixtureEntry()
	entry.CryptoEndpoint = "https://" + entry.CryptoEndpoint
	config := Config{SocketPath: filepath.Join(socketDir, "lease.sock"), CatalogPath: filepath.Join(dir, "catalog.json"), Environment: "production", Region: "GRU", AllowedUID: uint32(os.Geteuid()), SocketGID: uint32(os.Getegid())}
	catalog := Catalog{Version: 1, Entries: []Entry{entry}}
	if err := WriteCatalog(config.CatalogPath, catalog); err != nil {
		t.Fatal(err)
	}
	return config, catalog
}
func bindingWire(b Binding) []byte {
	body := []byte{'T', 'B', 'K', 'L', 1}
	for _, s := range []string{b.Environment, b.TenantID, b.ProjectID, b.DatabaseID, b.KeyVersion, b.Region, b.Purpose} {
		body = binary.BigEndian.AppendUint16(body, uint16(len(s)))
		body = append(body, s...)
	}
	return append(binary.BigEndian.AppendUint32(nil, uint32(len(body))), body...)
}
func request(t *testing.T, path string, b Binding) []byte {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err = c.Write(bindingWire(b)); err != nil {
		t.Fatal(err)
	}
	var prefix [4]byte
	if _, err = io.ReadFull(c, prefix[:]); err != nil {
		t.Fatal(err)
	}
	size := binary.BigEndian.Uint32(prefix[:])
	if size > maximumFrame {
		t.Fatal("response oversized")
	}
	body := make([]byte, size)
	if _, err = io.ReadFull(c, body); err != nil {
		t.Fatal(err)
	}
	return body
}

func successKey(body []byte) ([]byte, bool) {
	if len(body) != 68 || body[0] != 'T' || body[1] != 'B' || body[2] != 'K' || body[3] != 'L' || body[4] != 1 || body[5] != 0 {
		return nil, false
	}
	return body[36:], true
}

func writeCatalogWithRetry(ctx context.Context, path string, catalog Catalog) error {
	deadline := time.Now().Add(2 * time.Second)
	for {
		err := WriteCatalog(path, catalog)
		if err == nil {
			return nil
		}
		if !errors.Is(err, ErrUnavailable) {
			return err
		}
		wait := time.NewTimer(5 * time.Millisecond)
		select {
		case <-ctx.Done():
			wait.Stop()
			return ctx.Err()
		case <-wait.C:
		}
		if time.Until(deadline) <= 0 {
			return ErrUnavailable
		}
	}
}

func TestLeaseRestartRotationAndRevocation(t *testing.T) {
	config, catalog := fixture(t)
	calls := 0
	unwrap := func(_ context.Context, e Entry) (*hostsecrets.DataKey, error) {
		calls++
		if e.Ciphertext == "wrapped-rotated" {
			return testDataKey(t, 2), nil
		}
		return testDataKey(t, 1), nil
	}
	server, err := start(t.Context(), config, unwrap)
	if err != nil {
		t.Fatal(err)
	}
	body := request(t, config.SocketPath, catalog.Entries[0].Binding)
	if len(body) != 68 || body[5] != 0 || binary.BigEndian.Uint32(body[6:10]) != 30 || !bytes.Equal(body[36:], bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("incorrect success binding")
	}
	server.Close()
	server, err = start(t.Context(), config, unwrap)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	body = request(t, config.SocketPath, catalog.Entries[0].Binding)
	if _, ok := successKey(body); !ok {
		t.Fatal("restart lost key")
	}
	rotated := catalog.Entries[0]
	rotated.Binding.KeyVersion = "01ARZ3NDEKTSV4RRFFQ69G5FAZ"
	rotated.Ciphertext = "wrapped-rotated"
	catalog.Entries = append(catalog.Entries, rotated)
	if WriteCatalog(config.CatalogPath, catalog) != nil {
		t.Fatal("rotation failed")
	}
	rotatedBody := request(t, config.SocketPath, rotated.Binding)
	rotatedKey, ok := successKey(rotatedBody)
	if !ok || !bytes.Equal(rotatedKey, bytes.Repeat([]byte{2}, 32)) {
		t.Fatal("new version not selected")
	}
	body = request(t, config.SocketPath, catalog.Entries[0].Binding)
	oldKey, ok := successKey(body)
	if !ok || !bytes.Equal(oldKey, bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("old readable version substituted")
	}
	catalog.Entries[0].Revoked = true
	if err := writeCatalogWithRetry(t.Context(), config.CatalogPath, catalog); err != nil {
		t.Fatalf("revocation failed: %v", err)
	}
	before := calls
	if body = request(t, config.SocketPath, catalog.Entries[0].Binding); !bytes.Equal(body, []byte{'T', 'B', 'K', 'L', 1, 1}) || calls != before {
		t.Fatal("revoked key reached Vault")
	}
	missing := rotated.Binding
	missing.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	if body = request(t, config.SocketPath, missing); len(body) != 6 || calls != before {
		t.Fatal("scope mismatch reached Vault")
	}
	stored, err := os.ReadFile(config.CatalogPath)
	if err != nil || bytes.Contains(stored, bytes.Repeat([]byte{1}, 32)) {
		t.Fatal("plaintext persisted")
	}
}
func TestRevocationDuringUnwrapAndSanitizedFailure(t *testing.T) {
	for _, failure := range []bool{false, true} {
		t.Run(map[bool]string{false: "revoke", true: "provider-error"}[failure], func(t *testing.T) {
			config, catalog := fixture(t)
			server, err := start(t.Context(), config, func(_ context.Context, _ Entry) (*hostsecrets.DataKey, error) {
				if failure {
					return nil, errors.New("SECRET PROVIDER RESPONSE")
				}
				catalog.Entries[0].Revoked = true
				if WriteCatalog(config.CatalogPath, catalog) != nil {
					t.Error("persist revocation")
				}
				return testDataKey(t, 3), nil
			})
			if err != nil {
				t.Fatal(err)
			}
			defer server.Close()
			body := request(t, config.SocketPath, catalog.Entries[0].Binding)
			if !bytes.Equal(body, []byte{'T', 'B', 'K', 'L', 1, 1}) {
				t.Fatal("failure disclosed key or provider error")
			}
		})
	}
}
func TestRejectsUnsafeFilesystemAndProtocol(t *testing.T) {
	config, _ := fixture(t)
	if err := os.Chmod(config.CatalogPath, 0644); err != nil {
		t.Fatal(err)
	}
	if _, err := Start(t.Context(), config); err == nil {
		t.Fatal("unsafe catalog accepted")
	}
	if _, err := readBinding(bytes.NewReader([]byte{0, 0, 16, 0})); err == nil {
		t.Fatal("oversized frame accepted")
	}
	config, _ = fixture(t)
	config.SocketGID++
	if _, err := Start(t.Context(), config); err == nil {
		t.Fatal("wrong socket group accepted")
	}
}

func TestTBCKRequestUsesCustomerAuthority(t *testing.T) {
	config, catalog := fixture(t)
	called := false
	config.Customer = &CustomerConfig{Authority: customerAuthorityFunc(func(_ context.Context, b Binding, ciphertext string) (*hostsecrets.DataKey, error) {
		called = true
		if b != catalog.Entries[0].Binding || ciphertext != catalog.Entries[0].Ciphertext {
			return nil, ErrUnavailable
		}
		return testDataKey(t, 9), nil
	})}
	server, err := start(t.Context(), config, func(context.Context, Entry) (*hostsecrets.DataKey, error) {
		t.Fatal("TBCK request reached OCI authority")
		return nil, ErrUnavailable
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	body := requestProtocol(t, config.SocketPath, catalog.Entries[0].Binding, "TBCK")
	if len(body) != 68 || string(body[:4]) != "TBCK" || body[5] != 0 || !bytes.Equal(body[36:], bytes.Repeat([]byte{9}, 32)) || !called {
		t.Fatalf("TBCK response/call invalid: %x called=%v", body, called)
	}
}

type customerAuthorityFunc func(context.Context, Binding, string) (*hostsecrets.DataKey, error)

func (f customerAuthorityFunc) Unwrap(ctx context.Context, b Binding, ciphertext string) (*hostsecrets.DataKey, error) {
	return f(ctx, b, ciphertext)
}

func requestProtocol(t *testing.T, path string, b Binding, protocol string) []byte {
	t.Helper()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	body := bindingWire(b)
	copy(body[4:], protocol)
	if _, err = c.Write(body); err != nil {
		t.Fatal(err)
	}
	var prefix [4]byte
	if _, err = io.ReadFull(c, prefix[:]); err != nil {
		t.Fatal(err)
	}
	response := make([]byte, binary.BigEndian.Uint32(prefix[:]))
	if _, err = io.ReadFull(c, response); err != nil {
		t.Fatal(err)
	}
	return response
}

func TestMalformedAndTruncatedRequestsReceiveRefusal(t *testing.T) {
	config, _ := fixture(t)
	server, err := start(t.Context(), config, func(context.Context, Entry) (*hostsecrets.DataKey, error) {
		t.Error("invalid request reached Vault")
		return nil, ErrUnavailable
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()

	for name, frame := range map[string][]byte{
		"malformed body": append(binary.BigEndian.AppendUint32(nil, 5), []byte("BAD!!")...),
		"truncated body": append(binary.BigEndian.AppendUint32(nil, 10), []byte("TBK")...),
	} {
		t.Run(name, func(t *testing.T) {
			connection, err := net.DialUnix("unix", nil, &net.UnixAddr{Name: config.SocketPath, Net: "unix"})
			if err != nil {
				t.Fatal(err)
			}
			defer connection.Close()
			if _, err := connection.Write(frame); err != nil {
				t.Fatal(err)
			}
			if name == "truncated body" {
				if err := connection.CloseWrite(); err != nil {
					t.Fatal(err)
				}
			}
			if err := connection.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			var prefix [4]byte
			if _, err := io.ReadFull(connection, prefix[:]); err != nil {
				t.Fatal(err)
			}
			if got := binary.BigEndian.Uint32(prefix[:]); got != 6 {
				t.Fatalf("refusal length = %d, want 6", got)
			}
			body := make([]byte, 6)
			if _, err := io.ReadFull(connection, body); err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(body, []byte{'T', 'B', 'K', 'L', 1, 1}) {
				t.Fatalf("refusal = %x", body)
			}
		})
	}
}

func testDataKey(t *testing.T, value byte) *hostsecrets.DataKey {
	t.Helper()
	key, err := hostsecrets.NewDataKey()
	if err != nil {
		t.Fatal(err)
	}
	for i := range key.Bytes() {
		key.Bytes()[i] = value
	}
	return key
}

func TestSocketPeerUIDRefusesOtherGroupMember(t *testing.T) {
	config, _ := fixture(t)
	config.AllowedUID++
	server, err := start(t.Context(), config, func(context.Context, Entry) (*hostsecrets.DataKey, error) {
		t.Error("unlisted UID reached Vault")
		return nil, ErrUnavailable
	})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	c, err := net.Dial("unix", config.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(time.Second))
	var body [1]byte
	if _, err := c.Read(body[:]); err == nil {
		t.Fatal("unlisted UID received data")
	}
}

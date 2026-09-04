package hostagent

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// memoryDownloader serves release files from a map; it is the fake of the
// downloader seam for filesystem tests under t.TempDir().
type memoryDownloader struct {
	files    map[string][]byte
	failUrls map[string]error
}

func TestDownloadClientRejectsRedirectOutsideHTTPSAllowlist(t *testing.T) {
	var attackerHits int
	attacker := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { attackerHits++ }))
	defer attacker.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL, http.StatusFound)
	}))
	defer redirect.Close()
	client := redirect.Client()
	originalRedirect := func(*http.Request, []*http.Request) error { return nil }
	client.CheckRedirect = originalRedirect
	target := filepath.Join(t.TempDir(), "artifact")
	err := (DownloadClient{Client: client, AllowedHosts: []string{redirect.Listener.Addr().String()}}).Download(
		redirect.URL+"/artifact", target, 1024)
	if err == nil {
		t.Fatal("cross-host redirect accepted")
	}
	if attackerHits != 0 {
		t.Fatalf("redirect target contacted %d times", attackerHits)
	}
	if reflect.ValueOf(client.CheckRedirect).Pointer() != reflect.ValueOf(originalRedirect).Pointer() {
		t.Fatal("caller redirect policy was mutated")
	}
}

func TestDownloadClientRejectsUnsafeTargetPath(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("x")) }))
	defer server.Close()
	if err := (DownloadClient{Client: server.Client()}).Download(server.URL, "relative/../artifact", 32); err == nil {
		t.Fatal("relative traversal target accepted")
	}
}

func (m memoryDownloader) Download(url string, target string, limitBytes int64) error {
	if err, present := m.failUrls[url]; present {
		return err
	}
	body, present := m.files[url]
	if !present {
		return &InvalidDataError{Message: "no such release file"}
	}
	return os.WriteFile(target, body, 0o600)
}

// signedRelease builds one artifact, its sha256, and its detached raw
// signature under the given key.
func signedRelease(t *testing.T, seed string, privateKey ed25519.PrivateKey) (artifact []byte, signature string, sha256Hex string) {
	t.Helper()
	artifact = []byte("terrascale release " + seed)
	signature = string(ed25519.Sign(privateKey, artifact))
	digest := sha256.Sum256(artifact)
	return artifact, signature, hex.EncodeToString(digest[:])
}

func newTestInstaller(t *testing.T, root string, key ed25519.PrivateKey, files map[string][]byte, failUrls map[string]error) *Installer {
	t.Helper()
	publicKey := key.Public().(ed25519.PublicKey)
	installer, err := NewInstaller(InstallerConfig{
		InstallRoot:  root,
		PublicKeyHex: hex.EncodeToString(publicKey),
		Downloader:   memoryDownloader{files: files, failUrls: failUrls},
	})
	if err != nil {
		t.Fatalf("installer construction failed: %v", err)
	}
	return installer
}

func installTestURLs(version string) (artifactURL, signatureURL string) {
	base := "https://releases.terrascale.tech/terrabase/" + version
	return base + "/terrabase", base + "/terrabase.sig"
}

// TestInstallVerifiedRelease asserts the happy path: the verified bytes land
// at /<root>/<component>/<version>/<component>, executable, no staging left.
func TestInstallVerifiedRelease(t *testing.T) {
	root := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact, signature, sha256Hex := signedRelease(t, "1.2.3", privateKey)
	artifactURL, signatureURL := installTestURLs("1.2.3")
	installer := newTestInstaller(t, root, privateKey, map[string][]byte{
		artifactURL: artifact, signatureURL: []byte(signature),
	}, nil)
	spec := testComponentSpec()
	spec.Sha256 = sha256Hex

	versionDir, err := installer.Install(spec)
	if err != nil {
		t.Fatalf("install failed: %v", err)
	}
	if versionDir != root+"/terrabase/1.2.3" {
		t.Fatalf("unexpected version dir %s", versionDir)
	}
	installed, err := os.ReadFile(filepath.Join(versionDir, "terrabase"))
	if err != nil || string(installed) != string(artifact) {
		t.Fatalf("installed bytes differ: %v %q", err, installed)
	}
	info, err := os.Stat(filepath.Join(versionDir, "terrabase"))
	if err != nil || info.Mode().Perm() != 0o755 {
		t.Fatalf("installed binary not executable: %v %v", err, info)
	}
	if !InstalledVersion(root, "terrabase", "1.2.3") {
		t.Fatal("InstalledVersion does not see the release")
	}
}

// TestInstallFailsClosedOnBadSignature asserts a wrong key fails and leaves
// neither a version directory nor staging behind.
func TestInstallFailsClosedOnBadSignature(t *testing.T) {
	root := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact, signature, sha256Hex := signedRelease(t, "1.2.3", wrongKey)
	artifactURL, signatureURL := installTestURLs("1.2.3")
	installer := newTestInstaller(t, root, privateKey, map[string][]byte{
		artifactURL: artifact, signatureURL: []byte(signature),
	}, nil)
	spec := testComponentSpec()
	spec.Sha256 = sha256Hex

	if _, err := installer.Install(spec); err == nil {
		t.Fatal("bad signature accepted")
	}
	assertNoPartialDir(t, root, "1.2.3")
}

// TestInstallFailsClosedOnBadSha256 asserts a digest mismatch fails closed
// even when the signature is valid for different bytes.
func TestInstallFailsClosedOnBadSha256(t *testing.T) {
	root := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifact, signature, _ := signedRelease(t, "1.2.3", privateKey)
	artifactURL, signatureURL := installTestURLs("1.2.3")
	installer := newTestInstaller(t, root, privateKey, map[string][]byte{
		artifactURL: artifact, signatureURL: []byte(signature),
	}, nil)
	spec := testComponentSpec()
	spec.Sha256 = strings.Repeat("ab", 32)

	if _, err := installer.Install(spec); err == nil {
		t.Fatal("sha256 mismatch accepted")
	}
	assertNoPartialDir(t, root, "1.2.3")
}

// TestInstallFailsClosedOnDownloadFailure asserts a failed download leaves
// no partial version directory.
func TestInstallFailsClosedOnDownloadFailure(t *testing.T) {
	root := t.TempDir()
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	artifactURL, signatureURL := installTestURLs("1.2.3")
	installer := newTestInstaller(t, root, privateKey, map[string][]byte{
		artifactURL: []byte("bytes"),
	}, map[string]error{signatureURL: &InvalidDataError{Message: "network"}})
	if _, err := installer.Install(testComponentSpec()); err == nil {
		t.Fatal("failed download accepted")
	}
	assertNoPartialDir(t, root, "1.2.3")
}

func assertNoPartialDir(t *testing.T, root, version string) {
	t.Helper()
	componentDir := filepath.Join(root, "terrabase")
	entries, err := os.ReadDir(componentDir)
	if os.IsNotExist(err) {
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), version) {
			t.Fatalf("partial directory left behind: %s", entry.Name())
		}
	}
}

// TestDecodeEd25519Signature covers both published spellings.
func TestDecodeEd25519Signature(t *testing.T) {
	signature := make([]byte, ed25519.SignatureSize)
	for index := range signature {
		signature[index] = byte(index)
	}
	raw, err := decodeEd25519Signature(signature)
	if err != nil || string(raw) != string(signature) {
		t.Fatalf("raw signature rejected: %v", err)
	}
	hexSignature := []byte(hex.EncodeToString(signature) + "\n")
	raw, err = decodeEd25519Signature(hexSignature)
	if err != nil || string(raw) != string(signature) {
		t.Fatalf("hex signature rejected: %v", err)
	}
	if _, err := decodeEd25519Signature([]byte("junk")); err == nil {
		t.Fatal("junk signature accepted")
	}
}

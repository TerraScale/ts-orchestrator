package terrabase

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/pem"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestParseProfile(t *testing.T) {
	peers := "gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443"
	profile, err := ParseProfile(map[string]string{EnvPeerPort: "9443", EnvClientPort: "9465", EnvPeers: peers})
	if err != nil {
		t.Fatal(err)
	}
	if profile.AdminPort != DefaultAdminPort || profile.PeerPort != 9443 || profile.ClientPort != 9465 || len(profile.Peers) != 2 {
		t.Fatalf("profile %+v", profile)
	}
	if peer, ok := profile.Peer("gru-1-db-2"); !ok || peer.Address.String() != "10.251.0.22:9443" {
		t.Fatalf("peer lookup %+v %v", peer, ok)
	}
	if _, ok := profile.Peer("gru-1-db-3"); ok {
		t.Fatal("unlisted node resolved")
	}
	for name, env := range map[string]map[string]string{
		"missing peer port":  {EnvPeers: peers},
		"missing peers":      {EnvPeerPort: "9443"},
		"bad port":           {EnvPeerPort: "09443", EnvPeers: peers},
		"peer on other port": {EnvPeerPort: "9444", EnvPeers: peers},
		"admin equals peer":  {EnvPeerPort: "9443", EnvAdminPort: "9443", EnvPeers: peers},
		"host-owned key":     {EnvPeerPort: "9443", EnvPeers: peers, EnvDataDirectory: "/tmp"},
		"bundle dir":         {EnvPeerPort: "9443", EnvPeers: peers, EnvBundleExtract: "/tmp"},
		"repeated name":      {EnvPeerPort: "9443", EnvPeers: "a=10.0.0.1:9443,a=10.0.0.2:9443"},
		"repeated address":   {EnvPeerPort: "9443", EnvPeers: "a=10.0.0.1:9443,b=10.0.0.1:9443"},
		"hostname address":   {EnvPeerPort: "9443", EnvPeers: "a=db.internal:9443"},
		"unspecified":        {EnvPeerPort: "9443", EnvPeers: "a=0.0.0.0:9443"},
		"bad name":           {EnvPeerPort: "9443", EnvPeers: "Gru=10.0.0.1:9443"},
		"empty entry":        {EnvPeerPort: "9443", EnvPeers: "a=10.0.0.1:9443,"},
	} {
		if _, err := ParseProfile(env); err == nil {
			t.Errorf("%s: accepted %v", name, env)
		}
	}
}

func TestParsePeersRejectsScopedAddresses(t *testing.T) {
	for _, address := range []string{"[fe80::1%eth0]:7443", "[2001:db8::1%eth0]:7443", "[fe80::1]:7443",
		"169.254.1.2:7443", "[::ffff:169.254.1.2]:7443", "[ff02::1]:7443", "224.0.0.1:7443"} {
		_, err := ParsePeers("gru-1-db-1=" + address)
		if err == nil || !strings.Contains(err.Error(), "zone identifiers and link-local addresses are not supported") {
			t.Errorf("address %s: got %v", address, err)
		}
	}
	if _, err := ParseProfile(map[string]string{EnvPeerPort: "7443",
		EnvPeers: "gru-1-db-1=10.251.0.21:7443,gru-1-db-2=[2001:db8::1]:7443"}); err != nil {
		t.Fatalf("valid IPv4/IPv6 profile: %v", err)
	}
}

func TestLayoutEnvAddsHostOwnedPaths(t *testing.T) {
	profile := Profile{PeerPort: 9443, ClientPort: 9465}
	env := Layout("/srv/ts-managed/terrabase").Env(map[string]string{EnvPeerPort: "9443"}, profile, "ts-gru-1")
	for key, want := range map[string]string{
		EnvPeerPort:          "9443",
		EnvDataDirectory:     "/srv/ts-managed/terrabase/data",
		EnvBundleExtract:     "/srv/ts-managed/terrabase/bundle",
		EnvPeerCertificate:   "/srv/ts-managed/terrabase/tls/member.pem",
		EnvPeerPrivateKey:    "/srv/ts-managed/terrabase/tls/member.key",
		EnvPeerClientCA:      "/srv/ts-managed/terrabase/tls/ca.pem",
		EnvClientCertificate: "/srv/ts-managed/terrabase/tls/member.pem",
		EnvClientPrivateKey:  "/srv/ts-managed/terrabase/tls/member.key",
		EnvNodeName:          "ts-gru-1",
	} {
		if env[key] != want {
			t.Errorf("%s = %q, want %q", key, env[key], want)
		}
	}
	if env := Layout("/r").Env(map[string]string{}, Profile{}, "ts-gru-1"); env[EnvClientCertificate] != "" {
		t.Fatal("client certificate set without a client port")
	}
}

// elfHeader is the 64-byte ELF64 little-endian header of an executable built
// for machine, with no program or section headers.
func elfHeader(machine elf.Machine) []byte {
	header := elf.Header64{Type: uint16(elf.ET_EXEC), Machine: uint16(machine), Version: uint32(elf.EV_CURRENT), Ehsize: 64}
	copy(header.Ident[:], elf.ELFMAG)
	header.Ident[elf.EI_CLASS], header.Ident[elf.EI_DATA], header.Ident[elf.EI_VERSION] = byte(elf.ELFCLASS64), byte(elf.ELFDATA2LSB), byte(elf.EV_CURRENT)
	var b bytes.Buffer
	binary.Write(&b, binary.LittleEndian, header)
	return b.Bytes()
}

// testdata/terrabase-linux-arm64 is a bare aarch64 ELF header with its
// sha256sum line. It stands in for the asset TerraBase CI publishes once
// TS-483 lands, so the arm64 rollout path is exercised before then.
func TestVerifyReleaseAcceptsTheARM64Fixture(t *testing.T) {
	binary := filepath.Join("testdata", "terrabase-linux-arm64")
	data, err := os.ReadFile(binary)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if got, err := VerifyRelease(binary, binary+".sha256"); err != nil || got != hex.EncodeToString(sum[:]) {
		t.Fatalf("VerifyRelease = %q, %v", got, err)
	}
}

func TestVerifyReleaseRequiresTheAssetMachine(t *testing.T) {
	dir := t.TempDir()
	binary, checksum := filepath.Join(dir, "terrabase-linux-arm64"), filepath.Join(dir, "terrabase-linux-arm64.sha256")
	for name, data := range map[string][]byte{
		"x86-64 as arm64":  append(elfHeader(elf.EM_X86_64), "terrabase"...),
		"truncated header": elfHeader(elf.EM_AARCH64)[:40],
		"32-bit":           append([]byte("\x7fELF\x01\x01\x01"), make([]byte, 57)...),
	} {
		sum := sha256.Sum256(data)
		if err := os.WriteFile(binary, data, 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(checksum, []byte(hex.EncodeToString(sum[:])+"  terrabase-linux-arm64\n"), 0o644); err != nil {
			t.Fatal(err)
		}
		_, err := VerifyRelease(binary, checksum)
		if err == nil {
			t.Errorf("%s: accepted", name)
		} else if name == "x86-64 as arm64" && !strings.Contains(err.Error(), "EM_AARCH64, found EM_X86_64") {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestVerifyRelease(t *testing.T) {
	dir := t.TempDir()
	binary := filepath.Join(dir, "terrabase-linux-arm64")
	data := append(elfHeader(elf.EM_AARCH64), "terrabase"...)
	if err := os.WriteFile(binary, data, 0o755); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	checksum := filepath.Join(dir, "terrabase-linux-arm64.sha256")
	write := func(content string) {
		t.Helper()
		if err := os.WriteFile(checksum, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write(digest + "  terrabase-linux-arm64\n")
	if got, err := VerifyRelease(binary, checksum); err != nil || got != digest {
		t.Fatalf("VerifyRelease = %q, %v", got, err)
	}
	for name, content := range map[string]string{
		"other digest":    strings.Repeat("0", 64) + "  terrabase-linux-arm64\n",
		"other asset":     digest + "  terrabase-linux-amd64\n",
		"two lines":       digest + "  terrabase-linux-arm64\n" + digest + "  terrabase-linux-arm64\n",
		"uppercase":       strings.ToUpper(digest) + "  terrabase-linux-arm64\n",
		"missing name":    digest + "\n",
		"not hexadecimal": strings.Repeat("g", 64) + "  terrabase-linux-arm64\n",
	} {
		write(content)
		if _, err := VerifyRelease(binary, checksum); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	write(digest + "  terrabase-linux-arm64\n")
	renamed := filepath.Join(dir, "tb-server-linux-arm64")
	if err := os.Rename(binary, renamed); err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyRelease(renamed, checksum); err == nil {
		t.Fatal("accepted a non-TerraBase asset name")
	}
	script := filepath.Join(dir, "terrabase-linux-arm64")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	sum = sha256.Sum256([]byte("#!/bin/sh\n"))
	write(hex.EncodeToString(sum[:]) + "  terrabase-linux-arm64\n")
	if _, err := VerifyRelease(script, checksum); err == nil {
		t.Fatal("accepted a non-ELF executable")
	}
}

func TestMemberCertificateIssue(t *testing.T) {
	now := time.Now()
	caPEM, caKey, err := NewCA("gru-1", now)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "ca.pem"), caPEM, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "ca.key"), caKey, 0o600); err != nil {
		t.Fatal(err)
	}
	ca, err := LoadCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key"))
	if err != nil {
		t.Fatal(err)
	}
	peers, err := ParsePeers("gru-1-db-1=10.251.0.21:9443,gru-1-db-2=10.251.0.22:9443")
	if err != nil {
		t.Fatal(err)
	}
	key, csr, err := NewMemberKey()
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := ca.Issue(csr, peers[0], now)
	if err != nil {
		t.Fatal(err)
	}
	if !CurrentCertificate(certificate, key, ca.CertificatePEM(), peers[0], now) {
		t.Fatal("fresh certificate is not current")
	}
	block, _ := pem.Decode(certificate)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	if leaf.Subject.CommonName != "gru-1-db-1" || len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "gru-1-db-1" ||
		len(leaf.IPAddresses) != 1 || !leaf.IPAddresses[0].Equal(net.ParseIP("10.251.0.21")) || len(leaf.ExtKeyUsage) != 2 {
		t.Fatalf("member certificate names %v %v %v %v", leaf.Subject, leaf.DNSNames, leaf.IPAddresses, leaf.ExtKeyUsage)
	}
	if CurrentCertificate(certificate, key, ca.CertificatePEM(), peers[1], now) {
		t.Fatal("certificate is current for another member")
	}
	if CurrentCertificate(certificate, key, ca.CertificatePEM(), peers[0], now.Add(61*24*time.Hour)) {
		t.Fatal("certificate inside its renewal window is current")
	}
	otherKey, _, err := NewMemberKey()
	if err != nil {
		t.Fatal(err)
	}
	if CurrentCertificate(certificate, otherKey, ca.CertificatePEM(), peers[0], now) {
		t.Fatal("certificate is current for another key")
	}
	foreign, _, err := NewCA("gru-2", now)
	if err != nil {
		t.Fatal(err)
	}
	if CurrentCertificate(certificate, key, foreign, peers[0], now) {
		t.Fatal("certificate is current under another CA")
	}
	again, err := CertificateRequest(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ca.Issue(again, peers[1], now); err != nil {
		t.Fatalf("reissue from the stored key: %v", err)
	}
	if _, err := ca.Issue([]byte("not a request"), peers[0], now); err == nil {
		t.Fatal("issued from an invalid request")
	}
	if _, err := LoadCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "missing.key")); err == nil {
		t.Fatal("loaded a CA without its key")
	}
	if err := os.Chmod(filepath.Join(dir, "ca.key"), 0o640); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "ca.key")); err == nil {
		t.Fatal("loaded a group-readable CA key")
	}
	if err := os.Symlink(filepath.Join(dir, "ca.key"), filepath.Join(dir, "link.key")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(dir, "ca.key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadCA(filepath.Join(dir, "ca.pem"), filepath.Join(dir, "link.key")); err == nil {
		t.Fatal("loaded a CA key through a symlink")
	}
}

func TestHealthy(t *testing.T) {
	status := http.StatusOK
	body := `{"status":"ok","version":"0.1.0"}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		w.WriteHeader(status)
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()
	port := server.Listener.Addr().(*net.TCPAddr).Port
	if err := Healthy(t.Context(), port); err != nil {
		t.Fatal(err)
	}
	status, body = http.StatusServiceUnavailable, `{"status":"ok"}`
	if err := Healthy(t.Context(), port); err == nil {
		t.Fatal("healthy on HTTP 503")
	}
	status, body = http.StatusOK, `{"status":"starting"}`
	if err := Healthy(t.Context(), port); err == nil {
		t.Fatal("healthy without status ok")
	}
	server.Close()
	if err := Healthy(t.Context(), port); err == nil {
		t.Fatal("healthy without a listener")
	}
}

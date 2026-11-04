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
	"testing"
	"time"
)

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
	write("invalid checksum\n")
	if _, err := VerifyRelease(binary, checksum); err == nil {
		t.Fatal("accepted a checksum mismatch")
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

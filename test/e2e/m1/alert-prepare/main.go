package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"golang.org/x/sys/unix"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/alertdelivery"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func require(ok bool, text string) {
	if !ok {
		panic(text)
	}
}

func main() {
	if os.Getpid() == 1 {
		defer func() {
			if failure := recover(); failure != nil {
				fmt.Println("alert-prepare e2e: FAIL:", failure)
			}
			unix.Reboot(unix.LINUX_REBOOT_CMD_POWER_OFF)
		}()
		must(unix.Mount("tmpfs", "/run", "tmpfs", 0, "mode=0755"))
		must(unix.Mount("ramfs", "/tmp", "ramfs", 0, "mode=1777"))
		socket, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
		must(err)
		request, err := unix.NewIfreq("lo")
		must(err)
		request.SetUint16(unix.IFF_UP | unix.IFF_LOOPBACK)
		must(unix.IoctlIfreq(socket, unix.SIOCSIFFLAGS, request))
		must(unix.Close(socket))
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	must(err)
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{OrganizationalUnit: []string{"opc-tenant:ocid1.tenancy.oc1..lane"}}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	must(err)
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	private := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	values := map[string]string{"gru-1-cloudflare-account-id": rand.Text(), "gru-1-cloudflare-email-token": rand.Text(), "gru-1-ts-alerts-ntfy-topic": rand.Text()}
	seen := map[string]bool{}
	denied := ""
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/opc/v2/instance/region":
			fmt.Fprint(w, "sa-saopaulo-1")
		case "/opc/v2/identity/cert.pem", "/opc/v2/identity/intermediate.pem":
			w.Write(certificate)
		case "/opc/v2/identity/key.pem":
			w.Write(private)
		case "/v1/x509":
			token := "e30." + base64.RawURLEncoding.EncodeToString([]byte(fmt.Sprintf(`{"exp":%d}`, time.Now().Add(time.Hour).Unix()))) + ".lane"
			must(json.NewEncoder(w).Encode(map[string]string{"token": token}))
		case "/20190301/secretbundles/actions/getByName":
			name := r.URL.Query().Get("secretName")
			value, ok := values[name]
			if !ok || name == denied {
				http.Error(w, "unavailable", http.StatusNotFound)
				return
			}
			seen[name] = true
			must(json.NewEncoder(w).Encode(map[string]any{"secretBundleContent": map[string]string{"contentType": "BASE64", "content": base64.StdEncoding.EncodeToString([]byte(value))}}))
		default:
			http.Error(w, "unknown endpoint", http.StatusNotFound)
		}
	})
	plain := httptest.NewServer(handler)
	defer plain.Close()
	secure := httptest.NewTLSServer(handler)
	defer secure.Close()
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	transport.TLSClientConfig = &tls.Config{RootCAs: x509.NewCertPool(), ServerName: "example.com"}
	transport.TLSClientConfig.RootCAs.AddCert(secure.Certificate())
	transport.DialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		socket, err := (&net.Dialer{}).DialContext(ctx, network, secure.Listener.Addr().String())
		if err != nil {
			return nil, err
		}
		connection := tls.Client(socket, transport.TLSClientConfig)
		if err := connection.HandshakeContext(ctx); err != nil {
			socket.Close()
			return nil, err
		}
		return connection, nil
	}
	transport.DialContext = func(ctx context.Context, network, address string) (net.Conn, error) {
		endpoint := plain.Listener.Addr().String()
		if strings.HasSuffix(address, ":443") {
			endpoint = secure.Listener.Addr().String()
		}
		return (&net.Dialer{}).DialContext(ctx, network, endpoint)
	}
	http.DefaultTransport = transport
	defer transport.CloseIdleConnections()
	disk, err := os.MkdirTemp("", "not-tmpfs-")
	must(err)
	defer os.RemoveAll(disk)
	var fs unix.Statfs_t
	must(unix.Statfs(disk, &fs))
	require(fs.Type != unix.TMPFS_MAGIC, "negative case must use a non-tmpfs filesystem")
	require(vaultsecret.RequireMemoryFilesystem(disk) != nil, "non-tmpfs directory must be refused")
	must(alertdelivery.Run(ctx, []string{"prepare"}))
	require(len(seen) == 3, "preparation must read all three approved secrets")
	account, err := user.Lookup("ts-alerts")
	must(err)
	gid, err := strconv.Atoi(account.Gid)
	must(err)
	directory := "/run/ts-alert-delivery"
	info, err := os.Stat(directory)
	must(err)
	require(info.Mode().Perm() == 0o750 && info.Sys().(*syscall.Stat_t).Uid == 0 && info.Sys().(*syscall.Stat_t).Gid == uint32(gid), "prepared directory ownership and mode")
	for name, value := range values {
		fileName := map[string]string{"gru-1-cloudflare-account-id": "cloudflare_account_id_file", "gru-1-cloudflare-email-token": "cloudflare_email_token_file", "gru-1-ts-alerts-ntfy-topic": "ts_alerts_ntfy_topic_file"}[name]
		path := filepath.Join(directory, fileName)
		data, err := os.ReadFile(path)
		must(err)
		info, err := os.Stat(path)
		must(err)
		require(string(data) == value && info.Mode().Perm() == 0o640 && info.Sys().(*syscall.Stat_t).Uid == 0 && info.Sys().(*syscall.Stat_t).Gid == uint32(gid), "prepared credential ownership, mode and bytes")
		clear(data)
	}
	for name := range values {
		denied = name
		err := alertdelivery.Run(ctx, []string{"prepare"})
		require(err != nil && strings.Contains(err.Error(), "could not read"), "unreadable secret must visibly refuse preparation")
		for _, value := range values {
			require(!strings.Contains(err.Error(), value), "error must not expose a value")
		}
	}
	secretGate(values, &seen, &denied)
	fmt.Println("alert-prepare e2e: PASS; three protected files; each unavailable secret visibly refused")
}

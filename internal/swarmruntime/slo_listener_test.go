package swarmruntime

import (
	"bufio"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const sloTestMetrics = "# HELP http_server_request_duration_seconds Native request duration.\n# TYPE http_server_request_duration_seconds histogram\nhttp_server_request_duration_seconds_bucket{le=\"+Inf\"} 1\nhttp_server_request_duration_seconds_sum 0.01\nhttp_server_request_duration_seconds_count 1\n"

func TestSLOListenerProcess(t *testing.T) {
	if os.Getenv("TS_SLO_LISTENER_TEST") != "1" {
		return
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metrics" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		io.WriteString(w, sloTestMetrics)
	})
	app := httptest.NewServer(handler)
	defer app.Close()
	metrics := httptest.NewServer(handler)
	defer metrics.Close()
	fmt.Println(strings.TrimPrefix(app.URL, "http://"), strings.TrimPrefix(metrics.URL, "http://"))
	io.Copy(io.Discard, os.Stdin)
}

func startSLOListenerProcess(t *testing.T) (uint32, string, string, func()) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	command := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSLOListenerProcess$")
	command.Env = append(os.Environ(), "TS_SLO_LISTENER_TEST=1")
	stdout, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdin, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		cancel()
		t.Fatal(err)
	}
	var once sync.Once
	stop := func() { once.Do(func() { stdin.Close(); command.Wait(); cancel() }) }
	t.Cleanup(stop)
	line, err := bufio.NewReader(stdout).ReadString('\n')
	fields := strings.Fields(line)
	if err != nil || len(fields) != 2 {
		t.Fatalf("listener subprocess failed: %v", err)
	}
	_, port, err := net.SplitHostPort(fields[0])
	if err != nil {
		t.Fatal(err)
	}
	return uint32(command.Process.Pid), port, fields[1], stop
}

func TestDiscoverSLOListenerOwnsSocketsAndExcludesApplication(t *testing.T) {
	// This valid exporter shares the network namespace but belongs to another PID.
	unrelated := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		io.WriteString(w, sloTestMetrics)
	}))
	defer unrelated.Close()
	pid, applicationPort, metricsAddress, stop := startSLOListenerProcess(t)
	port, _ := strconv.ParseUint(applicationPort, 10, 16)
	if got := discoverSLOListener(context.Background(), pid, uint16(port)); got != metricsAddress {
		t.Fatalf("listener = %q, want owned dedicated exporter %q", got, metricsAddress)
	}
	stop()
	if got := discoverSLOListener(context.Background(), pid, uint16(port)); got != "" {
		t.Fatalf("stopped process remains discoverable: %q", got)
	}
	if got := discoverSLOListener(context.Background(), 0, uint16(port)); got != "" {
		t.Fatalf("missing PID remains discoverable: %q", got)
	}
}

func TestSLOListeningAddressesFixtures(t *testing.T) {
	if binary.NativeEndian.Uint32([]byte{1, 0, 0, 0}) != 1 {
		t.Skip("fixtures use little-endian Linux proc words")
	}
	root := t.TempDir()
	for _, dir := range []string{"fd", "net"} {
		if err := os.Mkdir(filepath.Join(root, dir), 0700); err != nil {
			t.Fatal(err)
		}
	}
	for _, inode := range []string{"101", "102", "103", "104", "105", "106", "107", "108"} {
		if err := os.Symlink("socket:["+inode+"]", filepath.Join(root, "fd", inode)); err != nil {
			t.Fatal(err)
		}
	}
	row := func(address, state, inode string) string {
		return " 0: " + address + " 00000000:0000 " + state + " 00000000:00000000 00:00000000 00000000 0 0 " + inode + "\n"
	}
	tcp := "sl local_address rem_address st tx_queue rx_queue tr tm->when retrnsmt uid timeout inode\n" +
		row("0100007F:9E1F", "0A", "101") + // 127.0.0.1:40479
		row("00000000:1F95", "0A", "102") + // wildcard:8085
		row("0100007F:A3EF", "0A", "103") + // reserved app:41967
		row("0100007F:1F90", "01", "104") + // established, not LISTEN
		row("0100007F:1F91", "0A", "999") + // unrelated process
		row("0100000A:1F92", "0A", "105") + // non-loopback 10.0.0.1
		row("invalid:1F93", "0A", "106") + "malformed\n"
	tcp6 := row("00000000000000000000000001000000:1F96", "0A", "107") +
		row("00000000000000000000000000000000:1F97", "0A", "108")
	for name, content := range map[string]string{"tcp": tcp, "tcp6": tcp6} {
		if err := os.WriteFile(filepath.Join(root, "net", name), []byte(content), 0600); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"127.0.0.1:40479", "127.0.0.1:8085", "[::1]:8086", "[::1]:8087"}
	if got := sloListeningAddresses(root, 41967); !reflect.DeepEqual(got, want) {
		t.Fatalf("listeners = %v, want %v", got, want)
	}
	if got := sloListeningAddresses(filepath.Join(root, "missing"), 41967); len(got) != 0 {
		t.Fatalf("missing process has listeners: %v", got)
	}
	if err := os.RemoveAll(filepath.Join(root, "net")); err != nil {
		t.Fatal(err)
	}
	if got := sloListeningAddresses(root, 41967); len(got) != 0 {
		t.Fatalf("unavailable listener tables have targets: %v", got)
	}
}

func TestSLOExporterProbe(t *testing.T) {
	for _, tc := range []struct {
		name, contentType, body string
		status                  int
		want                    bool
	}{
		{"native", "text/plain; version=0.0.4", sloTestMetrics, 200, true},
		{"html", "text/html", "<html>login</html>", 200, false},
		{"invalid", "text/plain", "not prometheus", 200, false},
		{"empty", "text/plain", "# empty\n", 200, false},
		{"metadata-only", "text/plain", "# TYPE requests_total counter\n", 200, false},
		{"error", "text/plain", sloTestMetrics, 500, false},
		{"redirect", "text/plain", sloTestMetrics, 302, false},
		{"large", "text/plain", strings.Repeat("# padding\n", 120000) + sloTestMetrics, 200, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/metrics" {
					t.Errorf("unexpected probe path %q", r.URL.Path)
				}
				w.Header().Set("Content-Type", tc.contentType)
				w.Header().Set("Location", "http://192.0.2.1/secret")
				w.WriteHeader(tc.status)
				io.WriteString(w, tc.body)
			}))
			defer server.Close()
			client := &http.Client{Timeout: time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
			if got := sloExporter(context.Background(), client, strings.TrimPrefix(server.URL, "http://")); got != tc.want {
				t.Fatalf("exporter = %v, want %v", got, tc.want)
			}
		})
	}
	for _, address := range []string{"example.com:80", "192.0.2.1:80", "[2001:db8::1]:80", "invalid"} {
		if sloExporter(context.Background(), http.DefaultClient, address) {
			t.Fatalf("accepted non-loopback address %q", address)
		}
	}
}

func TestDiscoverSLOListenerBoundsSlowProbe(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-r.Context().Done()
	}))
	defer server.Close()
	// Every listener owned by this test PID is slow, absent, or not an exporter.
	t.Setenv("HTTP_PROXY", "http://192.0.2.1:1")
	t.Setenv("HTTPS_PROXY", "http://192.0.2.1:1")
	start := time.Now()
	if got := discoverSLOListener(context.Background(), uint32(os.Getpid()), 0); got != "" {
		t.Fatalf("unexpected exporter: %q", got)
	}
	if time.Since(start) > 2*time.Second {
		t.Fatal("discovery exceeded its one-second budget")
	}
}

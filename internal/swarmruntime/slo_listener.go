package swarmruntime

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"io"
	"mime"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/prometheus/common/expfmt"
	"github.com/prometheus/common/model"
)

func discoverSLOListener(ctx context.Context, pid uint32, applicationPort uint16) string {
	if pid == 0 {
		return ""
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	// A fresh transport has no environment proxy, cookies, or inherited credentials.
	transport := &http.Transport{DisableKeepAlives: true}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 250 * time.Millisecond,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	for _, address := range sloListeningAddresses(filepath.Join("/proc", strconv.FormatUint(uint64(pid), 10)), applicationPort) {
		if ctx.Err() != nil {
			break
		}
		if sloExporter(ctx, client, address) {
			return address
		}
	}
	return ""
}

// /proc/PID/net is shared by the host network namespace. Only socket inodes
// present in this task's fd directory belong to the application being scraped.
// Exit races and unavailable proc entries simply leave the task undiscovered.
func sloListeningAddresses(procDir string, applicationPort uint16) []string {
	fds, err := os.ReadDir(filepath.Join(procDir, "fd"))
	if err != nil {
		return nil
	}
	owned := map[string]bool{}
	for _, fd := range fds {
		link, err := os.Readlink(filepath.Join(procDir, "fd", fd.Name()))
		if err == nil && strings.HasPrefix(link, "socket:[") && strings.HasSuffix(link, "]") {
			owned[strings.TrimSuffix(strings.TrimPrefix(link, "socket:["), "]")] = true
		}
	}
	var addresses []string
	for _, table := range []string{"tcp", "tcp6"} {
		file, err := os.Open(filepath.Join(procDir, "net", table))
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(io.LimitReader(file, 4<<20))
		for scanner.Scan() {
			fields := strings.Fields(scanner.Text())
			if len(fields) < 10 || fields[3] != "0A" || !owned[fields[9]] {
				continue
			}
			if address := sloSocketAddress(fields[1], applicationPort); address != "" {
				addresses = append(addresses, address)
			}
		}
		file.Close()
	}
	slices.Sort(addresses)
	return slices.Compact(addresses)
}

func sloSocketAddress(local string, applicationPort uint16) string {
	encodedIP, encodedPort, ok := strings.Cut(local, ":")
	port, err := strconv.ParseUint(encodedPort, 16, 16)
	ip, ipErr := hex.DecodeString(encodedIP)
	if !ok || err != nil || ipErr != nil || port == 0 || uint16(port) == applicationPort || (len(ip) != 4 && len(ip) != 16) {
		return ""
	}
	// proc renders each native-endian 32-bit word as hexadecimal, including IPv6.
	for i := 0; i < len(ip); i += 4 {
		binary.NativeEndian.PutUint32(ip[i:i+4], binary.BigEndian.Uint32(ip[i:i+4]))
	}
	address := net.IP(ip)
	if address.IsUnspecified() {
		if len(ip) == 4 {
			address = net.IPv4(127, 0, 0, 1)
		} else {
			address = net.IPv6loopback
		}
	}
	if !address.IsLoopback() {
		return ""
	}
	return net.JoinHostPort(address.String(), strconv.Itoa(int(port)))
}

func sloExporter(ctx context.Context, client *http.Client, address string) bool {
	// Reject hostnames and non-loopback destinations even if a future caller
	// bypasses proc parsing. No redirect can escape this destination.
	host, _, err := net.SplitHostPort(address)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return false
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+address+"/metrics", nil)
	if err != nil {
		return false
	}
	request.Header.Set("Accept", "text/plain; version=0.0.4")
	response, err := client.Do(request)
	if err != nil {
		return false
	}
	defer response.Body.Close()
	contentType, _, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if response.StatusCode != http.StatusOK || err != nil || contentType != "text/plain" {
		return false
	}
	const maxBody = 1 << 20
	body, err := io.ReadAll(io.LimitReader(response.Body, maxBody+1))
	if err != nil || len(body) > maxBody {
		return false
	}
	parser := expfmt.NewTextParser(model.LegacyValidation)
	families, err := parser.TextToMetricFamilies(bytes.NewReader(body))
	if err == nil {
		for _, family := range families {
			if len(family.Metric) > 0 {
				return true
			}
		}
	}
	return false
}

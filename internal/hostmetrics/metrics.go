// Package hostmetrics exports bounded host storage evidence over NetBird.
package hostmetrics

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

// Port is reserved for bounded host evidence on the NetBird interface.
const Port = 9108

// Run serves automatically with the host runtime, retrying during NetBird startup.
func Run(ctx context.Context) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	for ctx.Err() == nil {
		if err := serve(ctx); err != nil {
			slog.WarnContext(ctx, "Host storage metrics unavailable", "error", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func serve(ctx context.Context) error {
	iface, err := net.InterfaceByName("wt0")
	if err != nil {
		return err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return err
	}
	address := ""
	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err == nil && ip.To4() != nil && ip.IsPrivate() {
			address = net.JoinHostPort(ip.String(), strconv.Itoa(Port))
			break
		}
	}
	if address == "" {
		return errors.New("NetBird has no private IPv4 address")
	}
	server := &http.Server{Addr: address, ReadHeaderTimeout: 2 * time.Second, WriteTimeout: 5 * time.Second, IdleTimeout: 15 * time.Second,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/metrics" {
				http.NotFound(w, r)
				return
			}
			var body bytes.Buffer
			view, err := observability.ReadSystem([]observability.FilesystemRole{{Role: "root", Path: "/"}, {Role: "data", Path: "/var/lib/ts-data"}})
			if err == nil {
				err = writeHost(&body, view)
			}
			if err == nil {
				var data []byte
				data, err = os.ReadFile("/proc/diskstats")
				if err == nil {
					err = writeDisks(&body, string(data), "/sys/block")
				}
			}
			if err != nil {
				http.Error(w, "host storage telemetry unavailable", http.StatusServiceUnavailable)
				return
			}
			observability.WriteEdgeListenerMetrics(&body)
			w.Header().Set("Content-Type", "text/plain; version=0.0.4")
			_, _ = w.Write(body.Bytes())
		})}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	err = server.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func writeHost(w io.Writer, view observability.SystemView) error {
	psi, ok := view.Pressure["io"]
	if !ok || !psi.HasFullRow {
		return errors.New("IO PSI unavailable")
	}
	for _, fs := range view.Filesystems {
		if fs.SizeBytes == 0 {
			return errors.New("filesystem unavailable")
		}
		fmt.Fprintf(w, "ts_host_disk_available_bytes{mount=%q} %d\nts_host_disk_size_bytes{mount=%q} %d\n", fs.Role, fs.AvailBytes, fs.Role, fs.SizeBytes)
	}
	fmt.Fprintf(w, "ts_host_io_psi_ratio{scope=%q} %g\nts_host_io_psi_ratio{scope=%q} %g\n", "some", psi.SomeAvg10/100, "full", psi.FullAvg10/100)
	return nil
}

func writeDisks(w io.Writer, data, sysBlock string) error {
	count := 0
	for _, line := range strings.Split(data, "\n") {
		f := strings.Fields(line)
		if len(f) < 14 {
			continue
		}
		device := f[2]
		if strings.ContainsAny(device, "/\\\"") || strings.HasPrefix(device, "loop") || strings.HasPrefix(device, "ram") {
			continue
		}
		if _, err := os.Stat(filepath.Join(sysBlock, device)); err != nil {
			continue
		} // excludes partitions
		if count++; count > 32 {
			return errors.New("too many block devices")
		}
		v := make([]uint64, 11)
		for i := range v {
			n, err := strconv.ParseUint(f[i+3], 10, 64)
			if err != nil {
				return errors.New("invalid diskstats")
			}
			v[i] = n
		}
		for i, operation := range []string{"read", "write"} {
			offset := i * 4
			fmt.Fprintf(w, "ts_host_disk_operations_total{device=%q,operation=%q} %d\n", device, operation, v[offset])
			fmt.Fprintf(w, "ts_host_disk_bytes_total{device=%q,operation=%q} %g\n", device, operation, float64(v[offset+2])*512)
			fmt.Fprintf(w, "ts_host_disk_operation_seconds_total{device=%q,operation=%q} %g\n", device, operation, float64(v[offset+3])/1000)
		}
		fmt.Fprintf(w, "ts_host_disk_inflight{device=%q} %d\nts_host_disk_busy_seconds_total{device=%q} %g\nts_host_disk_weighted_seconds_total{device=%q} %g\n", device, v[8], device, float64(v[9])/1000, device, float64(v[10])/1000)
	}
	if count == 0 {
		return errors.New("no block device telemetry")
	}
	return nil
}

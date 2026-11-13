package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/memberstatus"
)

func memberServer(ctx context.Context, socket string) error {
	listener, err := net.Listen("unix", socket)
	if err != nil {
		return err
	}
	if err := os.Chmod(socket, 0602); err != nil {
		listener.Close()
		return err
	}
	server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		timer := time.NewTimer(4 * time.Second)
		defer timer.Stop()
		select {
		case <-r.Context().Done():
			return
		case <-timer.C:
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Length", "2")
		_, _ = w.Write([]byte("{}"))
	})}
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	err = server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func qualifiedIdentity(ctx context.Context) error {
	root, err := os.MkdirTemp("", "member-readiness-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(root)
	if err := os.Chown(root, 0, 65532); err != nil {
		return err
	}
	if err := os.Chmod(root, 0730); err != nil {
		return err
	}
	socket := filepath.Join(root, "member.sock")
	child := exec.CommandContext(ctx, os.Args[0], "member-server", socket)
	child.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65532, Gid: 65532}}
	if err := child.Start(); err != nil {
		return err
	}
	defer func() { _ = child.Process.Kill(); _ = child.Wait() }()
	if err := until(ctx, func() error { _, err := os.Stat(socket); return err }); err != nil {
		return err
	}
	pid := child.Process.Pid
	var delay atomic.Int64
	delay.Store(int64(12 * time.Second))
	observe := func(ctx context.Context) (memberstatus.ProcessObservation, error) {
		timer := time.NewTimer(time.Duration(delay.Load()))
		defer timer.Stop()
		select {
		case <-ctx.Done():
			return memberstatus.ProcessObservation{}, ctx.Err()
		case <-timer.C:
		}
		stat, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
		if err != nil {
			return memberstatus.ProcessObservation{}, err
		}
		fields := strings.Fields(string(stat)[strings.LastIndexByte(string(stat), ')')+1:])
		cgroup, err := os.ReadFile(fmt.Sprintf("/proc/%d/cgroup", pid))
		if err != nil {
			return memberstatus.ProcessObservation{}, err
		}
		return memberstatus.ProcessObservation{PID: pid, UID: 65532, GID: 65532, KernelStart: fields[19], Cgroup: string(cgroup)}, nil
	}
	id := "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	client, err := memberstatus.NewClient(socket,
		memberstatus.Scope{ClusterID: strings.Repeat("a", 32), TenantID: id, DatabaseID: id, ShardID: 1, MemberID: id, Incarnation: strings.Repeat("b", 32)},
		memberstatus.Authority{Epoch: 1, ConfigurationID: strings.Repeat("a", 64), CertificateSHA256: strings.Repeat("b", 64), TLSLeafSHA256: strings.Repeat("c", 64)}, observe)
	if err != nil {
		return err
	}
	for round := range 2 {
		started := time.Now()
		err := client.Readiness(ctx)
		if !errors.Is(err, memberstatus.ErrReadinessUnobserved) || errors.Is(err, memberstatus.ErrUnresponsive) || time.Since(started) > 7*time.Second {
			return fmt.Errorf("qualified member slow identity round %d: expected unobserved within five-second bound, got %v after %s", round, err, time.Since(started))
		}
	}
	delay.Store(int64(4 * time.Second))
	if err := client.Readiness(ctx); err != nil {
		return fmt.Errorf("qualified member four-second identity and healthy four-second answer: %w", err)
	}
	fmt.Println("qualified member: two 12s identity lookups bounded at 5s are unobserved, never unresponsive; 4s identity + fresh 4s HTTP answer + 4s verification succeeds; PID " + strconv.Itoa(pid))
	return nil
}

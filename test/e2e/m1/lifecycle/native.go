package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/host"
)

func nativeWorker(ctx context.Context, socket, marker string) error {
	ctx, cancel := signal.NotifyContext(ctx, syscall.SIGTERM)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return err
	}
	if err := conn.Close(); err != nil {
		return err
	}
	<-ctx.Done()
	return os.WriteFile(marker, []byte("drained\n"), 0600)
}

func nativeDrain(ctx context.Context) error {
	directory, err := os.MkdirTemp("/tmp", "ts-native-drain-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(directory)
	if err := os.Chmod(directory, 0755); err != nil {
		return err
	}
	input, err := os.Open("/proc/self/exe")
	if err != nil {
		return err
	}
	defer input.Close()
	executable := filepath.Join(directory, "worker")
	output, err := os.OpenFile(executable, os.O_CREATE|os.O_WRONLY, 0755)
	if err != nil {
		return err
	}
	hash := sha256.New()
	_, copyErr := io.Copy(io.MultiWriter(output, hash), input)
	if err := errors.Join(copyErr, output.Close()); err != nil {
		return err
	}
	if err := os.Chown(executable, 0, 65532); err != nil {
		return err
	}
	data := filepath.Join(directory, "data")
	if err := os.Mkdir(data, 0700); err != nil {
		return err
	}
	if err := os.Chown(data, 65532, 65532); err != nil {
		return err
	}
	socket := filepath.Join(directory, "ready.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: socket, Net: "unix"})
	if err != nil {
		return err
	}
	defer listener.Close()
	if err := os.Chmod(socket, 0666); err != nil {
		return err
	}
	deadline, _ := ctx.Deadline()
	if err := listener.SetDeadline(deadline); err != nil {
		return err
	}
	runner := host.NewProcessRunner(filepath.Join(directory, "state"), host.WorkloadIdentity{UID: 65532, GID: 65532}, "local", "e2e")
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = runner.Close(cleanup)
	}()
	if err := runner.Recover(ctx); err != nil {
		return err
	}
	marker := filepath.Join(data, "drained")
	digest := fmt.Sprintf("%x", hash.Sum(nil))
	if err := runner.Apply(ctx, host.Workload{Role: "drain", Digest: digest, Fingerprint: digest,
		Executable: executable, Args: []string{"native-worker", socket, marker}, DrainTimeout: 5 * time.Second}); err != nil {
		return err
	}
	ready, err := listener.Accept()
	if err != nil {
		return err
	}
	if err := ready.Close(); err != nil {
		return err
	}
	if err := runner.Shutdown(ctx); err != nil {
		return err
	}
	content, err := os.ReadFile(marker)
	if err != nil || string(content) != "drained\n" {
		return errors.Join(errors.New("native workload did not finish its SIGTERM handler before shutdown"), err)
	}
	observation, err := runner.Observe(ctx, "drain")
	if err != nil {
		return err
	}
	if observation.Running {
		return errors.New("native workload survived shutdown")
	}
	fmt.Println("native SIGTERM handler completed before runner shutdown; process stopped")
	return nil
}

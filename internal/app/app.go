// Package app is the sole composition root for the one executable.
package app

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"syscall"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
)

func Run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 {
		return errors.New("usage: terrascale-orchestrator <run|host|check|operator|identity-new> --config FILE")
	}
	command := args[0]
	if command == "identity-new" {
		return newIdentity(args[1:], output)
	}
	if command == "operator" {
		return runOperator(ctx, args[1:], output)
	}
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "JSON role configuration")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("%s does not accept positional arguments", command)
	}
	cfg, err := LoadConfig(*configPath)
	if err != nil {
		return err
	}
	switch command {
	case "run":
		return runController(ctx, cfg, output)
	case "host":
		return runHost(ctx, cfg, output)
	case "check":
		return check(ctx, cfg, output)
	default:
		return fmt.Errorf("unknown command %q", command)
	}
}

func runHost(ctx context.Context, cfg Config, output io.Writer) error {
	if cfg.NATS.Embedded != nil {
		return errors.New("host role cannot start the regional NATS server")
	}
	cfg.NATS.ClientRole = "host"
	key, err := readPrivateKey(cfg.Host.IdentityKeyFile)
	if err != nil {
		return err
	}
	controllerKey, err := decodePublicKey(cfg.Host.ControllerPublicKey)
	if err != nil {
		return fmt.Errorf("controller response public key: %w", err)
	}
	runtime, err := natscell.Start(ctx, cfg.NATS)
	if err != nil {
		return err
	}
	defer runtime.Close()
	agent, err := host.NewAgent(host.AgentConfig{
		Cell: cfg.NATS.Cell, Node: cfg.Host.Node, Environment: cfg.Host.Environment,
		Roles: cfg.Host.Roles, Conn: runtime.Conn(), Identity: key, ControllerPublicKey: controllerKey,
		InstallRoot: cfg.Host.InstallRoot, StateRoot: cfg.Host.StateRoot,
		PollInterval: time.Duration(cfg.Host.PollMillis) * time.Millisecond,
	})
	if err != nil {
		return err
	}
	fmt.Fprintf(output, "host %s ready in cell %s\n", cfg.Host.Node, cfg.NATS.Cell)
	if err := agent.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}

func check(ctx context.Context, cfg Config, output io.Writer) error {
	connection, err := externalNATS(cfg.NATS)
	if err != nil {
		return err
	}
	runtime, err := natscell.Start(ctx, connection)
	if err != nil {
		return err
	}
	defer runtime.Close()
	probeCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	if err := runtime.WaitForCluster(probeCtx, cfg.NATS.Replicas); err != nil {
		return err
	}
	fmt.Fprintf(output, "regional NATS and JetStream ready: %s\n", cfg.NATS.Cell)
	return nil
}

func externalNATS(cfg natscell.Config) (natscell.Config, error) {
	if cfg.Embedded == nil {
		return cfg, nil
	}
	embedded := cfg.Embedded
	if embedded.Port < 1 {
		return cfg, errors.New("client command requires a fixed embedded NATS port")
	}
	hostname := embedded.Host
	if hostname == "0.0.0.0" || hostname == "::" {
		hostname = "127.0.0.1"
	}
	scheme := "nats"
	if embedded.TLS.CAFile != "" {
		scheme = "tls"
	}
	cfg.URL = scheme + "://" + net.JoinHostPort(hostname, fmt.Sprint(embedded.Port))
	cfg.Embedded = nil
	return cfg, nil
}

func newIdentity(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("identity-new", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	path := flags.String("key", "", "path for new private Ed25519 identity")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || flags.NArg() != 0 {
		return errors.New("usage: identity-new --key PRIVATE_KEY_FILE")
	}
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}
	file, err := os.OpenFile(*path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create private key: %w", err)
	}
	defer file.Close()
	if _, err := io.WriteString(file, base64.StdEncoding.EncodeToString(private)+"\n"); err != nil {
		return err
	}
	if err := file.Sync(); err != nil {
		return err
	}
	fmt.Fprintln(output, base64.StdEncoding.EncodeToString(public))
	return nil
}

func readPrivateKey(path string) (ed25519.PrivateKey, error) {
	if path == "" {
		return nil, errors.New("private identity key file is required")
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, fmt.Errorf("open private key: %w", err)
	}
	file := os.NewFile(uintptr(fd), path)
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat private key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("private key must be a regular file readable only by its owner")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Getuid()) {
		return nil, errors.New("private key must be owned by this process user")
	}
	data, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil {
		return nil, fmt.Errorf("read private key: %w", err)
	}
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
	if err != nil {
		return nil, fmt.Errorf("decode private key: %w", err)
	}
	if len(decoded) != ed25519.PrivateKeySize {
		return nil, errors.New("private key must contain 64 Ed25519 bytes")
	}
	return ed25519.PrivateKey(decoded), nil
}

func decodePublicKey(encoded string) (ed25519.PublicKey, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(decoded) != ed25519.PublicKeySize {
		return nil, errors.New("expected a base64 Ed25519 public key")
	}
	return ed25519.PublicKey(decoded), nil
}

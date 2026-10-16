package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"runtime"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
)

func runNetBirdEnroll(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("netbird-enroll", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	configPath := flags.String("config", "", "public NetBird enrollment configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("netbird-enroll accepts no positional arguments")
	}
	if os.Geteuid() != 0 {
		return errors.New("netbird-enroll must run as root")
	}
	return enrollNetBirdBootstrap(ctx, *configPath, output, netbirdBootstrapRuntime{
		binary: "/usr/local/bin/netbird", fallback: "/usr/local/lib/terrascale-orchestrator/netbird-client",
		status: client.ManagedStatus, defaults: client.ReadBootstrapConfig, install: client.InstallManaged, confirm: client.ConfirmManaged,
		enroll: func(ctx context.Context, _ netbird.Config) error { return client.EnrollBootstrap(ctx, *configPath) },
	})
}

type netbirdBootstrapRuntime struct {
	binary, fallback string
	status           func(context.Context) (client.ManagedResult, error)
	defaults         func(context.Context, string, bool) (client.Pin, netbird.Config, error)
	install          func(context.Context, client.Pin, netbird.Config, client.ManagedOptions) (client.ManagedResult, error)
	confirm          func(context.Context, string) error
	enroll           func(context.Context, netbird.Config) error
}

func enrollNetBirdBootstrap(ctx context.Context, configPath string, output io.Writer, runner netbirdBootstrapRuntime) error {
	// Recovery may restore the public config; read it only after the journal.
	transaction, err := runner.status(ctx)
	if err != nil {
		return err
	}
	bootstrapPending := transaction.Pending && transaction.Bootstrap
	if transaction.Pending && !bootstrapPending {
		return errors.New("NetBird enrollment waits for the controller-owned managed transaction")
	}
	_, binaryErr := os.Lstat(runner.binary)
	if binaryErr != nil && !errors.Is(binaryErr, os.ErrNotExist) {
		return binaryErr
	}
	if errors.Is(binaryErr, os.ErrNotExist) && transaction.TransactionID != "" && !transaction.Bootstrap {
		return errors.New("missing NetBird client awaits the controller-owned fenced rollout")
	}
	needsPin := errors.Is(binaryErr, os.ErrNotExist) || bootstrapPending
	pin, cfg, err := runner.defaults(ctx, configPath, needsPin)
	if err != nil {
		return err
	}
	if needsPin {
		archive, err := pin.Archive(runtime.GOARCH)
		if err != nil {
			return err
		}
		if err := client.VerifyBinary(runner.fallback, archive.BinarySHA256, runtime.GOARCH); err != nil {
			if bootstrapPending {
				return fmt.Errorf("NetBird bootstrap transaction awaits its verified fallback: %w", err)
			}
			fmt.Fprintln(output, "NetBird install held for authenticated cell artifact delivery")
			return nil
		}
		transactionID := transaction.TransactionID
		if !bootstrapPending {
			transactionID = entityid.New()
		}
		installed, err := runner.install(ctx, pin, cfg, client.ManagedOptions{BinaryPath: runner.fallback, TransactionID: transactionID, Bootstrap: true})
		if err != nil {
			return err
		}
		if err := runner.confirm(ctx, installed.TransactionID); err != nil {
			return err
		}
	}
	if err := runner.enroll(ctx, cfg); err != nil {
		return err
	}
	fmt.Fprintln(output, "NetBird connected to TerraScale management and signal")
	return nil
}

package app

import (
	"context"
	"errors"
	"flag"
	"io"
	"path/filepath"

	local "github.com/TerraScale/ts-orchestrator/internal/netbird/agent"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
)

func runNetBirdAgent(ctx context.Context, args []string) error {
	if len(args) == 0 {
		return errors.New("usage: ts-orch netbird agent run|rollback")
	}
	if args[0] != "run" && args[0] != "rollback" {
		return errors.New("unknown NetBird agent command")
	}
	flags := flag.NewFlagSet("netbird-agent", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	config := flags.String("config", "", "host role configuration")
	transaction := flags.String("transaction", "", "rollback transaction ID")
	if err := flags.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("NetBird agent accepts no positional arguments")
	}
	if args[0] == "rollback" {
		return client.RollbackPendingManaged(ctx, *transaction)
	}
	cfg, err := LoadConfig(*config)
	if err != nil {
		return err
	}
	public, err := decodePublicKey(cfg.Host.ControllerPublicKey)
	if err != nil {
		return err
	}
	return local.Run(ctx, local.Config{Cell: cfg.NATS.Cell, Node: cfg.Host.Node, Controller: public,
		Directory: filepath.Join(cfg.Host.StateRoot, cfg.NATS.Cell, cfg.Host.Node, "netbird")}, readNetBirdSetupKey)
}

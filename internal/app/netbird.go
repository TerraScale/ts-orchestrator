package app

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird"
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
	cfg, err := netbird.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	if err := netbird.Enroll(ctx, cfg); err != nil {
		return err
	}
	fmt.Fprintln(output, "NetBird connected to TerraScale management and signal")
	return nil
}

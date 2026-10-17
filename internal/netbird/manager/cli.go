package manager

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
)

// Commands exposes only offline image construction; account writes belong to the dedicated supervisor.
var Commands = []string{"image-input"}

func Run(ctx context.Context, args []string, output io.Writer) error {
	const usage = "usage: ts-orch netbird image-input --plan PLAN --out FILE\n"
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(output, usage)
		return err
	}
	if args[0] != "image-input" {
		return fmt.Errorf("unknown netbird command %q; account writes belong to the dedicated foundation", args[0])
	}
	flags := flag.NewFlagSet("netbird image-input", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	plan := flags.String("plan", "", "reviewed regional plan")
	out := flags.String("out", "", "new public image configuration file")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *plan == "" || *out == "" {
		return errors.New(usage)
	}
	return writeImageInput(*plan, *out)
}

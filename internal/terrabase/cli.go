package terrabase

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"
)

const cliUsage = "Usage: ts-orch terrabase member-ca --cell CELL --out DIR\n\n" +
	"  member-ca  Create a cell's TerraBase member CA: DIR/member-ca.pem and the owner-only DIR/member-ca.key\n"

// Run dispatches the local, NATS-free TerraBase commands.
func Run(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] != "member-ca" {
		_, err := io.WriteString(output, cliUsage)
		if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
			return err
		}
		return fmt.Errorf("unknown terrabase command %q", args[0])
	}
	flags := flag.NewFlagSet("terrabase member-ca", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	cell := flags.String("cell", "", "cell name, for example gru-1")
	out := flags.String("out", "", "new directory for the CA files")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	if flags.NArg() != 0 || *cell == "" || *out == "" {
		return errors.New("member-ca requires --cell and --out")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	certificate, key, err := NewCA(*cell, time.Now())
	if err != nil {
		return err
	}
	// A new directory: an existing CA is never overwritten.
	if err := os.Mkdir(*out, 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "member-ca.key"), key, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(*out, "member-ca.pem"), certificate, 0o644); err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "{\"certificate\":%q,\"key\":%q}\n",
		filepath.Join(*out, "member-ca.pem"), filepath.Join(*out, "member-ca.key"))
	return err
}

// Command vm-declaration prepares a private six-guest declaration for
// Firecracker qualification. It has no production deployment mode.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"terrascale.tech/orchestrator/internal/testengineconfig"
)

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, "vm-declaration:", err)
		os.Exit(1)
	}
}

func run(args []string, out, errOut io.Writer) error {
	set := flag.NewFlagSet("vm-declaration", flag.ContinueOnError)
	set.SetOutput(io.Discard)
	var artifact, release, parent string
	set.StringVar(&artifact, "artifact", "", "TerraBase SHA-256 artifact digest")
	set.StringVar(&release, "release", "", "TerraBase release")
	set.StringVar(&parent, "out", "", "private parent directory for the generated unique root")
	if err := set.Parse(args); err != nil {
		return fmt.Errorf("usage: vm-declaration --artifact SHA256 --release RELEASE --out PRIVATE_DIR: %w", err)
	}
	if set.NArg() != 0 || artifact == "" || release == "" || filepath.Clean(parent) != parent || !filepath.IsAbs(parent) {
		return errors.New("usage: vm-declaration --artifact SHA256 --release RELEASE --out PRIVATE_DIR")
	}
	if err := os.MkdirAll(parent, 0o700); err != nil {
		return fmt.Errorf("create private output directory: %w", err)
	}
	if err := os.Chmod(parent, 0o700); err != nil {
		return fmt.Errorf("secure private output directory: %w", err)
	}
	fixture, err := testengineconfig.PrepareAt(parent, artifact, release)
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(out, "root=%s\ndeclaration=%s\nartifact=%s\nrelease=%s\n", fixture.Root, fixture.DeclarationPath, artifact, release)
	_, _ = fmt.Fprintln(errOut, "vm-declaration: private qualification material retained until explicitly removed")
	return nil
}

// Package cli provides the release commands of the unified orchestrator executable.
package cli

import (
	"context"
	"io"
)

const usage = `Usage: ts-orch release <command> [flags]

Commands:
  sign-delegation
  binary-candidate
  sign-binary
  verify-binary
  image-candidate
  sign-image
  verify-image
  publish
`

type command struct {
	ctx    context.Context
	output io.Writer
}

// Run executes a release command without starting the controller or host agent.
func Run(ctx context.Context, args []string, output io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		_, err := io.WriteString(output, usage)
		return err
	}
	return (command{ctx: ctx, output: output}).run(args)
}

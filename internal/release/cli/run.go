// Package cli provides the release commands of the unified orchestrator executable.
package cli

import (
	"context"
	"errors"
	"io"

	"github.com/TerraScale/ts-orchestrator/internal/commandio"
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
  sign-update-delegation
  sign-binary-update
  sign-spec-delegation
  sign-spec
  sign-root-rotation
  deploy
  service-deploy
  fleet-status
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
	writer := commandio.NewWriter(output)
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		_, err := io.WriteString(writer, usage)
		return errors.Join(err, ctx.Err(), writer.Err())
	}
	err := (command{ctx: ctx, output: writer}).run(args)
	return errors.Join(err, ctx.Err(), writer.Err())
}

// Package cli provides the bootstrap commands of the unified orchestrator executable.
package cli

import (
	"context"
	"io"
)

const usage = `Usage: ts-orch bootstrap <command> [flags]

Commands:
  verify-anchor
  verify-manifest
  sign-ledger-delegation
  sign-anchor
  sign-manifest
  render-controller-config
  render-operator-config
  render-host-enrollment-public
  install-operator-material
  open-customer-material
  open-rotated-customer-material
  generate-controller-material
  provision-controller-material
  sign-peer-receipt-delegation
  render-founder-continuity
  sign-founder-continuity
  sign-founder-plan
  sign-initial-founder-selection
  publish-initial-founder-selection
  sign-external-seed-reservation
  publish-external-seed-reservation
  observe-external-seed
  sign-external-seed-completion
  publish-external-seed-completion
  sign-founder-selection
  publish-founder-selection
`

type command struct {
	ctx    context.Context
	output io.Writer
}

// Run executes a bootstrap command without starting the controller or host agent.
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

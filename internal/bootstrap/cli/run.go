// Package cli provides the bootstrap commands of the unified orchestrator executable.
package cli

import (
	"context"
	"errors"
	"io"

	"github.com/TerraScale/ts-orchestrator/internal/commandio"
)

const usage = `Usage: ts-orch bootstrap <command> [flags]

Commands:
  verify-anchor
  verify-manifest
  sign-ledger-delegation
  sign-anchor
  sign-foundation
  prepare-foundation
  publish-foundation
  foundation provision BUNDLE
  sign-manifest
  sign-material-generation
  sign-accepted-identity-checkpoint
  sign-host-state-handoff-plan
  sign-identity-reset
  render-controller-config
  render-operator-config
  render-host-enrollment-public
  install-operator-material
  open-customer-material
  open-rotated-customer-material
  generate-controller-material
  generate-interregion-material
  render-interregion-config
  role-claim
  provision-controller-material
  sign-peer-receipt-delegation
  sign-founder-plan
  sign-initial-founder-selection
  publish-initial-founder-selection
  sign-external-seed-reservation
  publish-external-seed-reservation
  observe-external-seed
  sign-external-seed-completion
  publish-external-seed-completion
  sign-slot-retirement
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
	writer := commandio.NewWriter(output)
	var err error
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h" || args[0] == "help") {
		_, err = io.WriteString(writer, usage)
	} else {
		err = (command{ctx: ctx, output: writer}).run(args)
	}
	return errors.Join(err, ctx.Err(), writer.Err())
}

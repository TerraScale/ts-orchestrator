// Package cli composes the runtime and operator commands of one executable.
package cli

import (
	"context"
	"fmt"
	"io"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/app"
	bootstrapcli "git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/cli"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/commandio"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
	releasecli "git.terrascale.tech/TerraScale/ts-orchestrator/internal/release/cli"
)

const usage = `Usage: ts-orch <command> [flags]

Runtime:
  run                    Run the regional controller and embedded NATS
  host                   Run the host agent
  check                  Validate role configuration and connectivity
  bootstrap-controller   Install and start a signed controller
  host-setup             Install signed host enrollment
  host-volume-init       Initialize an admitted host volume
  install-controller-config  Install signed controller configuration
  netbird-enroll         Enroll the local NetBird client
  identity-new           Generate a host identity

Operator tooling:
  operator               Manage workloads through the regional controller
  bootstrap              Prepare, sign, verify, and publish bootstrap material
  release                Prepare, sign, verify, and publish release receipts
  oci-region             Plan and deploy regional OCI resources

Use ts-orch bootstrap --help or ts-orch release --help to list their commands.
`

// Run dispatches CLI commands before runtime configuration or NATS startup.
func Run(ctx context.Context, args []string, output io.Writer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(commandio.NewWriter(output), usage)
		return err
	}
	switch args[0] {
	case "bootstrap":
		return bootstrapcli.Run(ctx, args[1:], output)
	case "release":
		return releasecli.Run(ctx, args[1:], output)
	case "oci-region":
		return runOCIRegion(ctx, args[1:], commandio.NewWriter(output))
	case "run", "host", "check", "operator", "identity-new", "netbird-enroll",
		"bootstrap-controller", "bootstrap-credential-check", "bootstrap-admit-initial",
		"bootstrap-admit-restart", "install-controller-config", "host-setup", "host-volume-init":
		return app.Run(ctx, args, output)
	default:
		return fmt.Errorf("unknown command %q; use ts-orch --help", args[0])
	}
}

func runOCIRegion(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		_, err := io.WriteString(output, "Usage: ts-orch oci-region <command> [flags]\n\n  import-image  Import a qualified ARM64 QCOW2 and enforce the A1 launch contract\n  public-api    Expose member HTTPS through an OCI network load balancer\n")
		return err
	}
	switch args[0] {
	case "import-image":
		return imageimport.Run(ctx, args[1:], output)
	case "public-api":
		return publicapi.Run(ctx, args[1:], output)
	default:
		return fmt.Errorf("unknown oci-region command %q", args[0])
	}
}

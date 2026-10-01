// Package cli composes the runtime and operator commands of one executable.
package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/app"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/attempt"
	bootstrapcli "git.terrascale.tech/TerraScale/ts-orchestrator/internal/bootstrap/cli"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ci/realcaller"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ci/sourcedigest"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/commandio"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/image"
	netbirdclient "git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/client"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/imageimport"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/qualification/firecracker"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/qualification/memberstatus"
	releasecli "git.terrascale.tech/TerraScale/ts-orchestrator/internal/release/cli"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/runtimepriority"
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
  image                  Validate inputs, build, inspect, and promote images
  netbird                Fetch, verify, and install the NetBird client
  qualification          Run source-backed operational qualification
  source-digest          Compute the versioned TerraBase source-tree digest
  runtime-priority       Qualify runtime resources and run bounded pressure

Use ts-orch bootstrap --help or ts-orch release --help to list their commands.
`

// Run dispatches CLI commands before runtime configuration or NATS startup.
func Run(ctx context.Context, args []string, output io.Writer) (err error) {
	writer := commandio.NewWriter(output)
	output = writer
	defer func() { err = errors.Join(err, writer.Err()) }()
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
	case "image", "netbird":
		root, err := os.Getwd()
		if err != nil {
			return err
		}
		var diagnostics bytes.Buffer
		var code int
		if args[0] == "image" {
			code = image.Run(ctx, root, args[1:], commandio.NewWriter(output), &diagnostics)
		} else {
			code = netbirdclient.Run(ctx, root, args[1:], commandio.NewWriter(output), &diagnostics)
		}
		return commandStatus(ctx, code, &diagnostics)
	case "source-digest":
		var diagnostics bytes.Buffer
		return commandStatus(ctx, sourcedigest.Run(ctx, args[1:], commandio.NewWriter(output), &diagnostics), &diagnostics)
	case "qualification":
		return runQualification(ctx, args[1:], commandio.NewWriter(output))
	case "runtime-priority":
		if len(args) == 1 || args[1] == "help" || args[1] == "--help" || args[1] == "-h" {
			_, err := io.WriteString(output, "Usage: ts-orch runtime-priority <qualify|pressure|probe-admission|adapter|remote> [flags]\n")
			return err
		}
		return runtimepriority.Run(ctx, args[1:], commandio.NewWriter(output))
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
		_, err := io.WriteString(output, "Usage: ts-orch oci-region <command> [flags]\n\n  preview       Inventory, estimate, admit, and inspect regional resources\n  attempt       Resume an admitted regional bootstrap attempt\n  import-image  Import a qualified ARM64 QCOW2 and enforce the A1 launch contract\n  public-api    Expose member HTTPS through an OCI network load balancer\n")
		return err
	}
	switch args[0] {
	case "preview", "attempt":
		var diagnostics bytes.Buffer
		var code int
		if args[0] == "preview" {
			code = ociregion.PreviewRun(ctx, args[1:], output, &diagnostics)
		} else {
			code = attempt.Run(ctx, args[1:], output, &diagnostics)
		}
		return commandStatus(ctx, code, &diagnostics)
	case "import-image":
		return imageimport.Run(ctx, args[1:], output)
	case "public-api":
		return publicapi.Run(ctx, args[1:], output)
	default:
		return fmt.Errorf("unknown oci-region command %q", args[0])
	}
}

func commandStatus(ctx context.Context, code int, diagnostics *bytes.Buffer) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if code == 0 {
		return nil
	}
	message := strings.TrimSpace(diagnostics.String())
	if message == "" {
		message = fmt.Sprintf("command failed with exit code %d", code)
	}
	return fmt.Errorf("%s", message)
}

func runQualification(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "help" || args[0] == "-h" {
		_, err := io.WriteString(out, "Usage: ts-orch qualification <command> [flags]\n\n  real-caller    Qualify admitted real OCI callers\n  firecracker    Run disposable Firecracker qualification\n")
		return err
	}
	var diagnostics bytes.Buffer
	switch args[0] {
	case "real-caller":
		return commandStatus(ctx, realcaller.Run(ctx, args[1:], out, &diagnostics), &diagnostics)
	case "firecracker":
		if len(args) == 1 || args[1] == "--help" || args[1] == "help" || args[1] == "-h" {
			_, err := io.WriteString(out, "Usage: ts-orch qualification firecracker <generic|memberstatus|managedmember|production|prepare-base> [flags]\n")
			return err
		}
		var err error
		switch args[1] {
		case "generic":
			err = firecracker.RunGeneric(ctx, args[2:], out, &diagnostics)
		case "production":
			err = firecracker.RunProduction(ctx, args[2:], out, &diagnostics)
		case "prepare-base":
			err = firecracker.RunPrepareBase(ctx, args[2:], out, &diagnostics)
		case "memberstatus":
			err = memberstatus.Run(ctx, args[2:], out, &diagnostics)
		case "managedmember":
			err = firecracker.RunManagedMember(ctx, args[2:], out, &diagnostics)
		default:
			return fmt.Errorf("unknown Firecracker qualification %q", args[1])
		}
		if err != nil {
			return err
		}
		return nil
	default:
		return fmt.Errorf("unknown qualification command %q", args[0])
	}
}

// Package cli composes the runtime and operator commands of one executable.
package cli

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/atlas"
	"github.com/TerraScale/ts-orchestrator/internal/attempt"
	"github.com/TerraScale/ts-orchestrator/internal/benchmark"
	bootstrapcli "github.com/TerraScale/ts-orchestrator/internal/bootstrap/cli"
	"github.com/TerraScale/ts-orchestrator/internal/capacity"
	"github.com/TerraScale/ts-orchestrator/internal/ci/realcaller"
	"github.com/TerraScale/ts-orchestrator/internal/ci/sourcedigest"
	"github.com/TerraScale/ts-orchestrator/internal/commandio"
	"github.com/TerraScale/ts-orchestrator/internal/dashboard/accesscheck"
	"github.com/TerraScale/ts-orchestrator/internal/disasterrecovery"
	"github.com/TerraScale/ts-orchestrator/internal/edge/geodns"
	"github.com/TerraScale/ts-orchestrator/internal/functions"
	"github.com/TerraScale/ts-orchestrator/internal/image"
	"github.com/TerraScale/ts-orchestrator/internal/liveverify"
	"github.com/TerraScale/ts-orchestrator/internal/logscan"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	netbirdclient "github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	netbirddns "github.com/TerraScale/ts-orchestrator/internal/netbird/dns"
	netbirdmanager "github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/pathaudit"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/sshlogin"
	"github.com/TerraScale/ts-orchestrator/internal/networkcheck"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/hostnetwork"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/teardown"
	"github.com/TerraScale/ts-orchestrator/internal/qualification/firecracker"
	"github.com/TerraScale/ts-orchestrator/internal/qualification/memberstatus"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	releasecli "github.com/TerraScale/ts-orchestrator/internal/release/cli"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/runtimepriority"
	selfupdatecli "github.com/TerraScale/ts-orchestrator/internal/selfupdate/cli"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const usage = `Usage: ts-orch <command> [flags]

Runtime:
  single-host            Run one SwarmKit manager+worker with containerd and the HTTPS edge
  managed-runtime-start  Run the admitted root Swarm runtime
  function-worker        Run one admitted function revision
  run                    Run the regional controller and embedded NATS
  host                   Run the host agent
  check                  Validate role configuration and connectivity
  bootstrap-controller   Install and start a signed controller
  host-setup             Install signed host enrollment
  host-volume-init       Initialize an admitted host volume
  install-controller-config  Install signed controller configuration
  restore-controller-material  Rebuild the controller credentials in memory from Vault
  identity-rekey         Stage, install and clean up a root-signed in-place identity transaction
  netbird-enroll         Enroll the local NetBird client
  identity-new           Generate a host identity
  selfupdate             Stage, activate and watch binary-only A/B updates

Operator tooling:
  observe                Inspect authenticated metrics, history, snapshots, cluster and events
  usage                  Print regional node and service CPU/memory for a time window
  cost                   Print a region's OCI spend and month forecast (read-only)
  bench                  Run isolated in-region benchmark clients and save capacity reports
  dashboard              Check every GRU and SJC dashboard over NetBird (read-only)
  network                Check address and DNS coexistence of NetBird and Tailscale (read-only)
  verify                 Observe production health, persistence gaps and OIDC (read-only)
  log-scan               Count recent WARN and ERROR records per service and node (read-only)
  events                 Print recent single-host task and service state changes; -f streams them (read-only)
  operator               Manage workloads through the regional controller
  get                    Print the running cell's spec (its signed desired state)
  diff                   Plan a cell spec file against the running cell's spec
  apply                  Apply a signed cell spec to the running cell
  service                Apply and remove services in every region, list this host's (apply -f FILE | ls | rm NAME)
  mesh                   Show which regions answer on the cross-region mesh (ping)
  edge                   Apply (or --plan) the GeoDNS steering policy to the nearest healthy region (edge geodns)
  rollout                Status, publish, pause, resume and roll back the cell's orchestrator release
  node                   Drain, reboot, resize, add and retire a cell's nodes, one at a time behind the load balancer
  bootstrap              Prepare, sign, verify, and publish bootstrap material
  release                Prepare, sign, verify, and publish release receipts
  oci-region             Plan and deploy regional OCI resources
  region                 Bring a new region up in one command; verify it serves
  image                  Validate inputs, build, inspect, and promote images
  netbird                Install clients; manage policies and operator DNS; browserless SSH; audit control-plane paths
  qualification          Run source-backed operational qualification
  source-digest          Compute the versioned TerraBase source-tree digest
  terrabase              C# TerraBase member CA and member data volumes
  ts-auth                Provision ts-auth's Vault secrets and host firewall
  vault                  Store secrets in OCI Vault once; render host files from them
  ouroboros              Bootstrap TerraScale's own TerraBase organization, project keys and owner
  atlas                  Create the Atlas publish key; publish the cell's topology to Atlas once
  runtime-priority       Qualify runtime resources and run bounded pressure
  cluster                Break-glass controller quorum-loss recovery
  disaster-recovery      Prepare cross-region Object Storage and Vault recovery copies

Use ts-orch bootstrap --help or ts-orch release --help to list their commands.
ts-orch release push sends a main build to every region in deploy/m1/regions.json (CI only);
ts-orch release pin --state /var/lib/ts-orch prints a host's listener pin for that file.
ts-orch release mesh-check re-proves mesh ping, service apply and HTTPS in every region (CI only).
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
	if observability.UnderJournal() {
		// Runtime roles replace this logger with their own; operators keep plain output.
		logger, err := observability.NewLogger(os.Stderr, observability.LogConfig{}, nil, observability.Identity(args[0], "")...)
		if err != nil {
			return err
		}
		observability.ConfigureDefault(logger)
	}
	switch args[0] {
	case "managed-host-start":
		return app.RunAutomaticBootstrap(ctx, args[1:])
	case "managed-runtime-start":
		return app.RunManagedRuntime(ctx, args[1:], output)
	case "function-worker":
		return functions.Run(ctx, args[1:], output)
	case "root-oci-qualification":
		return app.RunRootOCIQualification(ctx, args[1:], os.Stdin, output)
	case "root-oci-qualification-read", "root-oci-qualification-probe":
		return app.RunRootOCIQualificationReader(ctx, args[0], args[1:], os.Stdin, output)
	case "single-host":
		return app.RunSingleHostServing(ctx, args[1:], output)
	case "service":
		return app.RunServiceCLI(ctx, args[1:], output)
	case "edge":
		return geodns.Run(ctx, args[1:], output)
	case "mesh":
		return mesh.RunCLI(ctx, args[1:], "/var/lib/ts-orch", output)
	case "observe":
		return runObserve(ctx, args[1:], output)
	case "usage":
		return capacity.Run(ctx, args[1:], output)
	case "cost":
		return runCost(ctx, args[1:], output)
	case "events":
		return app.RunEventsCLI(ctx, args[1:], output)
	case "bench":
		return benchmark.CLI(ctx, args[1:], output)
	case "dashboard":
		return accesscheck.Run(ctx, args[1:], output)
	case "network":
		return networkcheck.Run(ctx, args[1:], output)
	case "verify":
		return liveverify.Run(ctx, args[1:], output)
	case "log-scan":
		return logscan.Run(ctx, args[1:], output)
	case "bootstrap":
		return bootstrapcli.Run(ctx, args[1:], output)
	case "release":
		if len(args) > 1 && args[1] == "push" {
			return releasepush.Push(ctx, args[2:], output)
		}
		if len(args) > 1 && args[1] == "mesh-check" {
			return mesh.Check(ctx, args[2:], output)
		}
		if len(args) > 1 && args[1] == "pin" {
			return releasepush.Pin(args[2:], output)
		}
		return releasecli.Run(ctx, args[1:], output)
	case "selfupdate":
		return selfupdatecli.Run(ctx, args[1:], commandio.NewWriter(output))
	case "oci-region":
		return runOCIRegion(ctx, args[1:], commandio.NewWriter(output))
	case "region":
		if len(args) > 1 && args[1] == "create" {
			return provisionOriginalFoundationFromFile(ctx, args[2:], commandio.NewWriter(output))
		}
		return region.Run(ctx, args[1:], commandio.NewWriter(output), os.Stderr)
	case "image", "netbird":
		if args[0] == "netbird" && len(args) > 1 && args[1] == "dns" {
			return netbirddns.Run(ctx, args[2:], commandio.NewWriter(output))
		}
		if args[0] == "netbird" && len(args) > 1 && args[1] == "path-audit" {
			return pathaudit.Run(ctx, args[2:], commandio.NewWriter(output))
		}
		if args[0] == "netbird" && len(args) > 1 && args[1] == "agent" {
			return app.Run(ctx, append([]string{"netbird-agent"}, args[2:]...), output)
		}
		if args[0] == "netbird" && len(args) > 1 && slices.Contains(netbirdmanager.Commands, args[1]) {
			return netbirdmanager.Run(ctx, args[1:], commandio.NewWriter(output))
		}
		if args[0] == "netbird" && len(args) > 1 && args[1] == "ssh" {
			return sshlogin.Run(ctx, args[2:], commandio.NewWriter(output))
		}
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
	case "terrabase":
		return terrabase.Run(ctx, args[1:], commandio.NewWriter(output))
	case "ts-auth":
		return tsauth.Run(ctx, args[1:], commandio.NewWriter(output), ociregion.LoadPlan)
	case "vault":
		return vaultsecret.Run(ctx, args[1:], commandio.NewWriter(output))
	case "atlas":
		if len(args) > 1 && args[1] == "add-region" {
			return app.Run(ctx, append([]string{"operator", "atlas-add-region"}, args[2:]...), output)
		}
		return atlas.Run(ctx, args[1:], commandio.NewWriter(output), ociregion.LoadPlan)
	case "ouroboros":
		return tsauth.RunOuroboros(ctx, args[1:], commandio.NewWriter(output), ociregion.LoadPlan)
	case "source-digest":
		var diagnostics bytes.Buffer
		return commandStatus(ctx, sourcedigest.Run(ctx, args[1:], commandio.NewWriter(output), &diagnostics), &diagnostics)
	case "qualification":
		return runQualification(ctx, args[1:], commandio.NewWriter(output))
	case "cluster":
		return runCluster(ctx, args[1:], commandio.NewWriter(output))
	case "disaster-recovery":
		return disasterrecovery.Run(ctx, args[1:], commandio.NewWriter(output))
	case "runtime-priority":
		if len(args) == 1 || args[1] == "help" || args[1] == "--help" || args[1] == "-h" {
			_, err := io.WriteString(output, "Usage: ts-orch runtime-priority <qualify|pressure|probe-admission|adapter|remote> [flags]\n")
			return err
		}
		return runtimepriority.Run(ctx, args[1:], commandio.NewWriter(output))
	case "run", "host", "check", "operator", "get", "diff", "apply", "rollout", "node", "identity-new", "netbird-enroll",
		"bootstrap-controller", "bootstrap-credential-check", "bootstrap-admit-initial",
		"bootstrap-admit-restart", "identity-rekey-completion-check", "identity-rekey", "install-controller-config", "host-setup", "host-volume-init", "restore-controller-material":
		return app.Run(ctx, args, output)
	default:
		return fmt.Errorf("unknown command %q; use ts-orch --help", args[0])
	}
}

func runOCIRegion(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		_, err := io.WriteString(output, "Usage: ts-orch oci-region <command> [flags]\n\n  preview       Inventory, estimate, admit, and inspect regional resources\n  foundation    Create the plan's missing compartments, network, Vault, IAM and buckets (dry run unless --apply)\n  network       Converge a static-host cell's VCN, subnets, gateways and role NSGs (dry run unless --apply)\n  peer          Create the private DRG/RPC peering of two cells that inspect-private-peer checks (dry run unless --apply)\n  attempt       Resume an admitted regional bootstrap attempt\n  public-api    Preview, certify and apply the cell's Cloudflare-fronted load balancer\n  dns           Set Full (strict), origin pulls and proxied A records in Cloudflare (dry run unless --apply)\n  teardown      Delete a reviewed cell teardown plan's OCI resources in dependency order\n")
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
	case "foundation":
		return foundation.Run(ctx, args[1:], output)
	case "network":
		return hostnetwork.Run(ctx, args[1:], output)
	case "peer":
		return foundation.RunPeer(ctx, args[1:], output)
	case "public-api":
		return publicapi.Run(ctx, args[1:], output)
	case "dns":
		return publicapi.RunDNS(ctx, args[1:], output)
	case "teardown":
		return teardown.Run(ctx, args[1:], output)
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

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

	"github.com/TerraScale/ts-orchestrator/internal/alertdelivery"
	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/benchmark"
	"github.com/TerraScale/ts-orchestrator/internal/callerkey"
	"github.com/TerraScale/ts-orchestrator/internal/capacity"
	"github.com/TerraScale/ts-orchestrator/internal/ci/sourcedigest"
	"github.com/TerraScale/ts-orchestrator/internal/commandio"
	"github.com/TerraScale/ts-orchestrator/internal/dashboard/accesscheck"
	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/imagetrust"
	"github.com/TerraScale/ts-orchestrator/internal/liveverify"
	"github.com/TerraScale/ts-orchestrator/internal/logscan"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	netbirdclient "github.com/TerraScale/ts-orchestrator/internal/netbird/client"
	netbirddns "github.com/TerraScale/ts-orchestrator/internal/netbird/dns"
	netbirdmanager "github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/pathaudit"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/sshlogin"
	"github.com/TerraScale/ts-orchestrator/internal/networkcheck"
	"github.com/TerraScale/ts-orchestrator/internal/nodeinit"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/foundation"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/hostnetwork"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/publicapi"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/teardown"
	"github.com/TerraScale/ts-orchestrator/internal/ocirelease"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/TerraScale/ts-orchestrator/internal/regionhost"
	"github.com/TerraScale/ts-orchestrator/internal/releasepreflight"
	"github.com/TerraScale/ts-orchestrator/internal/releasepush"
	"github.com/TerraScale/ts-orchestrator/internal/signedrelease"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

const usage = `Usage: ts-orch <command> [flags]

Runtime:
  alert-delivery         Deliver loopback Alertmanager notifications through Cloudflare Email Sending
  bootstrap-maintenance  Inspect or drive a finite pinned TerraBase bootstrap transaction (root, local socket)
  node                   Run this host's SwarmKit node with containerd and the HTTPS edge (--state DIR)

Operator tooling:
  observe                Inspect node dashboards in every production region (defaults to cluster)
  usage                  Print regional node and service CPU/memory for a time window
  cost                   Print a region's OCI spend and month forecast (read-only)
  bench                  Run isolated in-region benchmark clients and save capacity reports
  dashboard              Check every GRU and SJC dashboard over NetBird (read-only)
  network                Check address and DNS coexistence of NetBird and Tailscale (read-only)
  verify                 Observe production health, persistence gaps and OIDC (read-only)
  log-scan               Count recent WARN and ERROR records per service and node (read-only)
  events                 Print recent task and service state changes on this node; -f streams them (read-only)
  service                Apply and remove services in every region, list this host's (apply -f FILE | ls | rm NAME)
  member                 List this region's cluster hosts; drain and remove a worker (ls | leave HOSTNAME)
  mesh                   Show which regions answer on the mesh (ping); read the JetStream metadata group (meta)
  status                 Print every region's health: ok, degraded (memory, disk, replicas) or down
  edge                   Inspect certificates (edge certificates inventory, repair)
  release                Prepare, sign, verify, and publish release receipts
  oci-region             Plan and deploy regional OCI resources
  region                 Bring a new region up in one command; verify it serves
  netbird                Install clients; manage policies and operator DNS; browserless SSH; audit control-plane paths
  source-digest          Compute the versioned TerraBase source-tree digest
  terrabase              C# TerraBase member CA and member data volumes
  ts-auth                Provision ts-auth's Vault secrets and host firewall
  node-init              Install the launch release and bind the data volume at every host boot
  caller-key             Add, activate, retire, recover and list regional caller keys
  vault                  Store secrets in OCI Vault once; render host files from them
  ouroboros              Bootstrap TerraScale's own TerraBase organization, project keys and owner

Use ts-orch release --help to list its commands.
`

const releaseUsage = `Usage: ts-orch release <command> [flags]

ts-orch release hosts <revision> observes that every registered host runs the revision;
ts-orch release wait --service <name> --image <ref@sha256> observes a pulled app rollout over authenticated HTTPS;
ts-orch release wait-signed --service <name> --image <ref@sha256> proves the exact signed release and authorized regional readiness;
ts-orch release digests --out <file> records every mesh service's running image (app-digests CI only);
ts-orch release mesh-check reads mesh health, running digests and HTTPS in every region (CI only).
ts-orch release manifest --sha <sha> --sequence <n> --out <file> builds a signed-release manifest from a CI release's binaries;
ts-orch release sign --manifest <file> --key <keyfile> signs a manifest with an SSH key (namespace ts-orch-release);
ts-orch release verify --manifest <file> [--sig <file>] [--allowed <file>] verifies a manifest against the allowed SSH keys.
ts-orch release channel prepare <dist> <sha> <run> <seq> <channel.json> writes the channel document of a release for CI to sign;
ts-orch release channel publish <dist> <channel dir> pushes the release and its channel to every region's OCIR and verifies them;
ts-orch release verify-provenance --image <ref@sha256> --workflow <path@ref> --revision <sha> verifies an image's provenance attestation;
ts-orch release preflight [secrets] reads this host's service secrets with a candidate binary before it is accepted;
ts-orch release recover finishes or rolls back this host's pending release trial (run by its recovery unit).
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
	case "alert-delivery":
		return alertdelivery.Run(ctx, args[1:])
	case "bootstrap-maintenance":
		return app.RunBootstrapMaintenance(ctx, args[1:], output)
	case "service":
		return app.RunServiceCLI(ctx, args[1:], output)
	case "member":
		return app.RunMemberCLI(ctx, args[1:], output)
	case "edge":
		if len(args) > 1 && args[1] == "certificates" {
			if len(args) > 2 && args[2] == "repair" {
				return edge.RunCertificateCLI(ctx, args[2:], output)
			}
			return app.RunCertificateCLI(ctx, args[2:], output)
		}
		return errors.New("usage: ts-orch edge certificates <inventory|repair>")
	case "mesh":
		return mesh.RunCLI(ctx, args[1:], "/var/lib/ts-orch", output)
	case "status":
		return regionhealth.RunCLI(ctx, args[1:], "/var/lib/ts-orch", output)
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
	case "node":
		return app.RunNode(ctx, args[1:], output)
	case "release":
		if len(args) > 1 && args[1] == "recover" {
			if len(args) != 2 {
				return errors.New("usage: ts-orch release recover")
			}
			return releasepush.Recovery(ctx, output)
		}
		if len(args) > 1 && args[1] == "preflight" {
			if len(args) == 3 && args[2] == "secrets" {
				return releasepreflight.Secrets(ctx)
			}
			if len(args) != 2 {
				return errors.New("usage: ts-orch release preflight [secrets]")
			}
			return releasepreflight.Run(ctx)
		}

		if len(args) > 1 && args[1] == "hosts" {
			return releasepush.WaitHosts(ctx, args[2:], output)
		}
		if len(args) > 1 && args[1] == "wait" {
			return releasepush.WaitApp(ctx, args[2:], output)
		}
		if len(args) > 1 && args[1] == "wait-signed" {
			return releasepush.WaitSignedApp(ctx, args[2:], output)
		}
		if len(args) > 1 && args[1] == "digests" {
			return releasepush.Digests(ctx, args[2:], output)
		}
		if len(args) > 1 && args[1] == "mesh-check" {
			return mesh.Check(ctx, args[2:], output)
		}
		if len(args) > 1 && (args[1] == "manifest" || args[1] == "sign" || args[1] == "verify") {
			return signedrelease.Run(ctx, args[1:], output)
		}
		if len(args) > 1 && args[1] == "channel" {
			return ocirelease.Run(ctx, args[2:], output, releasepush.AnnounceChannel)
		}
		if len(args) > 1 && args[1] == "verify-provenance" {
			return imagetrust.VerifyImage(ctx, args[2:], output)
		}
		if len(args) == 1 || args[1] == "help" || args[1] == "--help" || args[1] == "-h" {
			_, err := io.WriteString(output, releaseUsage)
			return err
		}
		return fmt.Errorf("unknown release command %q; use ts-orch release --help", args[1])
	case "oci-region":
		return runOCIRegion(ctx, args[1:], commandio.NewWriter(output))
	case "region":
		if len(args) > 1 && (args[1] == "add" || args[1] == "rm" || args[1] == "backups") {
			return regionhost.Run(ctx, args[1:], output)
		}
		regionError := region.Run(ctx, args[1:], commandio.NewWriter(output), os.Stderr, regionhealth.RegionQuorum)
		if len(args) >= 2 && args[1] == "status" {
			return errors.Join(regionError, regionhealth.PrintReconcile(ctx, "/var/lib/ts-orch", output))
		}
		return regionError
	case "netbird":
		if len(args) > 1 && args[1] == "dns" {
			return netbirddns.Run(ctx, args[2:], commandio.NewWriter(output))
		}
		if len(args) > 1 && args[1] == "path-audit" {
			return pathaudit.Run(ctx, args[2:], commandio.NewWriter(output))
		}
		if len(args) > 1 && slices.Contains(netbirdmanager.Commands, args[1]) {
			return netbirdmanager.Run(ctx, args[1:], commandio.NewWriter(output))
		}
		if len(args) > 1 && args[1] == "ssh" {
			return sshlogin.Run(ctx, args[2:], commandio.NewWriter(output))
		}
		root, err := os.Getwd()
		if err != nil {
			return err
		}
		var diagnostics bytes.Buffer
		code := netbirdclient.Run(ctx, root, args[1:], commandio.NewWriter(output), &diagnostics)
		return commandStatus(ctx, code, &diagnostics)
	case "terrabase":
		return terrabase.Run(ctx, args[1:], commandio.NewWriter(output))
	case "node-init":
		return nodeinit.Boot(ctx, args[1:], output)
	case "ts-auth":
		return tsauth.Run(ctx, args[1:], commandio.NewWriter(output), ociregion.LoadPlan)
	case "caller-key":
		return callerkey.Run(ctx, args[1:], output)
	case "vault":
		return vaultsecret.Run(ctx, args[1:], commandio.NewWriter(output))
	case "ouroboros":
		return tsauth.RunOuroboros(ctx, args[1:], commandio.NewWriter(output), ociregion.LoadPlan)
	case "source-digest":
		var diagnostics bytes.Buffer
		return commandStatus(ctx, sourcedigest.Run(ctx, args[1:], commandio.NewWriter(output), &diagnostics), &diagnostics)
	default:
		return fmt.Errorf("unknown command %q; use ts-orch --help", args[0])
	}
}

func runOCIRegion(ctx context.Context, args []string, output io.Writer) error {
	if len(args) == 0 || args[0] == "--help" || args[0] == "-h" || args[0] == "help" {
		_, err := io.WriteString(output, "Usage: ts-orch oci-region <command> [flags]\n\n  preview       Inventory, estimate, admit, and inspect regional resources\n  foundation    Create the plan's missing compartments, network, Vault, IAM and buckets (dry run unless --apply)\n  network       Converge a static-host cell's VCN, subnets, gateways and role NSGs (dry run unless --apply)\n  peer          Create the private DRG/RPC peering of two cells that inspect-private-peer checks (dry run unless --apply)\n  public-api    Preview, certify and apply the cell's Cloudflare-fronted load balancer\n  dns           Set Full (strict), origin pulls and proxied A records in Cloudflare (dry run unless --apply)\n  teardown      Delete a reviewed cell teardown plan's OCI resources in dependency order\n")
		return err
	}
	switch args[0] {
	case "preview":
		var diagnostics bytes.Buffer
		code := ociregion.PreviewRun(ctx, args[1:], output, &diagnostics)
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

package region

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/fleet"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

const usage = `Usage: ts-orch region <command> [flags]

  plan [LABEL]
      Compare every region of the fleet document (deploy/fleet/fleet.json)
      with what exists in OCI: network, gateways, NSGs, instances, network
      load balancer, reserved address, DNS zone and steering policies.
      Document-made resources carry the ownership tags; others are hand-made.
      Reads OCI with the operator's ~/.oci/config, or the instance principal
      where there is none, and live SwarmKit membership over this host's mesh.
      Changes nothing. LABEL limits the comparison to one region.
  status [LABEL]
      The same comparison, one line per region. Fails unless each selected
      region has three distinct ready, Raft-reachable SwarmKit managers.
  validate
      Load and validate the embedded fleet document; reads nothing else.
  apply  LABEL KIND...
      Run the named reconcile passes once for one region of the fleet
      document. With no kind it refuses and lists the registered kinds
      (network, nlb, compute, dns). dns reconciles global steering in the DNS compartment;
      network adopts the document-made VCN, subnets, gateways
      and NSGs unchanged and creates or converges the NAT gateway, the
      private subnet's route table and the node NSG. Same credentials as
      plan.
  derive  REGION --out FILE [--from PLAN]
      Derive the region's plan from another non-home region's reviewed plan
      (default deploy/oci-region/sjc-1-plan.json): names, addresses, the
      availability domain and the service gateway of the new region, every
      resource ID unbound. Reads OCI; changes nothing. REGION is a cell
      token (fra) or an OCI region (eu-frankfurt-1).
  backups CODE [--check|--apply]
      Inventory every live host's boot volume, policy and newest available
      backup. Read-only by default; --check fails for gaps or age over 8 days.
      --apply assigns ts-boot-weekly-4 to volumes without a policy.
  verify  LABEL --plan BOUND_PLAN [--wait 0]
      Fail unless <label>.api answers /healthz for its cell, <label>.auth
      serves its OIDC discovery and every load balancer backend is healthy.
      With --wait, retry until then.
`

type QuorumReader func(context.Context, fleet.Fleet) map[string]fleet.QuorumObservation

func Run(ctx context.Context, args []string, out, errOut io.Writer, quorums QuorumReader) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(out, usage)
		return err
	}
	command, args := args[0], args[1:]
	switch command {
	case "plan", "status", "validate":
		return compareFleet(ctx, command, args, out, quorums)
	case "apply":
		return fleet.Apply(ctx, args, out)
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: ts-orch region %s needs a region argument; see ts-orch region --help", command)
	}
	label, args := args[0], args[1:]
	flags := flag.NewFlagSet("region "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	from := flags.String("from", "deploy/oci-region/sjc-1-plan.json", "reviewed plan of another non-home region")
	output := flags.String("out", "", "new plan file")
	plan := flags.String("plan", "", "the region's bound plan")
	wait := flags.Duration("wait", 30*time.Minute, "how long verification retries")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected region arguments")
	}
	switch command {
	case "derive":
		if *output == "" {
			return errors.New("derive requires --out")
		}
		if _, err := os.Stat(*output); err == nil {
			return fmt.Errorf("%s exists; derive never overwrites a plan", *output)
		}
		entry, err := ResolveRegion(label)
		if err != nil {
			return err
		}
		if err := DerivePlan(ctx, LiveSDK, *from, entry.Name(), entry.OCIRegion, *output); err != nil {
			return err
		}
		_, err = fmt.Fprintln(out, *output)
		return err
	case "verify":
		if *plan == "" {
			return errors.New("verify requires --plan")
		}
		if !isFlagSet(flags, "wait") {
			*wait = 0
		}
		return verify(ctx, label, *plan, *wait, out)
	default:
		return fmt.Errorf("unknown region command %q; use ts-orch region --help", command)
	}
}

func compareFleet(ctx context.Context, command string, args []string, out io.Writer, quorums QuorumReader) error {
	if command == "validate" && len(args) != 0 {
		return fmt.Errorf("ts-orch region validate takes no arguments")
	}
	if len(args) > 1 {
		return fmt.Errorf("usage: ts-orch region %s [LABEL]", command)
	}
	document, err := fleet.Load()
	if err != nil {
		return err
	}
	if command == "validate" {
		_, err := fmt.Fprintf(out, "fleet document valid: %d regions, zone %s\n", len(document.Regions), document.DNS.Zone)
		return err
	}
	label := ""
	if len(args) == 1 {
		label = args[0]
		if _, err := document.Region(label); err != nil {
			return err
		}
	}
	reports, err := fleet.Plan(ctx, document, quorums(ctx, document), label)
	if err != nil {
		return err
	}
	if command == "status" {
		return errors.Join(fleet.PrintStatus(out, reports), fleet.RequireQuorum(reports))
	}
	return fleet.PrintPlan(out, reports)
}

func isFlagSet(flags *flag.FlagSet, name string) bool {
	set := false
	flags.Visit(func(f *flag.Flag) { set = set || f.Name == name })
	return set
}

// verify checks the region of a bound plan against production.
func verify(ctx context.Context, label, bound string, wait time.Duration, out io.Writer) error {
	entry, ok := catalog.LookupName(label)
	if !ok {
		return fmt.Errorf("region %s is not in the region catalog", label)
	}
	plan, err := ociregion.LoadPlan(bound)
	if err != nil {
		return err
	}
	if plan["cell"] != entry.Cell {
		return fmt.Errorf("%s is not %s's plan", bound, label)
	}
	sets := []string{"terrabase", "ts-auth"}
	if public, _ := plan["public_api"].(map[string]any); public["orch"] == true {
		sets = append(sets, "ts-orch")
	}
	factory, err := ociclient.OperatorConfig(entry.OCIRegion)
	if err != nil {
		return err
	}
	balancers, err := lb.NewSDKAPI(factory)
	if err != nil {
		return err
	}
	id, _ := plan["resource_ids"].(map[string]any)["network_load_balancer"].(string)
	cell, err := naming.RegionCell(entry.Cell).Name()
	if err != nil {
		return err
	}
	verifier := Verifier{
		HTTP: &http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		Cell: cell, API: "https://" + label + ".api.terrascale.tech", Auth: "https://" + label + ".auth.terrascale.tech",
		LB: balancers, LoadBalancerID: id, BackendSets: sets,
	}
	checks, err := verifier.Until(ctx, wait, 30*time.Second)
	return errors.Join(Print(out, checks), err)
}

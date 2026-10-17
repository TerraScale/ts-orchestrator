package region

import (
	"context"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/naming"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"github.com/TerraScale/ts-orchestrator/internal/ociresource/lb"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const usage = `Usage: ts-orch region <command> [flags]

  plan    REGION --out FILE [--from PLAN]
      Derive the region's plan from another non-home region's reviewed plan
      (default deploy/oci-region/sfo-1-plan.json): names, addresses, the
      availability domain and the service gateway of the new region, every
      resource ID unbound. Reads OCI; changes nothing. REGION is a cell
      token (fra) or an OCI region (eu-frankfurt-1).
  create  BUNDLE
      Provision the complete signed regional footprint through the same
      operator path as bootstrap foundation provision BUNDLE. Resumes the
      protected original launch and IAM records; discovery publishes last.
  verify  LABEL --plan BOUND_PLAN [--wait 0]
      Fail unless <label>.api answers /healthz for its cell, <label>.auth
      serves its OIDC discovery, every load balancer backend is healthy and
      Atlas lists the region with health ok. With --wait, retry until then.
`

// Run dispatches the region commands.
func Run(ctx context.Context, args []string, out, errOut io.Writer) error {
	if len(args) == 0 || args[0] == "help" || args[0] == "--help" || args[0] == "-h" {
		_, err := io.WriteString(out, usage)
		return err
	}
	command, args := args[0], args[1:]
	if command == "create" {
		return provisionFromFile(ctx, args, out)
	}
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return fmt.Errorf("usage: ts-orch region %s needs a region argument; see ts-orch region --help", command)
	}
	label, args := args[0], args[1:]
	flags := flag.NewFlagSet("region "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	from := flags.String("from", "deploy/oci-region/sfo-1-plan.json", "reviewed plan of another non-home region")
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
	case "plan":
		if *output == "" {
			return errors.New("plan requires --out")
		}
		if _, err := os.Stat(*output); err == nil {
			return fmt.Errorf("%s exists; plan never overwrites a plan", *output)
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

func provisionFromFile(ctx context.Context, args []string, out io.Writer) error {
	if len(args) != 1 || args[0] == "" || strings.HasPrefix(args[0], "-") {
		return errors.New("usage: ts-orch region create BUNDLE")
	}
	file, err := os.Open(args[0])
	if err != nil {
		return err
	}
	defer file.Close()
	const maximum = 3 << 20
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > maximum {
		return errors.New("foundation bundle must be a bounded regular file")
	}
	wire, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || len(wire) > maximum {
		return errors.Join(errors.New("foundation bundle exceeds its read bound"), err)
	}
	var bundle RetainedFoundation
	if err := json.Unmarshal(wire, &bundle, json.RejectUnknownMembers(true)); err != nil {
		return err
	}
	genesis, err := trust.DiscoveryGenesis()
	if err != nil {
		return err
	}
	if err := VerifyFoundationProvisionBundle(ctx, genesis, bundle); err != nil {
		return err
	}
	factory, err := ociclient.OperatorConfig(foundationHomeRegion)
	if err != nil {
		return err
	}
	if err := provisionOriginalFoundationCompartments(ctx, factory, genesis, bundle); err != nil {
		return err
	}
	_, err = fmt.Fprintln(out, "provisioned exact signed foundation footprint")
	return err
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
		Atlas: "https://atlas.terrascale.tech", LB: balancers, LoadBalancerID: id, BackendSets: sets,
	}
	checks, err := verifier.Until(ctx, wait, 30*time.Second)
	return errors.Join(Print(out, checks), err)
}

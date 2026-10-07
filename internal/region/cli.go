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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/naming"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociclient"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/catalog"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociresource/lb"
)

const usage = `Usage: ts-orch region <command> [flags]

  plan    LABEL OCI_REGION --out FILE [--from PLAN]
      Derive the region's plan from another non-home region's reviewed plan
      (default deploy/oci-region/sfo-1-plan.json): names, addresses, the
      availability domain and the service gateway of the new region, every
      resource ID unbound. Reads OCI; changes nothing.
  create  LABEL OCI_REGION --state DIR --attempt-base FILE --home-plan FILE
          [--from PLAN] [--home-operator FILE] [--deployment ID] [--wait 30m]
      Bring the region up: plan, foundation, the private peering with the
      global home (--home-plan is its bound plan), ts-auth secrets, the
      founding attempt, the load balancer with its Origin CA certificate,
      proxied DNS, Atlas, then verify. Each step is idempotent; a rerun
      resumes after the last finished step (DIR/journal.json) and prints each
      step's wall time. Needs CF_API_TOKEN and NB_PAT.
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
	want := 2
	if command == "verify" {
		want = 1
	}
	if len(args) < want || strings.HasPrefix(args[0], "-") || want == 2 && strings.HasPrefix(args[1], "-") {
		return fmt.Errorf("usage: ts-orch region %s needs %d positional arguments; see ts-orch region --help", command, want)
	}
	positional, args := args[:want], args[want:]
	flags := flag.NewFlagSet("region "+command, flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	from := flags.String("from", "deploy/oci-region/sfo-1-plan.json", "reviewed plan of another non-home region")
	output := flags.String("out", "", "new plan file")
	state := flags.String("state", "", "the region's working directory")
	base := flags.String("attempt-base", "", "attempt settings shared by every region (trust, tools, image, release)")
	home := flags.String("home-operator", "/var/lib/terrascale-operator/operator.json", "the global home's operator config")
	homePlan := flags.String("home-plan", "", "the global home's bound plan, the region's private peer")
	deployment := flags.String("deployment", "", "founding deployment ID (default <cell>-found-1)")
	plan := flags.String("plan", "", "the region's bound plan")
	wait := flags.Duration("wait", 30*time.Minute, "how long verification retries")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("unexpected region arguments")
	}
	label := positional[0]
	switch command {
	case "plan":
		if *output == "" {
			return errors.New("plan requires --out")
		}
		if _, err := os.Stat(*output); err == nil {
			return fmt.Errorf("%s exists; plan never overwrites a plan", *output)
		}
		if err := DerivePlan(ctx, LiveSDK, *from, label, positional[1], *output); err != nil {
			return err
		}
		_, err := fmt.Fprintln(out, *output)
		return err
	case "create":
		if *state == "" || *base == "" {
			return errors.New("create requires --state and --attempt-base")
		}
		run, err := Exec(out, errOut)
		if err != nil {
			return err
		}
		creation := Creation{Label: label, OCIRegion: positional[1], State: *state, Template: *from, AttemptBase: *base,
			HomeOperator: *home, HomePlan: *homePlan, Deployment: *deployment, Wait: *wait, Run: run, Lookup: LiveSDK, Now: time.Now, Out: out,
			Verify: func(ctx context.Context, bound string, wait time.Duration) error {
				return verify(ctx, label, bound, wait, out)
			}}
		return creation.Create(ctx)
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

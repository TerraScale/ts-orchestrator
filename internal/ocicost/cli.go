package ocicost

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

const costUsage = "Usage: ts-orch cost tag --region <cell> --compartment <ocid> [--compartment <ocid>...] [--apply]\n"

// Run handles `ts-orch cost tag` through the operator's OCI configuration.
func Run(ctx context.Context, args []string, out io.Writer) error {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		_, err := io.WriteString(out, costUsage)
		return err
	}
	switch args[0] {
	case "tag":
		return runTag(ctx, args[1:], out)
	default:
		return fmt.Errorf("unknown cost command %q; want tag", args[0])
	}
}

// compartmentFlags collects every --compartment flag.
type compartmentFlags []string

func (c *compartmentFlags) String() string { return strings.Join(*c, ",") }

func (c *compartmentFlags) Set(value string) error {
	*c = append(*c, value)
	return nil
}

func runTag(ctx context.Context, args []string, out io.Writer) error {
	flags := flag.NewFlagSet("cost tag", flag.ContinueOnError)
	flags.SetOutput(out)
	cell := flags.String("region", "", "cell token such as gru or sfo (required)")
	var compartments compartmentFlags
	flags.Var(&compartments, "compartment", "compartment OCID to tag; repeat for each (at least one required)")
	apply := flags.Bool("apply", false, "stamp the tags; without it the command only plans")
	if err := flags.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return nil
		}
		return err
	}
	if flags.NArg() > 0 {
		return fmt.Errorf("cost tag takes no positional arguments, got %q", flags.Args())
	}
	if *cell == "" {
		return errors.New("cost tag needs --region <cell>")
	}
	if len(compartments) == 0 {
		return errors.New("cost tag needs at least one --compartment <ocid>")
	}
	for _, compartment := range compartments {
		if err := CheckCompartment(compartment); err != nil {
			return fmt.Errorf("cost tag: %w", err)
		}
	}
	// The component rules match bucket names by the lower-case cell prefix.
	token := strings.ToLower(*cell)
	ociRegion, err := oci.Region(strings.ToUpper(token)).OCIRegion()
	if err != nil {
		return fmt.Errorf("cost tag: %w", err)
	}
	ctx, cancel := context.WithTimeout(ctx, passTimeout)
	defer cancel()
	return printTags(ctx, token, ociRegion, compartments, *apply, out)
}

// printTags lists the cell's billable resources in the given compartments,
// prints the stamps and untagged resources, and applies them with apply.
func printTags(ctx context.Context, cell, ociRegion string, compartments []string, apply bool, out io.Writer) error {
	factory, err := ociclient.OperatorConfig(ociRegion)
	if err != nil {
		return fmt.Errorf("cost tag: operator OCI config: %w", err)
	}
	api, err := ConnectTags(factory, compartments)
	if err != nil {
		return fmt.Errorf("cost tag: %w", err)
	}
	resources, err := api.Resources(ctx)
	if err != nil {
		return fmt.Errorf("cost tag: list resources: %w", err)
	}
	stamps, untagged := PlanTags(cell, resources, time.Now())
	for _, stamp := range stamps {
		fmt.Fprintf(out, "stamp %s %s %s %s=%s %s=%s\n", stamp.Resource.Type, stamp.Resource.Name, stamp.Resource.ID,
			ComponentTag, stamp.Tags[ComponentTag], RegionTag, stamp.Tags[RegionTag])
	}
	for _, resource := range untagged {
		fmt.Fprintf(out, "untagged %s %s %s\n", resource.Type, resource.Name, resource.ID)
	}
	if !apply {
		_, err := io.WriteString(out, "plan only; rerun with --apply\n")
		return err
	}
	result, err := applyStamps(ctx, api, stamps)
	if err != nil {
		return fmt.Errorf("cost tag: %w", err)
	}
	_, err = fmt.Fprintf(out, "stamped %d changed %d not_permitted %d untagged %d\n",
		result.Stamped, result.Changed, result.NotPermitted, len(untagged))
	return err
}

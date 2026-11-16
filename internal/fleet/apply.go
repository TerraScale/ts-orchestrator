package fleet

import (
	"context"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

type Pass struct {
	Kind  string
	Apply func(ctx context.Context, region Region, f *ociclient.Factory, out io.Writer) error
}

var Passes = []Pass{
	{Kind: "network", Apply: applyNetwork},
	{Kind: "nlb", Apply: applyNLB},
}

func kinds() string {
	var names []string
	for _, pass := range Passes {
		names = append(names, pass.Kind)
	}
	return strings.Join(names, " ")
}

func Apply(ctx context.Context, args []string, out io.Writer) error {
	if len(args) < 2 {
		return fmt.Errorf("usage: ts-orch region apply <label> <kind>...; registered kinds: %s", kinds())
	}
	label, wanted := args[0], args[1:]
	for i, kind := range wanted {
		if !slices.ContainsFunc(Passes, func(p Pass) bool { return p.Kind == kind }) {
			return fmt.Errorf("unknown kind %q; registered kinds: %s", kind, kinds())
		}
		if slices.Contains(wanted[:i], kind) {
			return fmt.Errorf("kind %q is named twice", kind)
		}
	}
	document, err := Load()
	if err != nil {
		return err
	}
	i := slices.IndexFunc(document.Regions, func(r Region) bool { return r.Label == label })
	if i < 0 {
		return fmt.Errorf("region %q is not in the fleet document", label)
	}
	region := document.Regions[i]
	f, err := factory(ctx, region.OCIRegion)
	if err != nil {
		return err
	}
	for _, pass := range Passes {
		if !slices.Contains(wanted, pass.Kind) {
			continue
		}
		if _, err := fmt.Fprintf(out, "%s %s\n", region.Label, pass.Kind); err != nil {
			return err
		}
		if err := pass.Apply(ctx, region, f, out); err != nil {
			return fmt.Errorf("%s %s: %w", region.Label, pass.Kind, err)
		}
	}
	return nil
}

package teardown

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/region"
)

// The current grant requires the GRU manager. A reviewed legacy teardown plan
// cannot retire it or authorize destruction of its retained recovery resources.
func (p *SDKProvider) teardown(ctx context.Context, plan Plan, apply bool, out io.Writer) error {
	if err := plan.Validate(); err != nil {
		return err
	}
	if plan.Region != "sa-saopaulo-1" {
		return Teardown(ctx, plan, p, apply, out)
	}
	resolver, err := region.DiscoverCurrentFoundation(ctx, p.factory)
	if err != nil {
		return fmt.Errorf("GRU teardown blocked: current foundation authority: %w", err)
	}
	view, err := region.ObserveNetBirdNetworkTeardown(ctx, p.factory, resolver)
	if err != nil {
		return fmt.Errorf("GRU teardown blocked: NetBird network provenance: %w", err)
	}
	if err := view.CheckProvenance(ctx); err != nil {
		return fmt.Errorf("GRU teardown blocked: NetBird network provenance changed: %w", err)
	}
	if _, err := fmt.Fprintf(out, "NetBird network inventory: operation %s generation %d instance %s observed %s\n", view.OperationID(), view.Generation(), view.InstanceID(), view.ObservedAt().Format(time.RFC3339)); err != nil {
		return err
	}
	for _, resource := range view.Resources() {
		if _, err := fmt.Fprintf(out, "%-8s %-24s %s compartment %s\n", "retain", resource.Kind, resource.ID, resource.CompartmentID); err != nil {
			return err
		}
	}
	for _, resource := range view.Keep() {
		if _, err := fmt.Fprintf(out, "%-8s %-24s %s compartment %s\n", "keep", resource.Kind, resource.ID, resource.CompartmentID); err != nil {
			return err
		}
	}
	blocked := []error{errors.New("GRU teardown has no verified manager retirement and protected-backup destructive authority")}
	for _, reason := range view.Blockers() {
		blocked = append(blocked, errors.New(reason))
		if _, err := fmt.Fprintf(out, "blocked: %s\n", reason); err != nil {
			return errors.Join(err, errors.Join(blocked...))
		}
	}
	return errors.Join(blocked...)
}

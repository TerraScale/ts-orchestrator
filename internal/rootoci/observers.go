package rootoci

import (
	"context"
	"errors"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ocicost"
)

// LocalInstanceObserver preserves admission's candidate comparison without
// allowing the caller to select an arbitrary OCI instance through IPC.
type LocalInstanceObserver struct{ Client *Client }

var _ bootstrapstart.InstanceObserver = LocalInstanceObserver{}

func (observer LocalInstanceObserver) ObserveInstance(ctx context.Context, candidate string) (bootstrapstart.InstanceObservation, error) {
	if observer.Client == nil || candidate == "" {
		return bootstrapstart.InstanceObservation{}, bootstrapstart.ErrInstanceObservation
	}
	observed, err := observer.Client.ObserveLocalInstance(ctx)
	if err != nil {
		return bootstrapstart.InstanceObservation{}, err
	}
	if observed.InstanceOCID != candidate {
		return bootstrapstart.InstanceObservation{}, bootstrapstart.ErrInstanceObservation
	}
	return observed, nil
}

// FleetObserver filters only already verified root observations. The predicate
// remains local; IPC never accepts code or caller-derived cloud scope.
type FleetObserver struct{ Client *Client }

var _ oci.FleetObserver = FleetObserver{}

func (observer FleetObserver) Observe(ctx context.Context) ([]oci.Instance, error) {
	if observer.Client == nil {
		return nil, ErrUnauthorized
	}
	return observer.Client.ObserveFleet(ctx)
}

func (observer FleetObserver) ObserveSelected(ctx context.Context, selectInstance func(id, node string) bool) ([]oci.Instance, error) {
	if selectInstance == nil {
		return nil, errors.New("root fleet observation requires a local selection predicate")
	}
	instances, err := observer.Observe(ctx)
	if err != nil {
		return nil, err
	}
	selected := make([]oci.Instance, 0, len(instances))
	for _, instance := range instances {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if selectInstance(instance.ID, instance.Node) {
			selected = append(selected, instance)
		}
	}
	return selected, nil
}

// CostReader lets the existing collector consume the root's bounded current
// report. The caller's clock cannot widen the Usage API query window.
type CostReader struct{ Client *Client }

var _ ocicost.Reader = CostReader{}

func (reader CostReader) Read(ctx context.Context, _ time.Time) (ocicost.Report, error) {
	if reader.Client == nil {
		return ocicost.Report{}, ErrUnauthorized
	}
	report, err := reader.Client.Costs(ctx)
	if err != nil {
		return ocicost.Report{}, err
	}
	if err := report.Validate(); err != nil {
		return ocicost.Report{}, err
	}
	return report, nil
}

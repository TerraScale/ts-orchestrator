package app

import (
	"context"
	"errors"
	"fmt"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
)

// Overridden only by tests whose local kernel clock is deliberately not an NTP
// qualification source. Production startup and broker authority share a probe.
var controllerBrokerClockProbe = func() brokerauth.ClockProbe { return brokerauth.KernelClockProbe{} }

func runAdmittedControllerFounder(ctx context.Context) error {
	identity, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil {
		return err
	}
	if _, err := bootstrapstart.ReadIdentityRekeyJournal(identity); err == nil {
		return nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	// The admission child is a process boundary. Reread the trusted public
	// inputs and accepted marker in this process before any founder work.
	baked, err := bootstrapstart.LoadBakedInputs()
	if err != nil {
		return fmt.Errorf("reread baked controller founder inputs: %w", err)
	}
	accepted, err := bootstrapstart.NewMarkerStore().ReadInitialFormation()
	if err != nil {
		return fmt.Errorf("reread accepted controller founder install: %w", err)
	}
	serviceUID, serviceGID, err := controllerServiceIdentity()
	if err != nil {
		return err
	}
	if accepted.DeploymentID != identity.DeploymentID || accepted.Cell != identity.Cell || accepted.Slot != identity.Slot ||
		accepted.InstanceOCID != identity.InstanceOCID || accepted.PrimaryVNICOCID != identity.PrimaryVNICOCID {
		return errors.New("initial formation history differs from accepted installation")
	}
	if _, derived, present, err := installedAutomaticStartup(ctx); err != nil {
		return err
	} else if present {
		return bootstrapstart.RunAdmittedDerivedFounder(ctx, baked, accepted, derived, serviceUID, serviceGID)
	}
	return bootstrapstart.RunAdmittedFounder(ctx, baked, accepted, serviceUID, serviceGID)
}

func controllerClockCheck(probe brokerauth.ClockProbe) func() error {
	return func() error {
		_, err := brokerauth.MeasureHealthyClock(probe)
		return err
	}
}

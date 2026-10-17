//go:build fixturetest

package app

import (
	"context"
	"errors"
	"io"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

type fixtureControllerHostSource struct {
	acquisition *bootstrapstart.ControllerSDKAcquisitionFixture
}

func (source fixtureControllerHostSource) founders(ctx context.Context) (*bootstrapstart.CurrentFounderAuthorityReader, error) {
	if ctx == nil || ctx.Err() != nil || source.acquisition == nil {
		return nil, bootstrapstart.ErrAdmission
	}
	reader := source.acquisition.Reader()
	accepted, err := bootstrapstart.NewMarkerStore().ReadIdentity()
	if err != nil || reader == nil {
		return nil, bootstrapstart.ErrAdmission
	}
	if _, err := reader.ReadRuntimeAuthority(ctx, accepted, time.Now().UTC()); err != nil {
		return nil, err
	}
	return reader, nil
}

// The test executable alone reconstructs ready SDK clients. The real hidden
// launcher, service account, installed Gate and registration body remain shared.
func runSDKFixtureControllerHostSource(ctx context.Context, args []string, input io.Reader, output io.Writer) (bool, error) {
	if _, err := os.Lstat("/run/ts-installed-controller-sdk/source.json"); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return true, err
	}
	uid, gid, err := controllerServiceIdentity()
	if err != nil || len(args) != 0 || os.Geteuid() != int(uid) || os.Getegid() != int(gid) {
		return true, bootstrapstart.ErrAdmission
	}
	wire, err := io.ReadAll(io.LimitReader(input, (128<<10)+1))
	var query swarmruntime.WorkerRegistrationQuery
	if err != nil || len(wire) == 0 || protocol.DecodeStrict(wire, &query, 128<<10) != nil || query.Swarm != nil {
		return true, bootstrapstart.ErrAdmission
	}
	acquisition, err := bootstrapstart.AcquireControllerSDKAcquisitionFixture(ctx)
	if err != nil {
		return true, err
	}
	cfg, err := LoadConfig(controllerConfigDirectory + "/" + controllerConfigFilename)
	if err != nil {
		return true, err
	}
	gate, accepted, err := acceptedControllerAdmissionGate(cfg, bootstrapstart.NewMarkerStore(), controllerClockCheck(controllerBrokerClockProbe()))
	if err != nil {
		return true, err
	}
	gate.Descriptor = acquisition.Descriptor()
	if _, err := gate.AdmitRestartLocal(ctx); err != nil {
		return true, err
	}
	return true, readRuntimeControllerHostAdmissionSource(ctx, cfg, accepted, query, output, fixtureControllerHostSource{acquisition})
}

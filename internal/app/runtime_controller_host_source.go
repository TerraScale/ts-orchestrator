package app

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/cellspec"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func currentControllerHostReader(ctx context.Context) (*bootstrapstart.CurrentFounderAuthorityReader, error) {
	initial, err := bootstrapstart.NewMarkerStore().ReadInitialFormation()
	if err != nil {
		return nil, err
	}
	uid, _, err := controllerServiceIdentity()
	if err != nil {
		return nil, err
	}
	floor, err := bootstrapstart.NewServiceFounderSelectionFloorStore(uid)
	if err != nil {
		return nil, err
	}
	local, err := foundationDiscovery(ctx)
	if err != nil {
		return nil, err
	}
	return currentControllerFounderReader(ctx, local.baked, initial, floor)
}

func controllerHostSpecCurrent(ctx context.Context, js jetstream.JetStream, services *specRegistry, entry jetstream.KeyValueEntry, rootHead string) error {
	if js == nil || js.Conn() == nil {
		return errors.New("controller host profile requires its current broker leader")
	}
	options := js.Options()
	var opts []nats.JSOpt
	if options.Domain != "" {
		opts = append(opts, nats.Domain(options.Domain))
	} else if options.APIPrefix != "" {
		opts = append(opts, nats.APIPrefix(options.APIPrefix))
	}
	reader, err := js.Conn().JetStream(opts...)
	if err != nil {
		return err
	}
	subject := "$KV." + cellSpecBucket + "." + cellSpecKey
	latest, err := reader.GetLastMsg("KV_"+cellSpecBucket, subject, nats.Context(ctx))
	if err != nil {
		return err
	}
	services.mu.Lock()
	adopted := services.revision
	services.mu.Unlock()
	if latest == nil || latest.Subject != subject || latest.Sequence == 0 || latest.Header.Get("KV-Operation") != "" || latest.Header.Get(jetstream.MarkerReasonHeader) != "" ||
		len(latest.Data) == 0 || len(latest.Data) > cellspec.MaxSignedBytes || latest.Sequence != entry.Revision() || adopted != entry.Revision() ||
		!bytes.Equal(latest.Data, entry.Value()) || services.roots.reply("").Head != rootHead {
		return errors.New("controller host profile or roots changed during recipient verification")
	}
	return rootTrustHeadCurrent(ctx, js, services.roots, rootHead)
}

func controllerHostRegistration(query swarmruntime.WorkerRegistrationQuery, snapshot swarmruntime.WorkerRegistrationSnapshot,
	request hostenroll.Request, descriptor hostboot.Descriptor, response hostenroll.Response, accepted bootstrapstart.AcceptedIdentity,
) error {
	registration := snapshot.Registration
	if !descriptor.IsController() || query.Swarm != nil || response.Swarm != nil || snapshot.Retired || snapshot.Disabled ||
		snapshot.TerminalOperationID != "" || snapshot.IdentityResetOperationID != "" ||
		descriptor.Cell != registration.Cell || !strings.EqualFold(descriptor.Region, accepted.Cell) ||
		registration.Node != descriptor.Node || registration.Environment != accepted.Environment ||
		registration.PublicKey != request.IdentityPublicKey || registration.NATSUserPublicKey != request.NATSUserPublicKey ||
		registration.Generation != response.RegistrationReceipt.Generation || snapshot.Sequence != response.RegistrationReceipt.Revision ||
		len(registration.Roles) == 0 || !slices.Equal(registration.Roles, response.Roles) ||
		registration.ManagedOCI != nil || registration.ManagedMember != nil || registration.ManagedPlacement != nil {
		return errors.New("controller host query differs from its current registered recipient")
	}
	return nil
}

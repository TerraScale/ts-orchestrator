package app

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/budget"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
	"github.com/TerraScale/ts-orchestrator/internal/ociregion/capacityinventory"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
)

type capacitySpendAuthority interface {
	InfrastructureSpend(context.Context) (region.VerifiedInfrastructureSpend, error)
}

// Regions send recipes, never sealed authority, quotes or inventory snapshots.
type capacityReservationRequest struct {
	Nonce       string                       `json:"nonce"`
	Request     budget.ReservationRequest    `json:"request"`
	Recipe      nodescale.Recipe             `json:"recipe"`
	Image       nodescale.ImageQualification `json:"image"`
	Receipt     *budget.Reservation          `json:"receipt,omitempty"`
	ResourceIDs []string                     `json:"resource_ids,omitempty"`
	Pool        *capacityPoolRequest         `json:"pool,omitempty"`
}

type capacityReservationResponse struct {
	Nonce   string                `json:"nonce"`
	Receipt *budget.Reservation   `json:"receipt,omitempty"`
	Error   string                `json:"error,omitempty"`
	Pool    *capacityPoolResponse `json:"pool,omitempty"`
}

type capacityReservations struct {
	cell, user, environment string
	conn                    *nats.Conn
	global                  *globalControl
	spending                capacitySpendAuthority
	workers                 capacityWorkerAuthority
	caFile                  string
	specs                   *specRegistry
	responseKey             ed25519.PrivateKey
	homeKey                 func(context.Context) (ed25519.PublicKey, error)
}

// startCapacityReservations serves only on the home global leader. The signed
// footprint supplies every accepted source cell; credentials independently bound
// those exact source subjects and the controller's private reply namespace.
func startCapacityReservations(ctx context.Context, cfg Config, conn *nats.Conn, global *globalControl,
	spending capacitySpendAuthority, specs *specRegistry,
	responseKey ed25519.PrivateKey, homeKey func(context.Context) (ed25519.PublicKey, error),
) (*capacityReservations, error) {
	data, err := readBoundedConfigFile(cfg.NATS.CredentialsFile)
	if err != nil {
		return nil, fmt.Errorf("read capacity requester identity: %w", err)
	}
	defer clear(data)
	raw, err := nkeys.ParseDecoratedJWT(data)
	if err != nil {
		return nil, err
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil || !nkeys.IsValidPublicUserKey(claim.Subject) {
		return nil, errors.New("capacity requester needs its authenticated controller user identity")
	}
	environment := ""
	if specs != nil {
		environment = specs.identity.Environment
	}
	r := &capacityReservations{cell: cfg.NATS.Cell, user: claim.Subject, environment: environment,
		conn: conn, global: global, spending: spending, specs: specs, responseKey: responseKey, homeKey: homeKey, caFile: cfg.NATS.TLS.CAFile}
	r.workers, _ = spending.(capacityWorkerAuthority)
	if global != nil && global.writer != nil && global.authority != nil {
		go r.serve(ctx)
	}
	return r, nil
}

func (r *capacityReservations) serve(ctx context.Context) {
	subscriptions := map[string]*nats.Subscription{}
	defer func() {
		for _, subscription := range subscriptions {
			_ = subscription.Unsubscribe()
		}
	}()
	for {
		type route struct{ source, action string }
		wanted := map[string]route{}
		add := func(source, action string) {
			if subject := protocol.CapacityReservationSubject(source, action); subject != "" {
				wanted[subject] = route{source: source, action: action}
			}
		}
		if r.spending != nil {
			proof, err := r.spending.InfrastructureSpend(ctx)
			if err == nil && proof.ValidAt(time.Now()) {
				for _, source := range proof.Footprint().Regions {
					for _, action := range []string{"reserve", "revalidate", "observe"} {
						add(source.Cell, action)
					}
				}
			}
		}
		// Known cleanup has its own signed worker purpose. Missing purchase or
		// current-image readiness must not remove its authenticated home route.
		if scopes, ok := r.spending.(interface {
			CapacityPoolCells(context.Context) ([]string, error)
		}); ok {
			if cells, err := scopes.CapacityPoolCells(ctx); err == nil {
				for _, cell := range cells {
					add(cell, "observe")
				}
			}
		}
		for subject, target := range wanted {
			if subscriptions[subject] != nil {
				continue
			}
			subscription, err := r.conn.Subscribe(subject, func(message *nats.Msg) {
				r.answer(ctx, target.source, target.action, message)
			})
			if err == nil {
				subscriptions[subject] = subscription
			}
		}
		for subject, subscription := range subscriptions {
			if _, keep := wanted[subject]; !keep {
				_ = subscription.Unsubscribe()
				delete(subscriptions, subject)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Minute):
		}
	}
}

func (r *capacityReservations) answer(ctx context.Context, source, action string, message *nats.Msg) {
	leading := r.global.authority.Current()
	if !leading.CanMutate() {
		return
	}
	var request capacityReservationRequest
	if protocol.DecodeStrict(message.Data, &request, 128<<10) != nil {
		return
	}
	parts := strings.Split(message.Reply, ".")
	if len(parts) != 6 || protocol.CapacityReservationReplySubject(source, parts[4], request.Nonce) != message.Reply {
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	response := capacityReservationResponse{Nonce: request.Nonce}
	var err error
	if request.Pool != nil {
		if action != "observe" {
			return
		}
		var stopLeader context.CancelFunc
		ctx, stopLeader = context.WithDeadline(ctx, leading.ExpiresAt)
		defer stopLeader()
		response.Pool, err = r.applyPool(ctx, source, *request.Pool, leading.Epoch)
	} else {
		var receipt budget.Reservation
		receipt, err = r.apply(ctx, source, action, request, leading.Epoch)
		if err == nil {
			response.Receipt = new(receipt)
		}
	}
	if errors.Is(err, authority.ErrFenced) || errors.Is(err, authority.ErrNotLeader) {
		return
	}
	if err != nil {
		response.Error = err.Error()
	}
	if err := r.global.authority.Guard(ctx, leading.Epoch); err != nil {
		return
	}
	payload, err := protocol.EncodeJSON(response)
	if err != nil {
		return
	}
	now := time.Now().UTC()
	expires := now.Add(30 * time.Second)
	if deadline, ok := ctx.Deadline(); ok && deadline.Before(expires) {
		expires = deadline
	}
	envelope, err := protocol.SignEnvelope(payload, protocol.EnvelopeScope{Region: source, Kind: "capacity." + action + ".response",
		Actor: "capacity-home", OperationID: request.Nonce, Epoch: leading.Epoch}, now, expires, r.responseKey)
	if err != nil {
		return
	}
	if wire, err := protocol.EncodeJSON(envelope); err == nil && r.global.authority.Guard(ctx, leading.Epoch) == nil {
		_ = message.Respond(wire)
	}
}

func (r *capacityReservations) facts(ctx context.Context) (*capacityinventory.Reader, region.VerifiedInfrastructureSpend, capacityinventory.Snapshot, error) {
	if r == nil || r.spending == nil {
		return nil, region.VerifiedInfrastructureSpend{}, capacityinventory.Snapshot{}, fmt.Errorf("%w: signed infrastructure spending authority is unavailable", nodescale.ErrCapacityPending)
	}
	proof, err := r.spending.InfrastructureSpend(ctx)
	if err != nil {
		return nil, proof, capacityinventory.Snapshot{}, err
	}
	ociRegion, err := oci.Region(strings.ToUpper(r.cell)).OCIRegion()
	if err != nil {
		return nil, proof, capacityinventory.Snapshot{}, err
	}
	factory, err := instancePrincipal(ctx, ociRegion)
	if err != nil {
		return nil, proof, capacityinventory.Snapshot{}, err
	}
	reader, err := capacityinventory.New(factory)
	if err != nil {
		return nil, proof, capacityinventory.Snapshot{}, err
	}
	snapshot, err := reader.Read(ctx, proof.Footprint())
	if err == nil {
		err = snapshot.Validate(proof.Footprint(), time.Now())
	}
	return reader, proof, snapshot, err
}

func (r *capacityReservations) apply(ctx context.Context, source, action string, request capacityReservationRequest, epoch uint64) (budget.Reservation, error) {
	reader, proof, snapshot, err := r.facts(ctx)
	if err != nil {
		return budget.Reservation{}, err
	}
	if !strings.EqualFold(request.Request.Cell, source) || !strings.EqualFold(request.Recipe.Cell, source) || !entityid.Valid(request.Request.OperationID) ||
		request.Request.RecipeSHA256 != request.Recipe.SHA256() || request.Recipe.Validate() != nil {
		return budget.Reservation{}, errors.New("capacity request differs from its authenticated source or exact recipe")
	}
	if err := r.global.authority.Guard(ctx, epoch); err != nil {
		return budget.Reservation{}, err
	}
	if action == "observe" {
		capacity, _, err := budget.ReadCapacity(ctx, r.global.reader)
		if err != nil {
			return budget.Reservation{}, err
		}
		if !slices.ContainsFunc(capacity.Reservations, func(receipt budget.Reservation) bool {
			return receipt.OperationID == request.Request.OperationID && receipt.Cell == request.Request.Cell &&
				receipt.CompartmentID == request.Request.CompartmentID && receipt.RecipeSHA256 == request.Recipe.SHA256()
		}) {
			return budget.Reservation{}, errors.New("capacity observation differs from the source's exact durable commitment")
		}
		return budget.Observe(ctx, r.global.reader, r.global.writer, epoch, request.Request.OperationID, request.ResourceIDs, proof, snapshot, time.Now())
	}
	quote, err := r.verifyCandidate(ctx, reader, proof, snapshot, request)
	if err != nil {
		return budget.Reservation{}, err
	}
	if err := r.global.authority.Guard(ctx, epoch); err != nil {
		return budget.Reservation{}, err
	}
	switch action {
	case "reserve":
		return budget.Reserve(ctx, r.global.reader, r.global.writer, epoch, request.Request, proof, quote, snapshot, time.Now())
	case "revalidate":
		if request.Receipt == nil || request.Receipt.OperationID != request.Request.OperationID || request.Receipt.RecipeSHA256 != request.Recipe.SHA256() {
			return budget.Reservation{}, errors.New("capacity revalidation needs its exact durable receipt")
		}
		err := budget.Revalidate(ctx, r.global.reader, *request.Receipt, proof, quote, snapshot, time.Now())
		return *request.Receipt, err
	default:
		return budget.Reservation{}, errors.New("unknown capacity reservation action")
	}
}

// Reconcile all outstanding operations, including launches finished before a
// restart. Absence never retires a commitment; Observe requires every node and boot ID.
func (r *capacityReservations) reconcile(ctx context.Context, epoch uint64, proof region.VerifiedInfrastructureSpend, snapshot capacityinventory.Snapshot) error {
	capacity, _, err := budget.ReadCapacity(ctx, r.global.reader)
	if err != nil {
		return err
	}
	var pending []error
	for _, receipt := range capacity.Reservations {
		if !receipt.RetiredAt.IsZero() {
			continue
		}
		ids := []string{}
		for _, resource := range snapshot.Resources {
			if resource.OperationID == receipt.OperationID && resource.RecipeSHA256 == receipt.RecipeSHA256 &&
				resource.Cell == receipt.Cell && resource.CompartmentID == receipt.CompartmentID {
				ids = append(ids, resource.ID)
			}
		}
		if err := r.global.authority.Guard(ctx, epoch); err != nil {
			return err
		}
		if _, err := budget.Observe(ctx, r.global.reader, r.global.writer, epoch, receipt.OperationID, ids, proof, snapshot, time.Now()); err != nil {
			pending = append(pending, fmt.Errorf("operation %s: %w", receipt.OperationID, err))
		}
	}
	return errors.Join(pending...)
}

func (r *capacityReservations) verifyCandidate(ctx context.Context, reader *capacityinventory.Reader, proof region.VerifiedInfrastructureSpend,
	snapshot capacityinventory.Snapshot, request capacityReservationRequest,
) (capacityinventory.Quote, error) {
	var quote capacityinventory.Quote
	recipe := request.Recipe
	if r.specs == nil {
		return quote, fmt.Errorf("%w: current image trust or retained host evidence reader is unavailable", nodescale.ErrCapacityPending)
	}
	var regional capacityinventory.RegionScope
	for _, candidate := range proof.Footprint().Regions {
		if candidate.Cell == request.Request.Cell && strings.EqualFold(candidate.Cell, recipe.Cell) && slices.Contains(candidate.CompartmentIDs, request.Request.CompartmentID) {
			regional = candidate
		}
	}
	if regional.OCIRegion == "" {
		return quote, errors.New("capacity source compartment is outside the signed footprint")
	}
	worker, err := r.authorizeWorker(ctx, recipe, request.Request.CompartmentID)
	if err != nil {
		return quote, err
	}
	if err := sameWorkerSpendingGrant(worker, proof); err != nil {
		return quote, err
	}
	location, err := instancePrincipalChannel(regional.OCIRegion, strings.ToUpper(recipe.Cell)).get(ctx)
	if err != nil {
		return quote, err
	}
	openEvidence := func(ctx context.Context, digest string) (io.ReadCloser, error) {
		return releasechannel.OpenImageProductionEvidence(ctx, location, digest)
	}
	qualification := request.Image
	qualification.Role = recipe.Capacity.Role
	qualification.Expected = release.ImageExpectation{Environment: r.environment, LogicalRegion: strings.ToUpper(recipe.Cell),
		OCIImageOCID: recipe.ImageID, Architecture: recipe.Capacity.Architecture}
	image, expires, err := nodescale.QualifyImage(ctx, qualification, r.specs.hostImageSnapshot().roots, openEvidence, time.Now())
	if err != nil {
		return quote, err
	}
	if deadline := worker.Profile().ExpiresAt(); deadline.Before(expires) {
		expires = deadline
	}
	quote, err = reader.Quote(ctx, proof.Footprint(), request.Request.Cell, request.Request.CompartmentID, recipe.Capacity.Shape,
		float64(recipe.OCPUs), float64(recipe.MemoryGB), nodescale.BootVolumeGB)
	if err != nil {
		return quote, err
	}
	if request.Request.MonthlyCents != quote.MonthlyCents() || request.Request.Shape != recipe.Capacity.Shape ||
		request.Request.OCPUs != float64(recipe.OCPUs) || request.Request.MemoryGB != float64(recipe.MemoryGB) || request.Request.BootGB != nodescale.BootVolumeGB {
		return quote, errors.New("capacity request differs from the home's independent exact-geometry quote")
	}
	headroom, err := budget.InfrastructureHeadroom(ctx, r.global.reader, proof, snapshot, request.Request.OperationID, time.Now())
	if err != nil {
		return quote, err
	}
	factory, err := instancePrincipal(ctx, regional.OCIRegion)
	if err != nil {
		return quote, err
	}
	compute, err := factory.Compute()
	if err != nil {
		return quote, err
	}
	quotas, err := factory.Limits()
	if err != nil {
		return quote, err
	}
	if quote.ExpiresAt().Before(expires) {
		expires = quote.ExpiresAt()
	}
	if request.Request.FactsExpireAt.After(expires) {
		return quote, errors.New("capacity request outlives independently verified image or price facts")
	}
	selection, err := nodescale.DiscoverCapacity(ctx, compute, quotas, nodescale.CapacityRequest{
		TenancyID: proof.Footprint().TenancyID, CompartmentID: request.Request.CompartmentID, AvailabilityDomains: recipe.AvailabilityDomains,
		Role: recipe.Capacity.Role, Architectures: []string{recipe.Capacity.Architecture}, OCPUs: recipe.OCPUs, MemoryGB: recipe.MemoryGB,
		BootGB: nodescale.BootVolumeGB, Images: []nodescale.QualifiedImage{image}, Prices: quote.Prices(), MonthlyHeadroomCents: new(headroom), FactsExpireAt: expires})
	if err != nil {
		return quote, err
	}
	for _, domain := range recipe.AvailabilityDomains {
		if !slices.ContainsFunc(selection.Candidates, func(candidate nodescale.CapacityCandidate) bool {
			return candidate.Capacity == recipe.Capacity && candidate.ImageID == recipe.ImageID && candidate.AvailabilityDomain == domain &&
				candidate.MonthlyCents == quote.MonthlyCents()
		}) {
			return quote, fmt.Errorf("%w: exact candidate lacks current compatibility, quota, host capacity or spending headroom: %s", nodescale.ErrCapacityPending, strings.Join(selection.Pending, "; "))
		}
	}
	return quote, nil
}

// request uses the dedicated protected reply namespace. Ordinary cross-region
// inboxes are publishable by legacy links and cannot authenticate authority.
func (r *capacityReservations) request(ctx context.Context, action string, request capacityReservationRequest) (budget.Reservation, error) {
	response, err := r.exchange(ctx, action, request)
	if err != nil {
		return budget.Reservation{}, err
	}
	if response.Pool != nil || response.Receipt == nil || response.Receipt.OperationID != request.Request.OperationID || response.Receipt.RecipeSHA256 != request.Recipe.SHA256() {
		return budget.Reservation{}, fmt.Errorf("%w: home response differs from the original capacity reservation", nodescale.ErrCapacityPending)
	}
	return *response.Receipt, nil
}

func (r *capacityReservations) exchange(ctx context.Context, action string, request capacityReservationRequest) (capacityReservationResponse, error) {
	if r == nil || r.conn == nil {
		return capacityReservationResponse{}, fmt.Errorf("%w: home capacity authority is unavailable", nodescale.ErrCapacityPending)
	}
	if r.homeKey == nil {
		return capacityReservationResponse{}, fmt.Errorf("%w: independently verified current home response key is unavailable", nodescale.ErrCapacityPending)
	}
	public, err := r.homeKey(ctx)
	if err != nil || len(public) != ed25519.PublicKeySize {
		return capacityReservationResponse{}, fmt.Errorf("%w: current home response authority is unavailable: %v", nodescale.ErrCapacityPending, err)
	}
	request.Nonce = entityid.New()
	reply := protocol.CapacityReservationReplySubject(r.cell, r.user, request.Nonce)
	if reply == "" {
		return capacityReservationResponse{}, errors.New("capacity reply identity is invalid")
	}
	ctx, cancel := context.WithTimeout(ctx, 100*time.Second)
	defer cancel()
	subscription, err := r.conn.SubscribeSync(reply)
	if err != nil {
		return capacityReservationResponse{}, err
	}
	defer subscription.Unsubscribe()
	if err := r.conn.FlushWithContext(ctx); err != nil {
		return capacityReservationResponse{}, err
	}
	wire, err := protocol.EncodeJSON(request)
	if err != nil {
		return capacityReservationResponse{}, err
	}
	if err := r.conn.PublishRequest(protocol.CapacityReservationSubject(r.cell, action), reply, wire); err != nil {
		return capacityReservationResponse{}, err
	}
	message, err := subscription.NextMsgWithContext(ctx)
	if err != nil {
		return capacityReservationResponse{}, err
	}
	var envelope protocol.Envelope
	if err := protocol.DecodeStrict(message.Data, &envelope, 128<<10); err != nil {
		return capacityReservationResponse{}, err
	}
	currentPublic, err := r.homeKey(ctx)
	if err != nil {
		return capacityReservationResponse{}, fmt.Errorf("%w: current home response authority: %v", nodescale.ErrCapacityPending, err)
	}
	if !slices.Equal(public, currentPublic) {
		return capacityReservationResponse{}, errors.New("home response authority changed during the original request")
	}
	if envelope.Epoch == 0 {
		return capacityReservationResponse{}, errors.New("capacity response lacks home authority epoch")
	}
	if err := protocol.VerifyEnvelope(envelope, protocol.EnvelopeScope{Region: r.cell, Kind: "capacity." + action + ".response",
		Actor: "capacity-home", OperationID: request.Nonce, Epoch: envelope.Epoch}, public, time.Now().UTC(),
		protocol.VerifyPolicy{MaxLifetime: 30 * time.Second}); err != nil {
		return capacityReservationResponse{}, fmt.Errorf("verify current home capacity response: %w", err)
	}
	var response capacityReservationResponse
	if err := protocol.DecodeStrict(envelope.Payload, &response, 112<<10); err != nil {
		return capacityReservationResponse{}, err
	}
	if response.Nonce != request.Nonce || response.Error != "" {
		return capacityReservationResponse{}, fmt.Errorf("%w: home capacity reservation: %s", nodescale.ErrCapacityPending, response.Error)
	}
	return response, nil
}

package swarmruntime

import (
	"context"
	"errors"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrapstart"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostboot"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
	"github.com/TerraScale/ts-orchestrator/internal/rootoci"
)

// One operation retains the original root session, even across Vault and IAM retries.
type workerOperation struct {
	authority     *workerAuthority
	requestSHA256 string
	poolRequest   rootoci.PoolChildObservation
	client        *rootoci.Client
	pool          rootoci.VerifiedPoolChild
}

func (authority *workerAuthority) begin(ctx context.Context, query WorkerRegistrationQuery) (*workerOperation, error) {
	if authority == nil {
		return nil, errors.New("worker admission source unavailable")
	}
	request, descriptor, err := hostenroll.ParseRetainedWorkerRequest(query.Request, time.Now().UTC())
	if err != nil {
		return nil, err
	}
	operation := &workerOperation{authority: authority, requestSHA256: hostenroll.RequestSHA256(query.Request)}
	if descriptor.IsStatic() {
		operation.poolRequest = rootoci.PoolChildObservation{Cell: descriptor.Region, InstanceID: request.InstanceID}
	}
	return operation, nil
}

func (operation *workerOperation) verifyPoolChild(ctx context.Context) error {
	if operation.client != nil {
		return nil
	}
	if operation.authority.root == nil || operation.poolRequest.InstanceID == "" {
		return ErrWorkerCreationLineagePending
	}
	client, err := operation.authority.root.RootClient(ctx)
	if err != nil {
		return err
	}
	proof, err := client.VerifyPoolChild(ctx, operation.poolRequest)
	if err != nil {
		_ = client.Close()
		return err
	}
	operation.client, operation.pool = client, proof
	return nil
}

func (operation *workerOperation) close() {
	if operation != nil && operation.client != nil {
		_ = operation.client.Close()
	}
}

func (operation *workerOperation) expiresAt(bound time.Time) time.Time {
	if operation.client != nil {
		view := operation.pool.View()
		return minTime(bound, minTime(view.ExpiresAt, view.OriginalDeadline))
	}
	return bound
}

func (operation *workerOperation) boundedContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if operation.client == nil {
		return ctx, func() {}
	}
	view := operation.pool.View()
	return context.WithDeadline(ctx, minTime(view.ExpiresAt, view.OriginalDeadline))
}

func (operation *workerOperation) revalidate(ctx context.Context) error {
	if operation == nil || operation.authority == nil {
		return errors.New("worker admission source unavailable")
	}
	if err := operation.authority.refresh(ctx); err != nil {
		return err
	}
	if operation.client != nil {
		if err := operation.pool.Revalidate(ctx); err != nil {
			return err
		}
		view := operation.pool.View()
		return ociclient.LimitAdmission(ctx, minTime(view.ExpiresAt, view.OriginalDeadline))
	}
	return nil
}

type workerControlClient struct {
	api.ControlClient
	operation *workerOperation
}

func (client workerControlClient) UpdateNode(ctx context.Context, request *api.UpdateNodeRequest, options ...grpc.CallOption) (*api.UpdateNodeResponse, error) {
	ctx, cancel := client.operation.boundedContext(ctx)
	defer cancel()
	if err := client.operation.revalidate(ctx); err != nil {
		return nil, err
	}
	response, err := client.ControlClient.UpdateNode(ctx, request, options...)
	if err != nil {
		return nil, err
	}
	if err := client.operation.revalidate(ctx); err != nil {
		return nil, err
	}
	return response, nil
}

func (operation *workerOperation) requireBindings(ctx context.Context, descriptor hostboot.Descriptor, instanceID string, registration host.Registration) error {
	if !descriptor.IsStatic() {
		return requireWorkerManagedBindings(descriptor, instanceID, registration)
	}
	if err := operation.verifyPoolChild(ctx); err != nil {
		return err
	}
	if !operation.pool.IsVerified() {
		return ErrWorkerCreationLineagePending
	}
	view := operation.pool.View()
	wire, err := descriptor.CanonicalBytes()
	if err != nil || view.Descriptor != string(wire) || view.Cell != descriptor.Region || view.Node != descriptor.Node ||
		view.InstanceID != instanceID {
		return errors.New("worker differs from its original root pool creation")
	}
	// Root creation evidence must also authenticate the registration's managed bindings.
	return ErrWorkerCreationLineagePending
}

func (operation *workerOperation) requireObservation(ctx context.Context, descriptor hostboot.Descriptor, observed bootstrapstart.InstanceObservation, role, architecture string) error {
	if descriptor.IsStatic() {
		view := operation.pool.View()
		if !operation.pool.IsVerified() || view.InstanceID != observed.InstanceOCID || view.PrivateIP != observed.PrimaryPrivateIP ||
			view.CompartmentID != observed.CompartmentOCID || view.ImageID != observed.ImageOCID ||
			view.AvailabilityDomain != observed.AvailabilityDomain || view.FaultDomain != observed.FaultDomain || view.Shape != observed.Shape ||
			view.Role != role || view.Architecture != architecture {
			return errors.New("observed worker differs from its authenticated root pool recipient")
		}
	}
	return operation.revalidate(ctx)
}

func (n *Node) beginWorkerMembership(ctx context.Context, snapshot WorkerMembershipSnapshot) (*workerOperation, error) {
	if snapshot.Admission == nil {
		return nil, errors.New("worker membership lacks retained admission")
	}
	return n.workerAuthority.begin(ctx, WorkerRegistrationQuery{Request: snapshot.Admission.Transport.Request, Response: snapshot.Admission.Transport.Response})
}

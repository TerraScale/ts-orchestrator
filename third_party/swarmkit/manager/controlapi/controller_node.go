package controlapi

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"io"
	"strings"
	"time"

	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/ca"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
)

const (
	ControllerNodeActivate = "activate"
	ControllerNodeRetire   = "retire"
	controllerNodeMetadata = "terrascale-controller-node"
)

// ControllerNodeConstraints only narrow independently reconstructed authority.
// They are not a credential, and contain no callback or authority-bearing DTO.
type ControllerNodeConstraints struct {
	Operation                        string
	LeaseEpoch, RaftTerm, RaftLeader uint64
	TargetSHA256, SourceSHA256       string
}

// ControllerNodeSource must independently authenticate the origin against its
// installed concrete signed sources before invoking an observed native mutation.
type ControllerNodeSource interface {
	UpdateControllerNode(context.Context, string, *api.UpdateNodeRequest) (*api.UpdateNodeResponse, error)
	RemoveControllerNode(context.Context, string, *api.RemoveNodeRequest) (*api.RemoveNodeResponse, error)
}

// WithControllerNodeConstraints retains the original deadline and context while
// carrying finite constraints through the existing native Control RPC only.
func WithControllerNodeConstraints(ctx context.Context, constraints ControllerNodeConstraints) (context.Context, error) {
	if err := validateControllerNodeContext(ctx, constraints); err != nil {
		return nil, err
	}
	incoming, _ := metadata.FromIncomingContext(ctx)
	outgoing, _ := metadata.FromOutgoingContext(ctx)
	if len(incoming.Get(controllerNodeMetadata)) != 0 || len(outgoing.Get(controllerNodeMetadata)) != 0 {
		return nil, status.Error(codes.PermissionDenied, "controller node constraints already present")
	}
	wire, err := json.Marshal(constraints)
	if err != nil {
		return nil, err
	}
	return metadata.AppendToOutgoingContext(ctx, controllerNodeMetadata, string(wire)), nil
}

// ControllerNodeConstraintsFromContext reads narrowing data only. The actual
// authenticated origin is separately derived from the native TLS request.
func ControllerNodeConstraintsFromContext(ctx context.Context) (ControllerNodeConstraints, error) {
	var constraints ControllerNodeConstraints
	if ctx == nil {
		return constraints, status.Error(codes.PermissionDenied, "controller node context missing")
	}
	md, _ := metadata.FromIncomingContext(ctx)
	values := md.Get(controllerNodeMetadata)
	if len(values) != 1 || len(values[0]) > 2048 {
		return constraints, status.Error(codes.PermissionDenied, "controller node constraints missing or duplicated")
	}
	decoder := json.NewDecoder(bytes.NewBufferString(values[0]))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&constraints); err != nil {
		return constraints, status.Error(codes.PermissionDenied, "invalid controller node constraints")
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return constraints, status.Error(codes.PermissionDenied, "invalid controller node constraints suffix")
	}
	canonical, err := json.Marshal(constraints)
	if err != nil || !bytes.Equal(canonical, []byte(values[0])) {
		return constraints, status.Error(codes.PermissionDenied, "controller node constraints must have one canonical encoding")
	}
	return constraints, validateControllerNodeContext(ctx, constraints)
}

func validateControllerNodeContext(ctx context.Context, constraints ControllerNodeConstraints) error {
	if ctx == nil {
		return status.Error(codes.PermissionDenied, "controller node context missing")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	deadline, ok := ctx.Deadline()
	if !ok || !time.Now().Before(deadline) ||
		constraints.Operation != ControllerNodeActivate && constraints.Operation != ControllerNodeRetire ||
		constraints.LeaseEpoch == 0 || constraints.RaftTerm == 0 || constraints.RaftLeader == 0 ||
		!controllerNodeDigest(constraints.TargetSHA256) || !controllerNodeDigest(constraints.SourceSHA256) {
		return status.Error(codes.PermissionDenied, "controller node requires finite original constraints and deadline")
	}
	return nil
}

func controllerNodeDigest(value string) bool {
	digest, err := hex.DecodeString(value)
	return err == nil && len(digest) == 32 && value == strings.ToLower(value)
}

func controllerNodeTagged(ctx context.Context) bool {
	md, _ := metadata.FromIncomingContext(ctx)
	_, exists := md[controllerNodeMetadata]
	return exists
}

func controllerNodeOrigin(ctx context.Context) (string, error) {
	info, err := ca.RemoteNode(ctx)
	if err != nil {
		return "", err
	}
	for _, role := range info.Roles {
		if role == ca.ManagerRole && info.NodeID != "" && info.Organization != "" {
			return info.NodeID, nil
		}
	}
	return "", status.Error(codes.PermissionDenied, "controller node origin must be an authenticated manager")
}

func controllerNodeManaged(node *api.Node) bool {
	return node.Role == api.NodeRoleManager || node.Spec.DesiredRole == api.NodeRoleManager ||
		node.Spec.Annotations.Labels["terrascale.host-role"] == "manager" || node.Spec.Annotations.Labels["terrascale.manager-retirement"] != ""
}

func controllerNodeUnobservedUpdate(node *api.Node, spec *api.NodeSpec) bool {
	if node.Spec.DesiredRole != spec.DesiredRole && (node.Spec.DesiredRole == api.NodeRoleManager || spec.DesiredRole == api.NodeRoleManager) {
		return true
	}
	if !controllerNodeManaged(node) {
		return false
	}
	// Initial admission may attach labels while preserving the native initial
	// availability; already admitted controller identity remains immutable.
	if node.Spec.Annotations.Labels["terrascale.instance-id"] != "" && !proto.Equal(&node.Spec.Annotations, &spec.Annotations) {
		return true
	}
	return spec.Availability == api.NodeAvailabilityActive &&
		(node.Spec.Availability != api.NodeAvailabilityActive || node.Spec.Annotations.Labels["terrascale.instance-id"] != "")
}

func (s *Server) dispatchControllerNodeUpdate(ctx context.Context, request *api.UpdateNodeRequest) (*api.UpdateNodeResponse, error) {
	constraints, err := ControllerNodeConstraintsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if s.ControllerNodeSource == nil || request.Spec == nil ||
		constraints.Operation == ControllerNodeActivate && request.Spec.Availability != api.NodeAvailabilityActive ||
		constraints.Operation == ControllerNodeRetire && (request.Spec.Availability != api.NodeAvailabilityPause || request.Spec.DesiredRole != api.NodeRoleWorker) {
		return nil, status.Error(codes.PermissionDenied, "controller node update requires installed matching source")
	}
	origin, err := controllerNodeOrigin(ctx)
	if err != nil {
		return nil, err
	}
	return s.ControllerNodeSource.UpdateControllerNode(ctx, origin, request.Copy())
}

func (s *Server) dispatchControllerNodeRemoval(ctx context.Context, request *api.RemoveNodeRequest) (*api.RemoveNodeResponse, error) {
	constraints, err := ControllerNodeConstraintsFromContext(ctx)
	if err != nil {
		return nil, err
	}
	if s.ControllerNodeSource == nil || constraints.Operation != ControllerNodeRetire || request.Force {
		return nil, status.Error(codes.PermissionDenied, "controller node removal requires installed retirement source and Force=false")
	}
	origin, err := controllerNodeOrigin(ctx)
	if err != nil {
		return nil, err
	}
	return s.ControllerNodeSource.RemoveControllerNode(ctx, origin, request.Copy())
}

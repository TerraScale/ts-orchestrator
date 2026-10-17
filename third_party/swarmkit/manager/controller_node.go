package manager

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"sync"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager/controlapi"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type ControllerNodeConstraints = controlapi.ControllerNodeConstraints
type ControllerNodeSource = controlapi.ControllerNodeSource

const (
	ControllerNodeActivate = controlapi.ControllerNodeActivate
	ControllerNodeRetire   = controlapi.ControllerNodeRetire
)

func WithControllerNodeConstraints(ctx context.Context, constraints ControllerNodeConstraints) (context.Context, error) {
	return controlapi.WithControllerNodeConstraints(ctx, constraints)
}

func ControllerNodeConstraintsFromContext(ctx context.Context) (ControllerNodeConstraints, error) {
	return controlapi.ControllerNodeConstraintsFromContext(ctx)
}

// ControllerNodeTargetSHA256 hashes the complete captured store row. Callers
// must not supply GetNode responses augmented with live ManagerStatus fields.
func ControllerNodeTargetSHA256(node *api.Node) (string, error) {
	if node == nil || node.ID == "" {
		return "", errors.New("controller node target missing")
	}
	wire, err := json.Marshal(node)
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256(wire)
	return hex.EncodeToString(digest[:]), nil
}

type controllerNodeSource struct {
	mu     sync.RWMutex
	source ControllerNodeSource
}

// InstallControllerNodeSource binds the actual running Control API to one
// concrete authority source. The holder is shared even when Run started first.
func (m *Manager) InstallControllerNodeSource(source ControllerNodeSource) error {
	if m == nil || source == nil {
		return errors.New("controller node source required")
	}
	m.controllerNodeSource.mu.Lock()
	defer m.controllerNodeSource.mu.Unlock()
	if m.controllerNodeSource.source != nil {
		return errors.New("controller node source already installed")
	}
	m.controllerNodeSource.source = source
	return nil
}

func (holder *controllerNodeSource) current() (ControllerNodeSource, error) {
	holder.mu.RLock()
	defer holder.mu.RUnlock()
	if holder.source == nil {
		return nil, status.Error(codes.PermissionDenied, "controller node signed source unavailable")
	}
	return holder.source, nil
}

func (holder *controllerNodeSource) UpdateControllerNode(ctx context.Context, origin string, request *api.UpdateNodeRequest) (*api.UpdateNodeResponse, error) {
	source, err := holder.current()
	if err != nil {
		return nil, err
	}
	return source.UpdateControllerNode(ctx, origin, request)
}

func (holder *controllerNodeSource) RemoveControllerNode(ctx context.Context, origin string, request *api.RemoveNodeRequest) (*api.RemoveNodeResponse, error) {
	source, err := holder.current()
	if err != nil {
		return nil, err
	}
	return source.RemoveControllerNode(ctx, origin, request)
}

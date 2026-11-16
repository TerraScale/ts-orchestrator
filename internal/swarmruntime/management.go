//go:build linux

package swarmruntime

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/autoscale"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/gogo/protobuf/proto"
	"github.com/moby/swarmkit/v2/api"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// StatefulServiceAuthorizer derives the exact current signed service in root.
// The unprivileged socket caller cannot supply its readers or a cached seal.
// The callback runs synchronously once and must not be retained.
type StatefulServiceAuthorizer interface {
	WithStatefulService(context.Context, *api.ServiceSpec, func(context.Context) error) error
}

type managementServer struct {
	api.UnimplementedControlServer
	client              api.ControlClient
	region, environment string
	stateful            StatefulServiceAuthorizer
}

func (s *managementServer) scoped(a api.Annotations) bool {
	return a.Labels[LabelRegion] == s.region && a.Labels[LabelEnvironment] == s.environment && entityid.Valid(a.Labels[LabelIntentID]) && intentName.MatchString(a.Labels[LabelRole])
}
func (s *managementServer) floor(spec *api.ConfigSpec) bool {
	if spec == nil || spec.Templating != nil || !s.scoped(spec.Annotations) || !validIntentLabels(spec.Annotations.Labels) {
		return false
	}
	sequence, err := strconv.ParseUint(spec.Annotations.Labels["terrascale.release-sequence"], 10, 64)
	if err != nil || sequence == 0 {
		return false
	}
	labels := spec.Annotations.Labels
	if strings.HasPrefix(spec.Annotations.Name, "ts-worker-family-") {
		migration := labels[labelReleaseMigration]
		digest, err := hex.DecodeString(migration)
		if labels[LabelRole] != "function-worker" || err != nil || len(digest) != sha256.Size || migration != strings.ToLower(migration) {
			return false
		}
		identity := sha256.Sum256([]byte(fmt.Sprintf("%s/%s/%s/%d", migration, labels[LabelRole], s.environment, sequence)))
		return spec.Annotations.Name == fmt.Sprintf("ts-worker-family-%x", identity[:16])
	}
	scope := s.environment + "/" + s.region + "/" + labels[LabelRole]
	if architecture := labels[labelReleaseArchitecture]; architecture != "" {
		if labels[LabelRole] != "function-worker" || architecture != "arm64" && architecture != "amd64" {
			return false
		}
		scope += "/" + architecture
	}
	identity := sha256.Sum256([]byte(scope))
	return spec.Annotations.Name == fmt.Sprintf("ts-release-%x", identity[:16])
}
func denied() error {
	return status.Error(codes.PermissionDenied, "management operation outside admitted scope")
}

func validIntentLabels(labels map[string]string) bool {
	stored, hasGeneration := labels[LabelIntentGeneration]
	fingerprint, hasFingerprint := labels[labelIntentFingerprint]
	if !hasGeneration && !hasFingerprint {
		return true
	}
	generation, err := strconv.ParseUint(stored, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != stored {
		return false
	}
	digest, err := hex.DecodeString(fingerprint)
	return err == nil && len(digest) == sha256.Size && fingerprint == strings.ToLower(fingerprint)
}

func retainsIntentGeneration(before, after map[string]string) bool {
	if !validIntentLabels(before) || !validIntentLabels(after) {
		return false
	}
	generation, _ := strconv.ParseUint(after[LabelIntentGeneration], 10, 64)
	return checkIntentGeneration(before, ServiceIntent{Generation: generation, intentFingerprint: after[labelIntentFingerprint]}) == nil
}

func (s *managementServer) GetNode(ctx context.Context, req *api.GetNodeRequest) (*api.GetNodeResponse, error) {
	return s.client.GetNode(ctx, req)
}
func (s *managementServer) ListNodes(ctx context.Context, req *api.ListNodesRequest) (*api.ListNodesResponse, error) {
	return s.client.ListNodes(ctx, req)
}
func (s *managementServer) UpdateNode(ctx context.Context, req *api.UpdateNodeRequest) (*api.UpdateNodeResponse, error) {
	if req.Spec == nil || req.Spec.Availability != api.NodeAvailabilityPause {
		return nil, denied()
	}
	current, err := s.client.GetNode(ctx, &api.GetNodeRequest{NodeID: req.NodeID})
	if err != nil {
		return nil, err
	}
	if req.Spec.DesiredRole != current.Node.Spec.DesiredRole || req.Spec.Membership != current.Node.Spec.Membership {
		return nil, denied()
	}
	labels := current.Node.Spec.Annotations.Labels
	if labels[LabelRegion] != s.region || labels[LabelInstanceID] == "" || !proto.Equal(&current.Node.Spec.Annotations, &req.Spec.Annotations) {
		return nil, denied()
	}
	return s.client.UpdateNode(ctx, req)
}
func (s *managementServer) GetTask(ctx context.Context, req *api.GetTaskRequest) (*api.GetTaskResponse, error) {
	return s.client.GetTask(ctx, req)
}
func (s *managementServer) ListTasks(ctx context.Context, req *api.ListTasksRequest) (*api.ListTasksResponse, error) {
	return s.client.ListTasks(ctx, req)
}
func (s *managementServer) GetService(ctx context.Context, req *api.GetServiceRequest) (*api.GetServiceResponse, error) {
	result, err := s.client.GetService(ctx, req)
	if err == nil && !s.scoped(result.Service.Spec.Annotations) {
		return nil, denied()
	}
	return result, err
}
func (s *managementServer) ListServices(ctx context.Context, req *api.ListServicesRequest) (*api.ListServicesResponse, error) {
	result, err := s.client.ListServices(ctx, req)
	if err != nil {
		return nil, err
	}
	visible := result.Services[:0]
	for _, service := range result.Services {
		if s.scoped(service.Spec.Annotations) {
			visible = append(visible, service)
		}
	}
	result.Services = visible
	return result, nil
}
func (s *managementServer) managedService(spec *api.ServiceSpec) bool {
	if spec == nil || !s.scoped(spec.Annotations) || !validIntentLabels(spec.Annotations.Labels) || spec.GetReplicated() == nil || spec.GetReplicated().Replicas > autoscale.MaxReplicas || len(spec.Networks) != 0 {
		return false
	}
	placement := spec.Task.Placement
	if placement == nil || len(placement.Platforms) != 1 || placement.Platforms[0] == nil || placement.Platforms[0].OS != "linux" || (placement.Platforms[0].Architecture != "arm64" && placement.Platforms[0].Architecture != "amd64") {
		return false
	}
	constraints := []string{"node.labels." + LabelRegion + "==" + s.region, "node.labels." + LabelExecutionScope + "==platform"}
	if spec.Annotations.Labels[LabelRole] == "function-worker" {
		constraints[1] = "node.labels." + LabelExecutionScope + "==tenant"
		constraints = append(constraints, "node.labels."+LabelHostRole+"==wasm")
	}
	if spec.Annotations.Labels[LabelRole] == "ts-auth" {
		constraints = append(constraints, "node.role==manager")
		if placement.MaxReplicas != 1 || spec.GetReplicated().Replicas > 3 {
			return false
		}
	}
	if !slices.Equal(placement.Constraints, constraints) {
		return false
	}
	if spec.Endpoint != nil && (spec.Endpoint.Mode != api.ResolutionModeDNSRoundRobin || len(spec.Endpoint.Ports) > 1) {
		return false
	}
	_, err := DecodeContainer(&api.Task{ID: "validation", ServiceID: "validation", Spec: spec.Task, ServiceAnnotations: spec.Annotations, Endpoint: &api.Endpoint{Spec: spec.Endpoint}})
	return err == nil
}

func (s *managementServer) CreateService(ctx context.Context, req *api.CreateServiceRequest) (*api.CreateServiceResponse, error) {
	if s.managedService(req.Spec) {
		return s.client.CreateService(ctx, req)
	}
	var result *api.CreateServiceResponse
	err := s.withStatefulService(ctx, req.Spec, func(effectCtx context.Context) error {
		var err error
		result, err = s.client.CreateService(effectCtx, req)
		return err
	})
	if err == nil && result == nil {
		return nil, denied()
	}
	return result, err
}
func (s *managementServer) UpdateService(ctx context.Context, req *api.UpdateServiceRequest) (*api.UpdateServiceResponse, error) {
	stateful := statefulService(req.Spec)
	if !s.managedService(req.Spec) && !stateful {
		return nil, denied()
	}
	current, err := s.GetService(ctx, &api.GetServiceRequest{ServiceID: req.ServiceID})
	if err != nil {
		return nil, err
	}
	if stateful != statefulService(&current.Service.Spec) {
		return nil, denied()
	}
	if stateful {
		if req.Rollback != api.UpdateServiceRequest_NONE || req.Spec.Annotations.Name != current.Service.Spec.Annotations.Name {
			return nil, denied()
		}
		for _, key := range []string{"terrascale.database-id", "terrascale.partition-id", "terrascale.member-id"} {
			if req.Spec.Annotations.Labels[key] != current.Service.Spec.Annotations.Labels[key] {
				return nil, denied()
			}
		}
	}
	effective := req.Spec
	switch req.Rollback {
	case api.UpdateServiceRequest_NONE:
		if !retainsIntentGeneration(current.Service.Spec.Annotations.Labels, effective.Annotations.Labels) {
			return nil, denied()
		}
	case api.UpdateServiceRequest_PREVIOUS:
		effective = current.Service.PreviousSpec
	default:
		return nil, denied()
	}
	if !stateful && !s.managedService(effective) {
		return nil, denied()
	}
	for _, key := range []string{LabelIntentID, LabelRole, LabelRegion, LabelEnvironment} {
		if current.Service.Spec.Annotations.Labels[key] != effective.Annotations.Labels[key] {
			return nil, denied()
		}
	}
	if stateful {
		var result *api.UpdateServiceResponse
		err := s.withStatefulService(ctx, effective, func(effectCtx context.Context) error {
			var err error
			result, err = s.client.UpdateService(effectCtx, req)
			return err
		})
		if err == nil && result == nil {
			return nil, denied()
		}
		return result, err
	}
	return s.client.UpdateService(ctx, req)
}

func statefulService(spec *api.ServiceSpec) bool {
	return spec != nil && spec.Annotations.Labels[LabelRole] == "terrabase" && spec.Annotations.Labels["terrascale.stateful"] == "true"
}

func (s *managementServer) withStatefulService(ctx context.Context, spec *api.ServiceSpec, effect func(context.Context) error) error {
	if !statefulService(spec) || !s.scoped(spec.Annotations) || !validIntentLabels(spec.Annotations.Labels) || s.stateful == nil {
		return denied()
	}
	called := false
	invalid := false
	var effectErr error
	err := s.stateful.WithStatefulService(ctx, spec, func(effectCtx context.Context) error {
		if called {
			invalid = true
			return denied()
		}
		called = true
		if effectCtx == nil || effectCtx.Err() != nil {
			invalid = true
			return denied()
		}
		effectErr = effect(effectCtx)
		return effectErr
	})
	if !called || invalid {
		return denied()
	}
	if effectErr != nil {
		return effectErr
	}
	return err
}
func (s *managementServer) RemoveService(ctx context.Context, req *api.RemoveServiceRequest) (*api.RemoveServiceResponse, error) {
	current, err := s.GetService(ctx, &api.GetServiceRequest{ServiceID: req.ServiceID})
	if err != nil {
		return nil, err
	}
	if !s.managedService(&current.Service.Spec) {
		return nil, denied()
	}
	return s.client.RemoveService(ctx, req)
}
func (s *managementServer) GetConfig(ctx context.Context, req *api.GetConfigRequest) (*api.GetConfigResponse, error) {
	result, err := s.client.GetConfig(ctx, req)
	if err == nil && !s.floor(&result.Config.Spec) {
		return nil, denied()
	}
	return result, err
}
func (s *managementServer) ListConfigs(ctx context.Context, req *api.ListConfigsRequest) (*api.ListConfigsResponse, error) {
	result, err := s.client.ListConfigs(ctx, req)
	if err != nil {
		return nil, err
	}
	visible := result.Configs[:0]
	for _, config := range result.Configs {
		if s.floor(&config.Spec) {
			visible = append(visible, config)
		}
	}
	result.Configs = visible
	return result, nil
}
func (s *managementServer) CreateConfig(ctx context.Context, req *api.CreateConfigRequest) (*api.CreateConfigResponse, error) {
	if !s.floor(req.Spec) {
		return nil, denied()
	}
	return s.client.CreateConfig(ctx, req)
}
func (s *managementServer) UpdateConfig(ctx context.Context, req *api.UpdateConfigRequest) (*api.UpdateConfigResponse, error) {
	if !s.floor(req.Spec) || strings.HasPrefix(req.Spec.Annotations.Name, "ts-worker-family-") {
		return nil, denied()
	}
	current, err := s.GetConfig(ctx, &api.GetConfigRequest{ConfigID: req.ConfigID})
	if err != nil {
		return nil, err
	}
	if current.Config.Spec.Annotations.Name != req.Spec.Annotations.Name || !bytes.Equal(current.Config.Spec.Data, req.Spec.Data) {
		return nil, denied()
	}
	before, after := current.Config.Spec.Annotations.Labels, req.Spec.Annotations.Labels
	if !retainsIntentGeneration(before, after) {
		return nil, denied()
	}
	for key := range after {
		if _, exists := before[key]; !exists && key != LabelIntentGeneration && key != labelIntentFingerprint {
			return nil, denied()
		}
	}
	for key, value := range before {
		if _, exists := after[key]; !exists {
			return nil, denied()
		}
		switch key {
		case "terrascale.release-sequence", "terrascale.release-fingerprint", "terrascale.release-baseline", LabelIntentGeneration, labelIntentFingerprint:
		default:
			if after[key] != value {
				return nil, denied()
			}
		}
	}
	previous, err := strconv.ParseUint(before["terrascale.release-sequence"], 10, 64)
	if err != nil || previous == 0 {
		return nil, denied()
	}
	next, err := strconv.ParseUint(after["terrascale.release-sequence"], 10, 64)
	if err != nil || next < previous || next == previous && after["terrascale.release-fingerprint"] != before["terrascale.release-fingerprint"] {
		return nil, denied()
	}
	return s.client.UpdateConfig(ctx, req)
}

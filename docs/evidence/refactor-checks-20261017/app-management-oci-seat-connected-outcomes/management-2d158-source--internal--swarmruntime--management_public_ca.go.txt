//go:build linux

package swarmruntime

import (
	"context"
	"slices"

	"github.com/moby/swarmkit/v2/api"
)

// ListClusters exposes only current public trust material needed to verify a
// root worker's stopped proof. Constructing a fresh value excludes every secret.
func (s *managementServer) ListClusters(ctx context.Context, request *api.ListClustersRequest) (*api.ListClustersResponse, error) {
	if request == nil || request.Filters != nil {
		return nil, denied()
	}
	response, err := s.client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil {
		return nil, err
	}
	if response == nil || len(response.Clusters) != 1 || response.Clusters[0] == nil || response.Clusters[0].ID == "" ||
		len(response.Clusters[0].RootCA.CACert) == 0 || len(response.Clusters[0].RootCA.CACert) > 64<<10 {
		return nil, denied()
	}
	cluster := response.Clusters[0]
	return &api.ListClustersResponse{Clusters: []*api.Cluster{{ID: cluster.ID, RootCA: api.RootCA{CACert: slices.Clone(cluster.RootCA.CACert)}}}}, nil
}

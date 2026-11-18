package regionjoin

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/ca"
	"github.com/moby/swarmkit/v2/connectionbroker"
	"github.com/moby/swarmkit/v2/remotes"
)

func ClusterMaterial(ctx context.Context, client api.ControlClient, founder string) (Material, error) {
	listed, err := client.ListNodes(ctx, &api.ListNodesRequest{})
	if err != nil {
		return Material{}, err
	}
	return ClusterMaterialOf(ctx, client, listed.Nodes, founder)
}

func ClusterMaterialOf(ctx context.Context, client api.ControlClient, nodes []*api.Node, founder string) (Material, error) {
	names := make([]string, 0, len(nodes))
	leader := ""
	for _, node := range nodes {
		if node.Description != nil {
			names = append(names, node.Description.Hostname)
			if node.Status.State == api.NodeStatus_READY && node.Role == api.NodeRoleManager && node.ManagerStatus != nil && node.ManagerStatus.Leader {
				leader = node.Description.Hostname
			}
		}
	}
	slices.Sort(names)
	if !slices.Contains(names, founder) {
		if leader == "" {
			return Material{}, errors.New("join material requires a current cluster leader")
		}
		founder = leader
	}
	clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
	if err != nil || len(clusters.Clusters) != 1 {
		return Material{}, errors.Join(errors.New("read the cluster's worker join token"), err)
	}
	return Material{Founder: founder, WorkerToken: clusters.Clusters[0].RootCA.JoinTokens.Worker, Nodes: names}, nil
}

func NamesStored(material Material, stateDir string, stored swarmruntime.Admission) (bool, error) {
	if material.WorkerToken == "" {
		return stored.HostID == stored.FounderID && material.Founder == stored.HostID && material.FounderInstance == stored.InstanceID, nil
	}
	parsed, err := ca.ParseJoinToken(material.WorkerToken)
	if err != nil {
		return false, fmt.Errorf("join material worker token: %w", err)
	}
	root, err := swarmruntime.ClusterRoot(stateDir)
	return err == nil && parsed.RootDigest == root, err
}

func ReachableManager(ctx context.Context, material Material) (string, bool) {
	if material.Founder == "" || len(material.Nodes) > 0 && !slices.Contains(material.Nodes, material.Founder) {
		return "", false
	}
	parsed, err := ca.ParseJoinToken(material.WorkerToken)
	if err != nil {
		return "", false
	}
	for _, manager := range material.Managers {
		bounded, cancel := context.WithTimeout(ctx, 5*time.Second)
		_, err := ca.GetRemoteCA(bounded, parsed.RootDigest, connectionbroker.New(remotes.NewRemotes(api.Peer{Addr: manager})))
		cancel()
		if err == nil {
			return manager, true
		}
	}
	return "", false
}

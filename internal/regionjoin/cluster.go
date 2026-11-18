package regionjoin

import (
	"context"
	"errors"
	"slices"
	"time"

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
	names := make([]string, 0, len(listed.Nodes))
	leader := ""
	for _, node := range listed.Nodes {
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

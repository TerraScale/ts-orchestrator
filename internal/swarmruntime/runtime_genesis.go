package swarmruntime

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/moby/swarmkit/v2/manager"
	"github.com/moby/swarmkit/v2/manager/state/store"
)

// RuntimeGenesisInfo is public provenance, not permission to initialize a store.
type RuntimeGenesisInfo struct {
	ClusterID, NodeID, RootCASHA256 string
	Region, HostID, InstanceID      string
	StartedAt                       time.Time
	Version, Term, Leader           uint64
}

// VerifiedRuntimeGenesis exists only on the actual first empty-state founder
// process. Root must independently bind it to its preexisting protected permit.
type VerifiedRuntimeGenesis struct {
	node    *Node
	manager *manager.Manager
	info    RuntimeGenesisInfo
	expires time.Time
}

func (proof VerifiedRuntimeGenesis) Info() RuntimeGenesisInfo { return proof.info }
func (proof VerifiedRuntimeGenesis) ExpiresAt() time.Time     { return proof.expires }

func (n *Node) RuntimeGenesis(ctx context.Context) (VerifiedRuntimeGenesis, error) {
	expires := time.Now().UTC().Add(30 * time.Second)
	ctx, cancel := context.WithDeadline(ctx, expires)
	defer cancel()
	info, source, err := n.observeRuntimeGenesis(ctx)
	if err != nil {
		return VerifiedRuntimeGenesis{}, err
	}
	return VerifiedRuntimeGenesis{node: n, manager: source, info: info, expires: expires}, nil
}

// Revalidate retains the original process, manager, leader epoch and deadline.
func (proof VerifiedRuntimeGenesis) Revalidate(ctx context.Context) error {
	if proof.node == nil || proof.manager == nil || !time.Now().Before(proof.expires) {
		return errors.New("original runtime genesis proof is absent or expired")
	}
	ctx, cancel := context.WithDeadline(ctx, proof.expires)
	defer cancel()
	current, source, err := proof.node.observeRuntimeGenesis(ctx)
	if err != nil {
		return err
	}
	original := proof.info
	current.Version = original.Version
	if source != proof.manager || current != original {
		return errors.New("runtime genesis source or leadership changed")
	}
	return nil
}

func (n *Node) observeRuntimeGenesis(ctx context.Context) (RuntimeGenesisInfo, *manager.Manager, error) {
	if err := ctx.Err(); err != nil {
		return RuntimeGenesisInfo{}, nil, err
	}
	if n == nil || n.upstream == nil || !n.createdGenesis || n.genesisStartedAt.IsZero() || n.role != "manager" || n.admission.HostID != n.admission.FounderID {
		return RuntimeGenesisInfo{}, nil, errors.New("runtime is not the original empty-state founder")
	}
	select {
	case <-n.done:
		return RuntimeGenesisInfo{}, nil, errors.New("runtime genesis process stopped")
	default:
	}
	source := n.upstream.Manager()
	if source == nil {
		return RuntimeGenesisInfo{}, nil, errors.New("runtime genesis manager is unavailable")
	}
	info := RuntimeGenesisInfo{NodeID: n.ID(), Region: n.admission.Region, HostID: n.admission.HostID, InstanceID: n.admission.InstanceID, StartedAt: n.genesisStartedAt}
	observed, err := source.Observe(&api.Version{}, func(tx store.ReadTx) error {
		clusters, err := store.FindClusters(tx, store.All)
		if err != nil || len(clusters) != 1 || clusters[0].ID == "" || len(clusters[0].RootCA.CACert) == 0 {
			return errors.New("runtime genesis requires one actual cluster and public CA")
		}
		info.ClusterID = clusters[0].ID
		digest := sha256.Sum256(clusters[0].RootCA.CACert)
		info.RootCASHA256 = hex.EncodeToString(digest[:])
		return nil
	})
	if err != nil {
		return RuntimeGenesisInfo{}, nil, err
	}
	defer observed.Cancel()
	for _, change := range observed.Replay {
		for _, action := range change.StoreActions {
			if action.GetService() != nil || action.GetTask() != nil || action.GetConfig() != nil || action.GetSecret() != nil || action.GetVolume() != nil || action.GetResource() != nil || action.GetExtension() != nil {
				return RuntimeGenesisInfo{}, nil, errors.New("runtime genesis contains prior workload history")
			}
		}
	}
	if err := source.ValidateObservation(observed); err != nil {
		return RuntimeGenesisInfo{}, nil, err
	}
	if err := ctx.Err(); err != nil {
		return RuntimeGenesisInfo{}, nil, err
	}
	if n.upstream.Manager() != source {
		return RuntimeGenesisInfo{}, nil, errors.New("runtime genesis manager was replaced")
	}
	info.Version, info.Term, info.Leader = observed.Version.Index, observed.Term, observed.Leader
	return info, source, nil
}

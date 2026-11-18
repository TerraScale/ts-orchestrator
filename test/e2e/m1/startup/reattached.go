package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

type volumeHost struct {
	name, instance, address string
}

func reattachedVolume(ctx context.Context, state string) error {
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	executor, err := swarmruntime.NewExecutor(swarmruntime.HostContainerdSocket, state)
	if err != nil {
		return err
	}
	defer executor.Close()
	staleFounder := volumeHost{"stale-founder", "stale-founder-instance", "127.0.0.1:4242"}
	staleWorker := volumeHost{"stale-worker", "stale-worker-instance", "127.0.0.1:4243"}
	liveFounder := volumeHost{"live-founder", "live-founder-instance", "127.0.0.1:4244"}
	stale, err := startVolumeHost(ctx, state, executor, staleFounder, swarmruntime.FoundingAdmission(staleFounder.name, staleFounder.instance))
	if err != nil {
		return err
	}
	staleMaterial, err := volumeMaterial(ctx, state, staleFounder)
	if err == nil {
		var worker *swarmruntime.Node
		if worker, err = joinVolumeHost(ctx, state, executor, staleFounder, staleWorker, staleMaterial, 2); err == nil {
			err = stopVolumeHost(ctx, worker)
		}
	}
	if err := errors.Join(err, stopVolumeHost(ctx, stale)); err != nil {
		return err
	}
	newcomer := volumeHost{"newcomer", "newcomer-instance", ""}
	if named, err := regionjoin.NamesStored(staleMaterial, filepath.Join(state, staleFounder.name), swarmruntime.FoundingAdmission(staleFounder.name, staleFounder.instance)); err != nil || !named {
		return errors.Join(errors.New("the stale cluster's own material did not name its founder's state"), err)
	}
	if _, holds, err := storedVolumeAdmission(filepath.Join(state, staleFounder.name), newcomer, staleMaterial); err != nil || holds {
		return errors.Join(errors.New("a new host would resume another host's admission that the join material still names"), err)
	}
	live, err := startVolumeHost(ctx, state, executor, liveFounder, swarmruntime.FoundingAdmission(liveFounder.name, liveFounder.instance))
	if err != nil {
		return err
	}
	defer func() { _ = stopVolumeHost(ctx, live) }()
	material, err := volumeMaterial(ctx, state, liveFounder)
	if err != nil {
		return err
	}
	firstID := live.ID()
	if err := stopVolumeHost(ctx, live); err != nil {
		return err
	}
	stored, holds, err := storedVolumeAdmission(filepath.Join(state, liveFounder.name), liveFounder, material)
	if err != nil || !holds {
		return errors.Join(errors.New("the live founder's own restart did not keep its stored admission"), err)
	}
	if live, err = startVolumeHost(ctx, state, executor, liveFounder, stored); err != nil {
		return err
	}
	resumed, err := volumeMaterial(ctx, state, liveFounder)
	if err != nil {
		return err
	}
	if live.ID() != firstID || resumed.WorkerToken != material.WorkerToken {
		return errors.New("the live founder's restart changed its node or cluster identity")
	}
	claimed := regionjoin.Material{Founder: liveFounder.name}
	if named, err := regionjoin.NamesStored(claimed, filepath.Join(state, liveFounder.name), stored); err != nil || !named {
		return errors.Join(errors.New("a founder claim without a token did not name its claimant"), err)
	}
	replacement := volumeHost{"replacement", "replacement-instance", "127.0.0.1:4245"}
	if err := os.Rename(filepath.Join(state, staleWorker.name), filepath.Join(state, replacement.name)); err != nil {
		return err
	}
	rebuilt := volumeHost{staleFounder.name, staleFounder.instance, "127.0.0.1:4246"}
	for _, host := range []volumeHost{replacement, rebuilt} {
		previous, holds, err := storedVolumeAdmission(filepath.Join(state, host.name), host, material)
		if err != nil {
			return err
		}
		if holds {
			return fmt.Errorf("%s resumed stored admission of %s in a cluster the join material does not name", host.name, previous.HostID)
		}
		aside, err := swarmruntime.SetAsideSwarm(filepath.Join(state, host.name), time.Now())
		if err != nil {
			return err
		}
		if _, err := os.Stat(filepath.Join(aside, "admission.json")); err != nil {
			return fmt.Errorf("set-aside state of %s lost its admission: %w", previous.HostID, err)
		}
	}
	joined, err := joinVolumeHost(ctx, state, executor, liveFounder, replacement, material, 2)
	if err != nil {
		return err
	}
	defer func() { _ = stopVolumeHost(ctx, joined) }()
	rejoined, err := joinVolumeHost(ctx, state, executor, liveFounder, rebuilt, material, 3)
	if err != nil {
		return err
	}
	if err := stopVolumeHost(ctx, rejoined); err != nil {
		return err
	}
	fmt.Println("reattached volume: another host's state is refused even while the join material names its cluster; another host's state and a stale cluster's state are set aside and join the live cluster; the same host's restart resumes")
	return nil
}

func storedVolumeAdmission(dir string, host volumeHost, material regionjoin.Material) (swarmruntime.Admission, bool, error) {
	stored, restarted, err := swarmruntime.StoredAdmission(dir)
	if err != nil || !restarted {
		return stored, false, errors.Join(fmt.Errorf("%s has no stored admission", host.name), err)
	}
	if !stored.BelongsTo(host.name, host.instance) {
		return stored, false, nil
	}
	named, err := regionjoin.NamesStored(material, dir, stored)
	return stored, named, err
}

func startVolumeHost(ctx context.Context, state string, executor *swarmruntime.Executor, host volumeHost, admission swarmruntime.Admission) (*swarmruntime.Node, error) {
	return swarmruntime.StartHost(ctx, filepath.Join(state, host.name), executor, host.address, host.address, admission)
}

func stopVolumeHost(ctx context.Context, node *swarmruntime.Node) error {
	stop, done := context.WithTimeout(context.WithoutCancel(ctx), 15*time.Second)
	defer done()
	return node.Stop(stop)
}

func volumeMaterial(ctx context.Context, state string, founder volumeHost) (regionjoin.Material, error) {
	client, conn, err := swarmruntime.DialControl(filepath.Join(state, founder.name))
	if err != nil {
		return regionjoin.Material{}, err
	}
	defer conn.Close()
	if err := awaitPromotionReady(ctx, client, api.NewWatchClient(conn), 1, 1); err != nil {
		return regionjoin.Material{}, err
	}
	material, err := regionjoin.ClusterMaterial(ctx, client, founder.name)
	material.Managers = []string{founder.address}
	return material, err
}

func joinVolumeHost(ctx context.Context, state string, executor *swarmruntime.Executor, founder, host volumeHost, material regionjoin.Material, members int) (*swarmruntime.Node, error) {
	manager, joinable := regionjoin.ReachableManager(ctx, material)
	if !joinable {
		return nil, errors.New("the live cluster's join material names no reachable manager")
	}
	joining, err := swarmruntime.JoiningAdmission(host.name, host.instance, manager, material.WorkerToken)
	if err != nil {
		return nil, err
	}
	node, err := startVolumeHost(ctx, state, executor, host, joining)
	if err != nil {
		return nil, err
	}
	client, conn, err := swarmruntime.DialControl(filepath.Join(state, founder.name))
	if err == nil {
		defer conn.Close()
		err = awaitPromotionReady(ctx, client, api.NewWatchClient(conn), members, 1)
	}
	if err != nil {
		return nil, errors.Join(err, stopVolumeHost(ctx, node))
	}
	return node, nil
}

package main

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

func settled(indices []int, check func(members []string) bool) func() bool {
	return func() bool {
		var members []string
		for _, i := range indices {
			group, err := metaOf(i)
			if err != nil || group.Observer || group.Leader == "" || group.Change != nil || group.Size != len(metaMembers(group)) {
				return false
			}
			for _, peer := range group.Peers {
				if !peer.Known {
					return false
				}
			}
			if members == nil {
				members = metaMembers(group)
			}
			if !slices.Equal(members, metaMembers(group)) {
				return false
			}
		}
		return check(members)
	}
}

func roles(indices []int) (leader int, followers []int, err error) {
	leader = -1
	for _, i := range indices {
		group, groupErr := metaOf(i)
		if groupErr != nil {
			return -1, nil, groupErr
		}
		if group.State == "LEADER" {
			leader = i
		} else {
			followers = append(followers, i)
		}
	}
	if leader < 0 {
		return -1, nil, errors.New("no metadata leader")
	}
	return leader, followers, nil
}

func metaGuard(work string) error {
	started := time.Now()
	processes := make([]*process, len(names))
	defer func() {
		for _, p := range processes {
			if p != nil {
				_ = p.cmd.Process.Kill()
				<-p.done
			}
		}
	}()
	launchAs := func(i int, mode string) error {
		p, err := launch(work, mode, names[i], i)
		processes[i] = p
		return err
	}
	stop := func(i int) {
		_ = processes[i].cmd.Process.Kill()
		<-processes[i].done
		processes[i] = nil
	}
	all := []int{0, 1, 2}
	without := func(members []string) bool { return len(members) == 3 && !slices.Contains(members, pendingPeer) }
	with := func(members []string) bool { return len(members) == 4 && slices.Contains(members, pendingPeer) }
	for _, i := range all {
		if err := launchAs(i, "meta-node"); err != nil {
			return err
		}
	}
	if err := bounded("three founders settle on a 3-member metadata group", 30*time.Second, settled(all, without)); err != nil {
		return err
	}
	founding, err := metaOf(0)
	if err != nil {
		return err
	}
	if err := bounded("every member compacts its metadata log past the founding peer state", 120*time.Second, func() bool {
		for _, i := range all {
			group, err := metaOf(i)
			if err != nil || group.WAL.FirstSeq <= founding.Committed {
				return false
			}
		}
		return true
	}); err != nil {
		return err
	}

	_, followers, err := roles(all)
	if err != nil {
		return err
	}
	stale := followers[0]
	stop(stale)
	if err := launchAs(stale, "meta-node-size-2"); err != nil {
		return err
	}
	var last server.RaftzGroup
	if err := bounded("a restarted follower keeps a stale local size of 2 for 3 members", 30*time.Second, func() bool {
		group, err := metaOf(stale)
		last = group
		if err != nil || group.State != "FOLLOWER" || group.Leader == "" || group.Size != 2 || len(metaMembers(group)) != 3 {
			return false
		}
		others := slices.DeleteFunc(slices.Clone(all), func(i int) bool { return i == stale })
		return settled(others, without)()
	}); err != nil {
		return fmt.Errorf("%w: last state %s, leader %q, size %d, members %v, observer %t", err, last.State, last.Leader, last.Size, metaMembers(last), last.Observer)
	}
	if err := restartAllowed([]int{stale}); err != nil {
		return fmt.Errorf("stale local size under a settled leader: %w", err)
	}
	fmt.Println("ok a follower whose own size is 2 for 3 members, under a settled leader with the same members, admits a release restart")

	leader, followers, err := roles(all)
	if err != nil {
		return err
	}
	for _, i := range followers {
		stop(i)
		if err := launchAs(i, "meta-node-size-4"); err != nil {
			return err
		}
		last = server.RaftzGroup{}
		if err := bounded(names[i]+" follows with a stale local size of 4 for 3 members", 30*time.Second, func() bool {
			group, err := metaOf(i)
			last = group
			return err == nil && group.State == "FOLLOWER" && group.Leader != "" && group.Size == 4 && len(metaMembers(group)) == 3
		}); err != nil {
			return fmt.Errorf("%w: last state %s, leader %q, size %d, members %v, observer %t", err, last.State, last.Leader, last.Size, metaMembers(last), last.Observer)
		}
	}
	if err := refused(leader, "after leadership handoff", "quorum needs 3"); err != nil {
		return err
	}
	fmt.Println("ok a leader whose successor needs 3 of 3 members refuses its stop after the handoff")
	if err := bounded("a metadata leader after the refused stop", 30*time.Second, func() bool {
		leader, followers, err = roles(all)
		return err == nil
	}); err != nil {
		return err
	}

	if err := post(leader, "resize?size=2"); err != nil {
		return err
	}
	if err := bounded("every member takes the leader's stale size of 2 for 3 members, the successor's 4 replaced", 30*time.Second, func() bool {
		for _, i := range all {
			group, err := metaOf(i)
			if err != nil || group.Size != 2 || len(metaMembers(group)) != 3 || group.Change != nil {
				return false
			}
		}
		return true
	}); err != nil {
		return err
	}
	if err := restartAllowed(followers); err != nil {
		return fmt.Errorf("stale leader size with the same members: %w", err)
	}
	if err := post(leader, "resize?size=3"); err != nil {
		return err
	}
	if err := bounded("every member takes the leader's size of 3 again", 30*time.Second, settled(all, without)); err != nil {
		return err
	}
	fmt.Println("ok with the leader's own size at 2 for 3 members, followers admit a release restart against a majority of the 3 members")
	held := func(i int, removing bool) func() bool {
		return func() bool {
			group, err := metaOf(i)
			return err == nil && group.Change != nil && group.Change.Peer == pendingPeer && group.Change.Removing == removing
		}
	}
	leader, followers, err = roles(all)
	if err != nil {
		return err
	}
	if err := post(leader, "resize?size=2"); err != nil {
		return err
	}
	if err := bounded("every member takes a stale size of 2 for 3 members before the addition", 30*time.Second, func() bool {
		for _, i := range all {
			group, err := metaOf(i)
			if err != nil || group.Size != 2 || len(metaMembers(group)) != 3 || group.Change != nil {
				return false
			}
		}
		return true
	}); err != nil {
		return err
	}
	stop(followers[1])
	if err := post(leader, "propose-add?id="+pendingPeer); err != nil {
		return err
	}
	if err := refused(followers[0], "membership change in progress", "has not committed adding", pendingPeer); err != nil {
		return err
	}
	if !held(leader, false)() || !held(followers[0], false)() {
		return errors.New("the pending addition did not stay pending at the leader and its follower")
	}
	fmt.Println("ok a pending addition held by the leader and one follower refuses release restarts and is named")
	if err := launchAs(followers[1], "meta-node"); err != nil {
		return err
	}
	if err := bounded("the held addition commits once a third voter returns", 60*time.Second, settled(all, with)); err != nil {
		return err
	}
	fmt.Println("ok the committed addition sets every member's size of 2 to its member count of 4")

	leader, followers, err = roles(all)
	if err != nil {
		return err
	}
	for _, i := range followers {
		stop(i)
	}
	if err := post(leader, "propose-remove?id="+pendingPeer); err != nil {
		return err
	}
	if err := refused(leader, "membership change in progress", "has not committed removing", pendingPeer); err != nil {
		return err
	}
	if !held(leader, true)() {
		return errors.New("the pending removal did not stay pending at the leader")
	}
	fmt.Println("ok a pending removal held by the leader alone refuses release restarts and is named")
	for _, i := range followers {
		if err := launchAs(i, "meta-node"); err != nil {
			return err
		}
	}
	if err := bounded("the held removal commits once the voters return", 60*time.Second, settled(all, without)); err != nil {
		return err
	}
	if err := restartAllowed(all); err != nil {
		return fmt.Errorf("after the membership settled: %w", err)
	}
	fmt.Printf("ok metadata membership lane: %s\n", time.Since(started).Round(time.Millisecond))
	return nil
}

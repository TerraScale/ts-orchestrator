package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/plannedstop"
)

const (
	pendingPeer  = "Fv5pEnDg"
	isolatedSeed = "nats://10.79.0.250:6222"
)

func metaNode(work string, i int, stale bool) error {
	ctx, cancel := plannedstop.NotifyContext(context.Background())
	defer cancel()
	var routes []*url.URL
	for j := range names {
		if j != i {
			routes = append(routes, &url.URL{Scheme: "nats", Host: address(j) + ":6222"})
		}
	}
	configured := make([]string, 0, len(routes))
	for _, route := range routes {
		configured = append(configured, route.String())
	}
	if stale {
		configured = []string{isolatedSeed}
	}
	options := &server.Options{}
	if err := options.ProcessConfigString(fmt.Sprintf(`server_name: %s
host: 0.0.0.0
port: 4223
jetstream { store_dir: %q }
cluster { name: fabric, host: 0.0.0.0, port: 6222, routes: [%s] }
accounts { SYS { users: [{user: monitor, password: fabric-monitor}] } }
system_account: SYS
`, names[i], filepath.Join(work, "meta-"+names[i]), strings.Join(configured, ","))); err != nil {
		return err
	}
	options.NoSigs, options.SyncAlways = true, true
	options.JetStreamMetaBootSize = len(names)
	s, err := server.NewServer(options)
	if err != nil {
		return err
	}
	go s.Start()
	defer s.Shutdown()
	if !s.ReadyForConnections(10 * time.Second) {
		return errors.New("embedded server did not start")
	}
	if stale {
		if err := bounded("metadata group on the isolated server", 10*time.Second, func() bool { return metaRaftNode(s) != nil }); err != nil {
			return err
		}
		if err := metaRaftNode(s).AdjustBootClusterSize(2); err != nil {
			return fmt.Errorf("stale boot size: %w", err)
		}
		s.AddRoutes(routes)
	} else {
		go formMetaGroup(ctx, s)
	}
	monitor, err := nats.Connect("nats://127.0.0.1:4223", nats.UserInfo("monitor", "fabric-monitor"))
	if err != nil {
		return err
	}
	defer monitor.Close()
	lifecycle := mesh.NewFabricLifecycle(s, monitor)
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		groups := server.RaftzStatus{}
		if status := s.Raftz(&server.RaftzOptions{AccountFilter: "SYS"}); status != nil {
			groups = *status
		}
		_ = json.NewEncoder(w).Encode(status{Groups: groups, MetaLeader: s.JetStreamIsLeader()})
	})
	mux.HandleFunc("/prepare", func(w http.ResponseWriter, r *http.Request) {
		if err := lifecycle.PrepareStop(r.Context()); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/abort", func(w http.ResponseWriter, r *http.Request) {
		lifecycle.AbortStop()
		w.WriteHeader(http.StatusNoContent)
	})
	propose := func(remove bool) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			meta := metaRaftNode(s)
			if meta == nil {
				http.Error(w, "metadata group missing", http.StatusConflict)
				return
			}
			peer := r.URL.Query().Get("id")
			err := meta.ProposeAddPeer(peer)
			if remove {
				err = meta.ProposeRemovePeer(peer)
			}
			if err != nil {
				http.Error(w, err.Error(), http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusNoContent)
		}
	}
	mux.HandleFunc("/resize", func(w http.ResponseWriter, r *http.Request) {
		meta := metaRaftNode(s)
		size, err := strconv.Atoi(r.URL.Query().Get("size"))
		if meta == nil || err != nil {
			http.Error(w, fmt.Sprintf("metadata group missing or invalid size: %v", err), http.StatusConflict)
			return
		}
		if err := meta.AdjustClusterSize(size); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/propose-add", propose(false))
	mux.HandleFunc("/propose-remove", propose(true))
	web := &http.Server{Addr: address(i) + ":8090", Handler: mux, ReadHeaderTimeout: time.Second}
	webDone := make(chan error, 1)
	go func() { webDone <- web.ListenAndServe() }()
	select {
	case <-ctx.Done():
		s.Shutdown()
		s.WaitForShutdown()
		_ = web.Close()
		return nil
	case err := <-webDone:
		return err
	}
}

func metaRaftNode(s *server.Server) server.RaftNode {
	for _, node := range s.RaftNodes() {
		if node.Group() == "_meta_" {
			return node
		}
	}
	return nil
}

func formMetaGroup(ctx context.Context, s *server.Server) {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if meta := metaRaftNode(s); meta != nil {
			if !meta.IsObserver() {
				return
			}
			if meta.HadPreviousLeader() || routedFounders(s) == len(names)-1 {
				meta.SetObserver(false)
				return
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func routedFounders(s *server.Server) int {
	routez, err := s.Routez(&server.RoutezOptions{})
	if err != nil {
		return 0
	}
	seen := map[string]bool{}
	for _, route := range routez.Routes {
		if slices.Contains(names, route.RemoteName) {
			seen[route.RemoteName] = true
		}
	}
	return len(seen)
}

func metaOf(i int) (server.RaftzGroup, error) {
	state, err := readStatus(i)
	if err != nil {
		return server.RaftzGroup{}, err
	}
	group, ok := state.Groups["SYS"]["_meta_"]
	if !ok {
		return group, errors.New("no metadata group")
	}
	return group, nil
}

func metaMembers(group server.RaftzGroup) []string {
	members := []string{group.ID}
	for id := range group.Peers {
		members = append(members, id)
	}
	slices.Sort(members)
	return members
}

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

func restartAllowed(indices []int) error {
	for _, i := range indices {
		if err := post(i, "prepare"); err != nil {
			return err
		}
		if err := post(i, "abort"); err != nil {
			return err
		}
	}
	return nil
}

func refused(i int, want ...string) error {
	err := post(i, "prepare")
	if err == nil {
		_ = post(i, "abort")
		return fmt.Errorf("%s: release restart admitted, want a refusal naming %q", names[i], want)
	}
	for _, text := range want {
		if !strings.Contains(err.Error(), text) {
			return fmt.Errorf("%s: refusal %q does not name %q", names[i], err, text)
		}
	}
	fmt.Printf("ok %s refuses: %v\n", names[i], err)
	return nil
}

func metaPeers(work string) error {
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

	_, followers, err := roles(all)
	if err != nil {
		return err
	}
	stale := followers[0]
	stop(stale)
	if err := launchAs(stale, "meta-node-stale"); err != nil {
		return err
	}
	if err := bounded("a restarted follower keeps a stale local size of 2 for 3 members", 30*time.Second, func() bool {
		group, err := metaOf(stale)
		if err != nil || group.State != "FOLLOWER" || group.Leader == "" || group.Size != 2 || len(metaMembers(group)) != 3 {
			return false
		}
		others := slices.DeleteFunc(slices.Clone(all), func(i int) bool { return i == stale })
		return settled(others, without)()
	}); err != nil {
		return err
	}
	if err := restartAllowed([]int{stale}); err != nil {
		return fmt.Errorf("stale local size under a settled leader: %w", err)
	}
	fmt.Println("ok a follower whose own size is 2 for 3 members, under a settled leader with the same members, admits a release restart")

	leader, followers, err := roles(all)
	if err != nil {
		return err
	}
	if err := post(leader, "resize?size=2"); err != nil {
		return err
	}
	if err := bounded("every member takes the leader's stale size of 2 for 3 members", 30*time.Second, func() bool {
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

	leader, followers, err = roles(all)
	if err != nil {
		return err
	}
	silent := slices.DeleteFunc(slices.Clone(followers), func(i int) bool { return i == stale })[0]
	stop(silent)
	if err := post(leader, "propose-add?id="+pendingPeer); err != nil {
		return err
	}
	if err := refused(stale, "membership change in progress", "has not committed adding", pendingPeer); err != nil {
		return err
	}
	fmt.Println("ok a pending addition refuses release restarts and is named")
	if err := launchAs(silent, "meta-node"); err != nil {
		return err
	}
	if err := bounded("the metadata group settles after the addition", 60*time.Second, settled(all, func(members []string) bool { return with(members) || without(members) })); err != nil {
		return err
	}
	if !settled(all, with)() {
		if leader, _, err = roles(all); err != nil {
			return err
		}
		if err := post(leader, "propose-add?id="+pendingPeer); err != nil {
			return err
		}
		if err := bounded("the addition commits", 30*time.Second, settled(all, with)); err != nil {
			return err
		}
	}

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
	fmt.Println("ok a pending removal refuses release restarts and is named")
	for _, i := range followers {
		if err := launchAs(i, "meta-node"); err != nil {
			return err
		}
	}
	if err := bounded("the metadata group settles after the removal", 60*time.Second, settled(all, func(members []string) bool { return with(members) || without(members) })); err != nil {
		return err
	}
	if !settled(all, without)() {
		if leader, _, err = roles(all); err != nil {
			return err
		}
		if err := post(leader, "propose-remove?id="+pendingPeer); err != nil {
			return err
		}
		if err := bounded("the removal commits", 30*time.Second, settled(all, without)); err != nil {
			return err
		}
	}
	if err := restartAllowed(all); err != nil {
		return fmt.Errorf("after the membership settled: %w", err)
	}
	fmt.Printf("ok metadata membership lane: %s\n", time.Since(started).Round(time.Millisecond))
	return nil
}

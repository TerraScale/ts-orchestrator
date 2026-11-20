package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/plannedstop"
)

type metaRole int

const (
	founder metaRole = iota
	worker
	manager
)

var metaRoster = []struct {
	name string
	role metaRole
}{{"one", founder}, {"two", founder}, {"three", founder}, {"worker", worker}, {"four", manager}}

const pendingPeer = "Fv5pEnDg"

func metaNode(work string, i int) error {
	ctx, cancel := plannedstop.NotifyContext(context.Background())
	defer cancel()
	self := metaRoster[i]
	var routes []string
	for j := range metaRoster {
		if j != i {
			routes = append(routes, "nats://"+address(j)+":6222")
		}
	}
	jetstream := ""
	if self.role != worker {
		jetstream = fmt.Sprintf("jetstream { store_dir: %q }", filepath.Join(work, "meta-"+self.name))
	}
	options := &server.Options{}
	if err := options.ProcessConfigString(fmt.Sprintf(`server_name: %s
host: 0.0.0.0
port: 4223
%s
cluster { name: fabric, host: 0.0.0.0, port: 6222, routes: [%s] }
accounts { SYS { users: [{user: monitor, password: fabric-monitor}] } }
system_account: SYS
`, self.name, jetstream, strings.Join(routes, ","))); err != nil {
		return err
	}
	options.NoSigs, options.SyncAlways = true, true
	if self.role != worker {
		options.JetStreamMetaBootSize = 3
	}
	s, err := server.NewServer(options)
	if err != nil {
		return err
	}
	go s.Start()
	defer s.Shutdown()
	if !s.ReadyForConnections(10 * time.Second) {
		return errors.New("embedded server did not start")
	}
	monitor, err := nats.Connect("nats://127.0.0.1:4223", nats.UserInfo("monitor", "fabric-monitor"))
	if err != nil {
		return err
	}
	defer monitor.Close()
	lifecycle := mesh.NewFabricLifecycle(s, monitor)
	var goneMu sync.Mutex
	gone := map[string]bool{}
	if self.role != worker {
		go formMetaGroup(ctx, s, self.role)
		go func() {
			tick := time.NewTicker(500 * time.Millisecond)
			defer tick.Stop()
			for {
				select {
				case <-ctx.Done():
					return
				case <-tick.C:
				}
				err := lifecycle.TendMeta(ctx, func(_ context.Context, id, _ string) (bool, error) {
					goneMu.Lock()
					defer goneMu.Unlock()
					return gone[id], nil
				})
				if err != nil && ctx.Err() == nil {
					fmt.Printf("tend %s: %v\n", self.name, err)
				}
			}
		}()
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		groups := server.RaftzStatus{}
		if status := s.Raftz(&server.RaftzOptions{AccountFilter: "SYS"}); status != nil {
			groups = *status
		}
		health := ""
		if self.role != worker {
			if err := lifecycle.Health(r.Context()); err != nil {
				health = err.Error()
			}
		}
		routes := map[string][]uint64{}
		if routez, err := s.Routez(&server.RoutezOptions{}); err == nil {
			for _, route := range routez.Routes {
				routes[route.RemoteName] = append(routes[route.RemoteName], route.Rid)
			}
		}
		_ = json.NewEncoder(w).Encode(status{Groups: groups, Routes: routes, MetaLeader: s.JetStreamIsLeader(), Health: health})
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
	mux.HandleFunc("/gone", func(w http.ResponseWriter, r *http.Request) {
		goneMu.Lock()
		gone[r.URL.Query().Get("id")] = true
		goneMu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	})
	mux.HandleFunc("/propose-add", func(w http.ResponseWriter, r *http.Request) {
		meta := metaRaftNode(s)
		if meta == nil {
			http.Error(w, "metadata group missing", http.StatusConflict)
			return
		}
		if err := meta.ProposeAddPeer(r.URL.Query().Get("id")); err != nil {
			http.Error(w, err.Error(), http.StatusConflict)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
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

func formMetaGroup(ctx context.Context, s *server.Server, role metaRole) {
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		if meta := metaRaftNode(s); meta != nil {
			if !meta.IsObserver() {
				return
			}
			if meta.HadPreviousLeader() || role == founder && routedFounders(s) == 2 {
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
		for _, member := range metaRoster {
			if member.role == founder && member.name == route.RemoteName {
				seen[member.name] = true
			}
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

func agreed(founders []int, size int, without string) func() bool {
	return func() bool {
		var members []string
		for _, i := range founders {
			group, err := metaOf(i)
			if err != nil || group.Size != size || group.Observer || group.Leader == "" || slices.Contains(metaMembers(group), without) {
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
			if len(metaMembers(group)) != size || !slices.Equal(members, metaMembers(group)) {
				return false
			}
		}
		return true
	}
}

func restartAllowed(founders []int) error {
	for _, i := range founders {
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
		return fmt.Errorf("%s: release restart admitted, want a refusal naming %q", metaRoster[i].name, want)
	}
	for _, text := range want {
		if !strings.Contains(err.Error(), text) {
			return fmt.Errorf("%s: refusal %q does not name %q", metaRoster[i].name, err, text)
		}
	}
	fmt.Printf("ok %s refuses: %v\n", metaRoster[i].name, err)
	return nil
}

func metaPeers(work string) error {
	started := time.Now()
	processes := make([]*process, len(metaRoster))
	defer func() {
		for _, p := range processes {
			if p != nil {
				_ = p.cmd.Process.Kill()
				<-p.done
			}
		}
	}()
	launchAt := func(i int) error {
		p, err := launch(work, "meta-node", metaRoster[i].name, i)
		processes[i] = p
		return err
	}
	stop := func(i int) {
		_ = processes[i].cmd.Process.Kill()
		<-processes[i].done
		processes[i] = nil
	}
	for _, i := range []int{3, 0, 1} {
		if err := launchAt(i); err != nil {
			return err
		}
	}
	if err := bounded("worker routed into the cold-booting founders", 20*time.Second, func() bool {
		for _, i := range []int{0, 1} {
			state, err := readStatus(i)
			if err != nil {
				return false
			}
			if group, ok := state.Groups["SYS"]["_meta_"]; !ok || group.Leader != "" || group.Size != 3 {
				return false
			}
		}
		return routedWorker(0) && routedWorker(1)
	}); err != nil {
		return err
	}
	if err := launchAt(2); err != nil {
		return err
	}
	founders := []int{0, 1, 2}
	if err := bounded("three founders agree on a 3-member metadata group with a worker routed in", 30*time.Second, agreed(founders, 3, "")); err != nil {
		return err
	}
	if err := restartAllowed(founders); err != nil {
		return fmt.Errorf("worker routed in at first start: %w", err)
	}
	fmt.Println("ok a worker routed in at first start leaves the metadata group at 3 founders and admits release restarts")

	if err := launchAt(4); err != nil {
		return err
	}
	if err := bounded("a fourth JetStream server joins the metadata group", 30*time.Second, agreed(founders, 4, "")); err != nil {
		return err
	}
	four, err := metaOf(4)
	if err != nil {
		return err
	}
	stop(4)
	if err := bounded("the metadata leader stops hearing from the removed server", 30*time.Second, func() bool {
		for _, i := range founders {
			group, err := metaOf(i)
			if err != nil || group.State != "LEADER" {
				continue
			}
			seen, err := time.ParseDuration(group.Peers[four.ID].LastSeen)
			return err == nil && seen > 3*time.Second
		}
		return false
	}); err != nil {
		return err
	}
	if err := refused(0, four.ID, "quorum needs 3"); err != nil {
		return err
	}
	for _, i := range founders {
		if err := post(i, "gone?id="+four.ID); err != nil {
			return err
		}
	}
	if err := bounded("the removed server leaves the metadata group", 30*time.Second, agreed(founders, 3, four.ID)); err != nil {
		return err
	}
	if err := restartAllowed(founders); err != nil {
		return fmt.Errorf("after removing a confirmed-gone peer: %w", err)
	}
	fmt.Println("ok a removed server is taken out of the metadata group and release restarts are admitted")

	stop(2)
	leader, follower := -1, -1
	if err := bounded("a metadata leader among the two running founders", 30*time.Second, func() bool {
		leader, follower = -1, -1
		for _, i := range []int{0, 1} {
			group, err := metaOf(i)
			if err != nil || group.Size != 3 || group.Leader == "" {
				return false
			}
			if group.State == "LEADER" {
				leader = i
			} else {
				follower = i
			}
		}
		return leader >= 0 && follower >= 0
	}); err != nil {
		return err
	}
	if err := post(leader, "propose-add?id="+pendingPeer); err != nil {
		return err
	}
	if err := refused(follower, "membership is changing", pendingPeer); err != nil {
		return err
	}
	fmt.Println("ok an uncommitted membership change refuses release restarts")
	for _, i := range []int{0, 1} {
		if err := post(i, "gone?id="+pendingPeer); err != nil {
			return err
		}
	}
	if err := launchAt(2); err != nil {
		return err
	}
	if err := bounded("the metadata group settles at 3 founders after the change", 60*time.Second, agreed(founders, 3, pendingPeer)); err != nil {
		return err
	}
	if err := restartAllowed(founders); err != nil {
		return fmt.Errorf("after the membership change settled: %w", err)
	}
	fmt.Printf("ok metadata membership lane: %s\n", time.Since(started).Round(time.Millisecond))
	return nil
}

func routedWorker(i int) bool {
	state, err := readStatus(i)
	return err == nil && len(state.Routes["worker"]) > 0
}

package main

import (
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/nats-io/nats-server/v2/logger"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

type transferLog struct {
	server.Logger
	selected chan string
}

func (l *transferLog) Debugf(format string, values ...any) {
	message := fmt.Sprintf(format, values...)
	if _, rest, ok := strings.Cut(message, "Selected \""); ok {
		if peer, _, ok := strings.Cut(rest, "\" for new leader"); ok {
			select {
			case l.selected <- peer:
			default:
			}
		}
	}
	l.Logger.Debugf(format, values...)
}

func metadata(s *server.Server) server.RaftNode {
	for _, node := range s.RaftNodes() {
		if node.Group() == "_meta_" {
			return node
		}
	}
	return nil
}

func caughtUpHandoffs(work string) error {
	servers := make([]*server.Server, 5)
	logs := make([]*transferLog, 5)
	defer func() {
		for _, s := range servers {
			if s != nil {
				s.Shutdown()
			}
		}
		for _, s := range servers {
			if s != nil {
				s.WaitForShutdown()
			}
		}
	}()
	seed, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	seedPort := seed.Addr().(*net.TCPAddr).Port
	if err := seed.Close(); err != nil {
		return err
	}
	for i := range servers {
		options := &server.Options{
			ServerName: fmt.Sprintf("caughtup-%d", i), Host: "127.0.0.1", Port: -1,
			JetStream: true, StoreDir: filepath.Join(work, fmt.Sprintf("caughtup-%d", i)),
			NoSigs: true, SyncAlways: true,
			Cluster: server.ClusterOpts{Name: "caughtup", Host: "127.0.0.1", Port: -1},
		}
		options.Tags.Add(options.ServerName)
		if i == 0 {
			options.Cluster.Port = seedPort
		}
		route, err := url.Parse(fmt.Sprintf("nats://127.0.0.1:%d", seedPort))
		if err != nil {
			return err
		}
		options.Routes = []*url.URL{route}
		s, err := server.NewServer(options)
		if err != nil {
			return err
		}
		servers[i] = s
		logs[i] = &transferLog{logger.NewFileLogger(filepath.Join(work, fmt.Sprintf("caughtup-%d.log", i)), false, true, false, true), make(chan string, 1)}
		s.SetLogger(logs[i], true, false)
		go s.Start()
		if !s.ReadyForConnections(10 * time.Second) {
			return errors.New("five-voter server did not start")
		}
	}
	currentLeader := func() int {
		for i, s := range servers {
			node := metadata(s)
			if node == nil || !node.Leader() || len(node.Peers()) != 5 {
				continue
			}
			current := true
			for _, peer := range node.Peers() {
				current = current && peer.Current && (peer.ID == node.ID() || time.Since(peer.Last) < time.Second)
			}
			if current {
				return i
			}
		}
		return -1
	}
	for round := range 32 {
		leader := -1
		if err := bounded("five current metadata voters", 10*time.Second, func() bool {
			leader = currentLeader()
			return leader >= 0
		}); err != nil {
			return err
		}
		conn, err := nats.Connect(servers[leader].ClientURL())
		if err != nil {
			return err
		}
		js, err := conn.JetStream()
		if err != nil {
			conn.Close()
			return err
		}
		err = func() error {
			defer conn.Close()
			lagging := metadata(servers[(leader+1)%len(servers)])
			lagID := lagging.ID()
			lock := lagging.(sync.Locker)
			lock.Lock()
			defer lock.Unlock()
			if _, err := js.AddStream(&nats.StreamConfig{Name: fmt.Sprintf("advance_%d", round), Replicas: 1, Placement: &nats.Placement{Tags: []string{servers[leader].Name()}}}); err != nil {
				return err
			}
			node := metadata(servers[leader])
			eligible := map[string]bool{}
			if err := bounded("one lagging and three current followers", time.Second, func() bool {
				eligible = map[string]bool{}
				lag := false
				for _, peer := range node.Peers() {
					if peer.ID == lagID {
						lag = !peer.Current && peer.Lag > 0 && time.Since(peer.Last) < time.Second
					} else if peer.ID != node.ID() && peer.Current && time.Since(peer.Last) < time.Second {
						eligible[peer.ID] = true
					}
				}
				return lag && len(eligible) == 3
			}); err != nil {
				return err
			}
			if !servers[leader].TransferRaftLeaders() || node.State() == server.Leader {
				return errors.New("five-voter leader did not transfer")
			}
			select {
			case selected := <-logs[leader].selected:
				if !eligible[selected] {
					return fmt.Errorf("handoff %d selected %s outside caught-up followers %v; lagging=%s", round, selected, eligible, lagID)
				}
				fmt.Printf("ok five-voter handoff %d: selected=%s lagging=%s current_followers=%d\n", round, selected, lagID, len(eligible))
			default:
				return errors.New("five-voter handoff did not select a successor")
			}
			return nil
		}()
		if err != nil {
			return err
		}
		if err := bounded("caught-up successor elected", 5*time.Second, func() bool {
			next := currentLeader()
			return next >= 0 && next != leader
		}); err != nil {
			return err
		}
		metadata(servers[leader]).SetObserver(false)
	}
	return noCaughtUpFollower(servers, logs, currentLeader)
}

func noCaughtUpFollower(servers []*server.Server, logs []*transferLog, currentLeader func() int) error {
	leader := -1
	if err := bounded("five current metadata voters", 10*time.Second, func() bool {
		leader = currentLeader()
		return leader >= 0
	}); err != nil {
		return err
	}
	node := metadata(servers[leader])
	conn, err := nats.Connect(servers[leader].ClientURL())
	if err != nil {
		return err
	}
	defer conn.Close()
	js, err := conn.JetStream()
	if err != nil {
		return err
	}
	var held []sync.Locker
	for i, s := range servers {
		if i != leader {
			lock := metadata(s).(sync.Locker)
			lock.Lock()
			held = append(held, lock)
		}
	}
	release := sync.OnceFunc(func() {
		for _, lock := range held {
			lock.Unlock()
		}
	})
	defer release()
	before, _, _ := node.Progress()
	added := make(chan error, 1)
	go func() {
		_, err := js.AddStream(&nats.StreamConfig{Name: "behind", Replicas: 1, Placement: &nats.Placement{Tags: []string{servers[leader].Name()}}})
		added <- err
	}()
	stored := before
	if err := bounded("metadata change stored only on the leader", time.Second, func() bool {
		stored, _, _ = node.Progress()
		return stored > before
	}); err != nil {
		return err
	}
	if servers[leader].TransferRaftLeaders() || node.State() != server.Leader {
		return fmt.Errorf("five-voter leader stepped down at index %d while all four followers held at most %d", stored, before)
	}
	select {
	case selected := <-logs[leader].selected:
		return fmt.Errorf("five-voter leader selected %s while no follower held index %d", selected, stored)
	default:
	}
	release()
	if err := <-added; err != nil {
		return err
	}
	if err := bounded("handoff once a follower holds every entry", 5*time.Second, func() bool {
		return servers[leader].TransferRaftLeaders()
	}); err != nil {
		return err
	}
	selected := <-logs[leader].selected
	successor := -1
	if err := bounded("caught-up successor elected", 5*time.Second, func() bool {
		successor = currentLeader()
		return successor >= 0 && metadata(servers[successor]).ID() == selected
	}); err != nil {
		return err
	}
	node.SetObserver(false)
	fmt.Printf("ok five-voter no caught-up follower: leader kept leading at index %d with four followers at %d, then handed off to %s\n", stored, before, selected)
	return nil
}

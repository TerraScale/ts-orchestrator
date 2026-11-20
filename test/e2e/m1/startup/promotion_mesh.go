package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/nats-io/nats.go"
)

type meshElectionLog struct {
	pending []byte
	elected chan struct{}
	once    sync.Once
}

func (log *meshElectionLog) Write(data []byte) (int, error) {
	log.pending = append(log.pending, data...)
	for {
		end := bytes.IndexByte(log.pending, '\n')
		if end < 0 {
			break
		}
		line := string(log.pending[:end])
		log.pending = log.pending[end+1:]
		if strings.Contains(line, "metadata leader") && !strings.Contains(line, "no metadata leader") {
			log.once.Do(func() { close(log.elected) })
		}
	}
	return os.Stderr.Write(data)
}

func meshIP(index int) string { return fmt.Sprintf("10.254.0.%d", index+2) }

func ipCommand(ctx context.Context, args ...string) error {
	output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ip %v: %w: %s", args, err, output)
	}
	return nil
}

func meshPromotionJourney(ctx context.Context, state string, nodes []*swarmruntime.Node) error {
	if err := ipCommand(ctx, "link", "add", "mesh-journey", "type", "bridge"); err != nil {
		return err
	}
	defer func() { _ = ipCommand(context.Background(), "link", "del", "mesh-journey") }()
	if err := ipCommand(ctx, "link", "set", "mesh-journey", "up"); err != nil {
		return err
	}
	binary, err := os.Executable()
	if err != nil {
		return err
	}
	var inputs []io.WriteCloser
	var outputs []*bufio.Scanner
	var elections []<-chan struct{}
	for i, node := range nodes {
		dir := "manager"
		if i > 0 {
			dir = fmt.Sprintf("worker-%d", i-1)
		}
		command := exec.CommandContext(ctx, "unshare", "--net", binary, filepath.Join(state, dir), "promotion-mesh", strconv.Itoa(i))
		log := &meshElectionLog{elected: make(chan struct{})}
		command.Stderr = log
		elections = append(elections, log.elected)
		input, err := command.StdinPipe()
		if err != nil {
			return err
		}
		output, err := command.StdoutPipe()
		if err != nil {
			return err
		}
		if err := command.Start(); err != nil {
			return err
		}
		defer func() {
			_ = input.Close()
			_ = command.Process.Kill()
			_ = command.Wait()
		}()
		scanner := bufio.NewScanner(output)
		if !scanner.Scan() || scanner.Text() != "waiting" {
			return fmt.Errorf("mesh %d network namespace did not start", i)
		}
		host, peer := fmt.Sprintf("mesh%d", i), fmt.Sprintf("node%d", i)
		for _, args := range [][]string{
			{"link", "add", host, "type", "veth", "peer", "name", peer},
			{"link", "set", host, "master", "mesh-journey"},
			{"link", "set", host, "up"},
			{"link", "set", peer, "netns", strconv.Itoa(command.Process.Pid)},
		} {
			if err := ipCommand(ctx, args...); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintln(input, "start"); err != nil {
			return err
		}
		want := "gru"
		if i > 0 {
			want += "." + node.ID()[:12]
		}
		if !scanner.Scan() || scanner.Text() != "ready "+want {
			return fmt.Errorf("mesh %d did not start with server name %s: %s", i, want, scanner.Text())
		}
		inputs, outputs = append(inputs, input), append(outputs, scanner)
	}
	for i, elected := range elections {
		select {
		case <-ctx.Done():
			return fmt.Errorf("mesh %d metadata election: %w", i, ctx.Err())
		case <-elected:
		}
	}
	for _, input := range inputs {
		if _, err := fmt.Fprintln(input, "check"); err != nil {
			return err
		}
	}
	for i := range outputs {
		if !outputs[i].Scan() || outputs[i].Text() != "checked" {
			return fmt.Errorf("mesh %d failed region request checks: %s", i, outputs[i].Text())
		}
	}
	fmt.Println("ok mesh promotion: three unique routed managers; ping/state/apply/drain each reply once per region")
	return nil
}

func servePromotionMesh() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := os.Args[1]
	index, err := strconv.Atoi(os.Args[3])
	if err != nil {
		return err
	}
	input := bufio.NewScanner(os.Stdin)
	fmt.Println("waiting")
	if !input.Scan() || input.Text() != "start" {
		return fmt.Errorf("mesh child missing start signal")
	}
	for _, args := range [][]string{
		{"link", "set", "lo", "up"},
		{"address", "add", meshIP(index) + "/24", "dev", fmt.Sprintf("node%d", index)},
		{"link", "set", fmt.Sprintf("node%d", index), "up"},
	} {
		if err := ipCommand(ctx, args...); err != nil {
			return err
		}
	}
	seed := sha256.Sum256([]byte("promotion-journey"))
	ca, err := mesh.DeriveCA(seed[:])
	if err != nil {
		return err
	}
	routes := []string{}
	for i := range 3 {
		if i != index {
			routes = append(routes, "nats://"+meshIP(i)+":6222")
		}
	}
	name := "manager"
	if index > 0 {
		name = fmt.Sprintf("worker-%d", index-1)
	}
	node, err := mesh.StartRegionalHost(mesh.RegionalHost{
		State: state, Region: "gru", Server: name, CA: ca, TerraBaseToken: fmt.Sprintf("%x", seed),
		Routes: routes, ClusterAddress: meshIP(index) + ":6222", Address: func() (string, error) { return meshIP(index), nil },
	})
	if err != nil {
		return err
	}
	defer node.Close()
	go node.Run(ctx)
	conn, err := mesh.Connect(state)
	if err != nil {
		return err
	}
	defer conn.Close()
	membership, err := conn.SubscribeSync(protocol.MeshWorkerPrefix + "gru")
	if err != nil {
		return err
	}
	defer membership.Unsubscribe()
	if err := regionhealth.Serve(conn, func() regionhealth.Report {
		return regionhealth.Report{State: regionhealth.StateOK, At: time.Now().UTC()}
	}); err != nil {
		return err
	}
	if err := conn.Flush(); err != nil {
		return err
	}
	fmt.Println("ready " + conn.ConnectedServerName())
	if !input.Scan() || input.Text() != "check" {
		return fmt.Errorf("mesh child missing check signal")
	}
	for len(node.RegionalNodes()) != 3 {
		if _, err := membership.NextMsgWithContext(ctx); err != nil {
			return fmt.Errorf("manager promotion lost regional serving peers: %w", err)
		}
	}
	for _, peer := range node.RegionalNodes() {
		want := map[string]string{"manager": meshIP(0), "worker-0": meshIP(1), "worker-1": meshIP(2)}
		if peer.Address != want[peer.Node] {
			return fmt.Errorf("regional manager peer changed identity or address: %+v", peer)
		}
	}
	if err := checkRegionRequests(conn); err != nil {
		return err
	}
	for i := range 3 {
		peer := "manager"
		if i > 0 {
			peer = fmt.Sprintf("worker-%d", i-1)
		}
		if _, err := conn.Request(protocol.MeshDrainPrefix+"gru."+peer+".clear", []byte("{"), 3*time.Second); err != nil {
			return fmt.Errorf("mesh route to manager %d: %w", i, err)
		}
	}
	if err := checkRegionRequests(conn); err != nil {
		return err
	}
	fmt.Println("checked")
	for input.Scan() {
	}
	return input.Err()
}

func checkRegionRequests(conn *nats.Conn) error {
	for _, subject := range []string{mesh.PingSubject, mesh.StateSubject, mesh.ApplySubject, protocol.MeshDrainPrefix + "gru", protocol.MeshHealthSubject} {
		payload := []byte("{}")
		if subject == mesh.ApplySubject {
			encoded, err := protocol.EncodeJSON(mesh.ApplyRequest{Name: "promotion-probe", Entry: mesh.Entry{Generation: time.Now().UnixNano()}})
			if err != nil {
				return err
			}
			payload = encoded
		}
		if err := oneRegionReply(conn, subject, payload); err != nil {
			return err
		}
	}
	return nil
}

func oneRegionReply(conn *nats.Conn, subject string, payload []byte) error {
	inbox := nats.NewInbox()
	subscription, err := conn.SubscribeSync(inbox)
	if err != nil {
		return err
	}
	defer func() { _ = subscription.Unsubscribe() }()
	if err := conn.Flush(); err != nil {
		return err
	}
	if err := conn.PublishRequest(subject, inbox, payload); err != nil {
		return err
	}
	deadline := time.Now().Add(time.Second)
	replies := 0
	for time.Now().Before(deadline) {
		message, err := subscription.NextMsg(time.Until(deadline))
		if err == nats.ErrTimeout {
			break
		}
		if err != nil {
			return err
		}
		if strings.HasPrefix(subject, "ts.svc.") || subject == mesh.PingSubject {
			var reply mesh.Reply
			if err := protocol.DecodeTolerant(message.Data, &reply, 1<<20); err != nil || reply.Region != "gru" {
				return fmt.Errorf("%s returned an invalid region reply: %s", subject, message.Data)
			}
		}
		if subject == protocol.MeshHealthSubject {
			var report regionhealth.Report
			if err := protocol.DecodeTolerant(message.Data, &report, 1<<20); err != nil || report.Region != "gru" || report.State != regionhealth.StateOK {
				return fmt.Errorf("health returned an invalid region report: %s", message.Data)
			}
		}
		replies++
	}
	if replies != 1 {
		return fmt.Errorf("%s answered %d times; want one region reply", subject, replies)
	}
	return nil
}

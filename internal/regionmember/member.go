package regionmember

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

const (
	actionList    = "ls"
	actionPromote = "promote"
	listWait      = 10 * time.Second
	promoteWait   = 3 * time.Minute
	reconnect     = 10 * time.Second
	maxMessage    = 256 << 10
)

type request struct {
	Action string `json:"action"`
}

type Reply struct {
	Region    string                  `json:"region"`
	Leader    string                  `json:"leader"`
	Members   swarmruntime.MemberList `json:"members"`
	Promotion *swarmruntime.Promotion `json:"promotion,omitempty"`
	Error     string                  `json:"error,omitempty"`
}

func subject(region string) string { return protocol.MeshMemberPrefix + region }

func Serve(ctx context.Context, state string, node *swarmruntime.Node) {
	tick := time.NewTicker(reconnect)
	defer tick.Stop()
	var conn *nats.Conn
	defer func() {
		if conn != nil {
			conn.Close()
		}
	}()
	for {
		if conn == nil || conn.IsClosed() {
			if conn, _ = mesh.Connect(state); conn != nil {
				if err := serve(ctx, conn, node); err != nil {
					slog.WarnContext(ctx, "region member responder failed", "error", err)
					conn.Close()
					conn = nil
				}
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func serve(ctx context.Context, conn *nats.Conn, node *swarmruntime.Node) error {
	region := mesh.ConnRegion(conn)
	if region == "" {
		return errors.New("mesh server has no region identity")
	}
	if _, err := conn.Subscribe(subject(region), func(m *nats.Msg) {
		go answer(ctx, node, region, m)
	}); err != nil {
		return err
	}
	return conn.Flush()
}

func answer(ctx context.Context, node *swarmruntime.Node, region string, m *nats.Msg) {
	var asked request
	if err := protocol.DecodeStrict(m.Data, &asked, maxMessage); err != nil || asked.Action != actionList && asked.Action != actionPromote {
		return
	}
	if _, err := node.RaftVoters(); err != nil {
		return
	}
	leader, _ := os.Hostname()
	reply := Reply{Region: region, Leader: leader}
	if asked.Action == actionPromote {
		promoteCtx, cancel := context.WithTimeout(ctx, promoteWait-10*time.Second)
		promotion, err := node.PromoteManager(promoteCtx)
		cancel()
		if promotion.NodeID != "" {
			reply.Promotion = &promotion
		}
		if err != nil {
			reply.Error = err.Error()
		}
		slog.InfoContext(ctx, "operator promotion", "region", region, "promoted", promotion.Hostname, "voters", promotion.Voters, "error", reply.Error)
	}
	listCtx, cancel := context.WithTimeout(ctx, listWait)
	defer cancel()
	members, err := list(listCtx, node)
	reply.Members = members
	if err != nil {
		reply.Error = strings.TrimPrefix(reply.Error+"; "+err.Error(), "; ")
	}
	data, err := protocol.EncodeJSON(reply)
	if err == nil {
		err = m.Respond(data)
	}
	if err != nil {
		slog.WarnContext(ctx, "region member reply failed", "region", region, "error", err)
	}
}

func list(ctx context.Context, node *swarmruntime.Node) (swarmruntime.MemberList, error) {
	client, err := node.ControlClient(ctx)
	if err != nil {
		return swarmruntime.MemberList{}, err
	}
	members, err := swarmruntime.ListMembers(ctx, client)
	if err != nil {
		return members, err
	}
	voters, err := node.RaftVoters()
	if err != nil {
		return members, err
	}
	members.Voters, members.Reachable = len(voters), 0
	for _, voter := range voters {
		if voter.Reachable {
			members.Reachable++
		}
	}
	return members, nil
}

func List(ctx context.Context, conn *nats.Conn, region string) (Reply, error) {
	return ask(ctx, conn, region, actionList, listWait)
}

func Promote(ctx context.Context, conn *nats.Conn, region string) (Reply, error) {
	return ask(ctx, conn, region, actionPromote, promoteWait)
}

func ask(ctx context.Context, conn *nats.Conn, region, action string, wait time.Duration) (Reply, error) {
	if regions := mesh.ConnRegions(conn); !slices.Contains(regions, region) {
		return Reply{}, fmt.Errorf("unknown region %q; the mesh has %s", region, strings.Join(regions, ", "))
	}
	data, err := protocol.EncodeJSON(request{Action: action})
	if err != nil {
		return Reply{}, err
	}
	ctx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	response, err := conn.RequestWithContext(ctx, subject(region), data)
	switch {
	case errors.Is(err, nats.ErrNoResponders):
		return Reply{}, fmt.Errorf("no manager of %s is on the mesh", region)
	case errors.Is(err, context.DeadlineExceeded):
		return Reply{}, fmt.Errorf("%s's Raft leader did not answer within %s", region, wait)
	case err != nil:
		return Reply{}, err
	}
	var reply Reply
	if err := protocol.DecodeStrict(response.Data, &reply, maxMessage); err != nil {
		return Reply{}, err
	}
	if reply.Error != "" {
		return reply, errors.New(reply.Error)
	}
	return reply, nil
}

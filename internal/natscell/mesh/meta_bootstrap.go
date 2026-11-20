package mesh

import (
	"context"
	"encoding/json"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

type metaPeers struct {
	founders []string
	stateful []string
}

func (cfg config) founders() []string {
	names := append([]string{cfg.region}, slices.Collect(maps.Keys(cfg.seeds))...)
	slices.Sort(names)
	return slices.Compact(names)
}

func (n *Node) formMeta() {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		if meta := n.metaNode(); meta != nil {
			if !meta.IsObserver() {
				return
			}
			if meta.HadPreviousLeader() {
				meta.SetObserver(false)
				slog.Info("mesh JetStream metadata joined its group", "region", n.cfg.region, "leader", meta.GroupLeader())
				return
			}
			if n.cfg.founder {
				peers, err := n.metaPeers(n.ctx)
				if n.ctx.Err() != nil {
					return
				}
				if err != nil {
					slog.Warn("mesh JetStream metadata peers unavailable", "error", err)
				} else if len(peers.stateful) == 0 && len(peers.founders) == len(n.cfg.founders()) {
					meta.SetObserver(false)
					slog.Info("mesh JetStream metadata forms a new group", "region", n.cfg.region, "founders", peers.founders)
					return
				}
			}
		}
		select {
		case <-n.ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func (n *Node) metaNode() server.RaftNode {
	for _, node := range n.server.RaftNodes() {
		if node.Group() == metaGroup {
			return node
		}
	}
	return nil
}

func (n *Node) metaPeers(parent context.Context) (metaPeers, error) {
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	inbox := n.monitor.NewRespInbox()
	sub, err := n.monitor.SubscribeSync(inbox)
	if err != nil {
		return metaPeers{}, err
	}
	defer sub.Unsubscribe()
	account := n.server.SystemAccount().Name
	payload, err := json.Marshal(server.RaftzOptions{AccountFilter: account, GroupFilter: metaGroup})
	if err != nil {
		return metaPeers{}, err
	}
	if err := n.monitor.PublishRequest("$SYS.REQ.SERVER.PING.RAFTZ", inbox, payload); err != nil {
		return metaPeers{}, err
	}
	founders := n.cfg.founders()
	seen := map[string]bool{}
	var peers metaPeers
	for {
		message, err := sub.NextMsgWithContext(ctx)
		if err != nil {
			return peers, parent.Err()
		}
		var reply struct {
			Server struct {
				Name string `json:"name"`
			} `json:"server"`
			Data server.RaftzStatus `json:"data"`
		}
		if err := json.Unmarshal(message.Data, &reply); err != nil || seen[reply.Server.Name] {
			continue
		}
		seen[reply.Server.Name] = true
		if slices.Contains(founders, reply.Server.Name) {
			peers.founders = append(peers.founders, reply.Server.Name)
		}
		group := reply.Data[account][metaGroup]
		if group.PIndex > 0 || group.Committed > 0 || group.EverHadLeader {
			peers.stateful = append(peers.stateful, reply.Server.Name)
		}
	}
}

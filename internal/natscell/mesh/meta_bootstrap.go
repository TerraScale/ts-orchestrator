package mesh

import (
	"context"
	"encoding/json"
	"log/slog"
	"slices"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

const (
	FounderRecord = "ts-orch-mesh-founder"
	foundingEvery = 5 * time.Second
)

type founding struct {
	Region  string `json:"region"`
	Cluster string `json:"cluster"`
	Formed  bool   `json:"formed"`
}

func (cfg config) candidate() bool { return cfg.founder && cfg.applier != nil }

func (cfg config) owns(record founding) bool {
	return record.Region == cfg.region && record.Cluster == cfg.cluster
}

func (cfg config) metaBootSize() int {
	if cfg.lone {
		return 1
	}
	return len(Regions(cfg.region))
}

func readFounding(ctx context.Context, records Records) (founding, int64, error) {
	value, version, err := records.Read(ctx, FounderRecord)
	if err != nil || version == 0 {
		return founding{}, version, err
	}
	var record founding
	if decodeStrict(value, &record) != nil || record.Region == "" || record.Cluster == "" {
		return founding{}, version, nil
	}
	return record, version, nil
}

func claimFounding(cfg config) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	if err := ensureOwnSeeds(ctx, cfg); err != nil {
		slog.Warn("mesh own seed record not published", "region", cfg.region, "error", err)
	}
	record, version, err := readFounding(ctx, cfg.records)
	if err == nil && version == 0 {
		if err = cfg.records.Create(ctx, FounderRecord, encodeRecord(founding{Region: cfg.region, Cluster: cfg.cluster})); err == nil {
			record, _, err = readFounding(ctx, cfg.records)
		}
	}
	if err != nil {
		slog.Warn("mesh founder record unavailable", "region", cfg.region, "error", err)
		return false
	}
	return cfg.owns(record) && !record.Formed
}

func (n *Node) staleFounding(ctx context.Context, record founding) (bool, error) {
	if record.Region == "" || !slices.Contains(Regions(n.cfg.region), record.Region) {
		return true, nil
	}
	if record.Region == n.cfg.region {
		return record.Cluster != n.cfg.cluster, nil
	}
	value, version, err := n.cfg.records.Read(ctx, SeedRecord(record.Region))
	if err != nil || version == 0 {
		return version == 0 && err == nil, err
	}
	seeds, _, err := parseSeeds(record.Region, value)
	return err != nil || seeds.Cluster != record.Cluster, nil
}

func (n *Node) found(meta server.RaftNode) bool {
	ctx, cancel := context.WithTimeout(n.ctx, time.Minute)
	defer cancel()
	stateful, err := n.metaPeers(ctx)
	if err != nil {
		slog.Warn("mesh JetStream metadata peers unavailable", "error", err)
		return false
	}
	if len(stateful) != 0 {
		return false
	}
	record, version, err := readFounding(ctx, n.cfg.records)
	if err != nil {
		slog.Warn("mesh founder record unavailable", "error", err)
		return false
	}
	ours := founding{Region: n.cfg.region, Cluster: n.cfg.cluster}
	if n.cfg.lone && n.cfg.owns(record) && !record.Formed {
		meta.SetObserver(false)
		slog.Info("mesh JetStream metadata forms a new group", "region", n.cfg.region, "cluster", n.cfg.cluster)
		return true
	}
	if version == 0 {
		err = n.cfg.records.Create(ctx, FounderRecord, encodeRecord(ours))
	} else if stale, staleErr := n.staleFounding(ctx, record); staleErr != nil || !stale {
		if staleErr != nil {
			slog.Warn("mesh founder record not checked", "founder", record.Region, "error", staleErr)
		}
		return false
	} else {
		slog.Warn("mesh founder record names a cell that no longer runs; replacing it", "founder", record.Region, "cluster", record.Cluster)
		err = n.cfg.records.Swap(ctx, FounderRecord, version, encodeRecord(ours))
	}
	if err != nil {
		slog.Warn("mesh founder record not claimed", "error", err)
		return false
	}
	if record, _, err = readFounding(ctx, n.cfg.records); err == nil && n.cfg.owns(record) {
		slog.Info("mesh founder record claimed; restarting to found the metadata group alone", "region", n.cfg.region)
		n.cfg.restart()
		return true
	}
	return false
}

func (n *Node) markFormed() {
	ctx, cancel := context.WithTimeout(n.ctx, time.Minute)
	defer cancel()
	value, version, err := n.cfg.records.Read(ctx, FounderRecord)
	var record founding
	if err == nil && version != 0 && decodeStrict(value, &record) == nil && n.cfg.owns(record) && !record.Formed {
		record.Formed = true
		err = n.cfg.records.Swap(ctx, FounderRecord, version, encodeRecord(record))
	}
	if err != nil {
		slog.Warn("mesh founder record not marked formed", "error", err)
	}
}

func (n *Node) formMeta() {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var checked time.Time
	formed := false
	for {
		if meta := n.metaNode(); meta != nil {
			switch {
			case formed || !meta.IsObserver():
				if meta.GroupLeader() != "" {
					if n.cfg.lone {
						n.markFormed()
					}
					return
				}
			case meta.HadPreviousLeader():
				meta.SetObserver(false)
				slog.Info("mesh JetStream metadata joined its group", "region", n.cfg.region, "leader", meta.GroupLeader())
				return
			case n.cfg.candidate() && time.Since(checked) >= foundingEvery:
				checked = time.Now()
				formed = n.found(meta)
				if formed && !n.cfg.lone {
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

func (n *Node) metaPeers(parent context.Context) ([]string, error) {
	ctx, cancel := context.WithTimeout(parent, time.Second)
	defer cancel()
	inbox := n.monitor.NewRespInbox()
	sub, err := n.monitor.SubscribeSync(inbox)
	if err != nil {
		return nil, err
	}
	defer sub.Unsubscribe()
	account := n.server.SystemAccount().Name
	payload, err := json.Marshal(server.RaftzOptions{AccountFilter: account, GroupFilter: metaGroup})
	if err != nil {
		return nil, err
	}
	if err := n.monitor.PublishRequest("$SYS.REQ.SERVER.PING.RAFTZ", inbox, payload); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var stateful []string
	for {
		message, err := sub.NextMsgWithContext(ctx)
		if err != nil {
			return stateful, parent.Err()
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
		group := reply.Data[account][metaGroup]
		if group.PIndex > 0 || group.Committed > 0 || group.EverHadLeader {
			stateful = append(stateful, reply.Server.Name)
		}
	}
}

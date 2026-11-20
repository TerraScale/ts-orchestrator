package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"slices"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

const (
	FounderRecord    = "ts-orch-mesh-founder"
	joinRecordPrefix = "ts-orch-join-"
	foundingEvery    = 5 * time.Second
)

type founding struct {
	Region  string            `json:"region"`
	Cluster string            `json:"cluster"`
	Formed  bool              `json:"formed"`
	Cells   map[string]string `json:"cells,omitempty"`
}

func JoinRecord(region string) string { return joinRecordPrefix + region }

func (record founding) members() map[string]string {
	if len(record.Cells) == 0 {
		return map[string]string{record.Region: record.Cluster}
	}
	return maps.Clone(record.Cells)
}

func (cfg config) candidate() bool { return cfg.founder && cfg.applier != nil && cfg.cluster != "" }

func (cfg config) owns(record founding) bool {
	return record.Region == cfg.region && record.Cluster == cfg.cluster
}

func (cfg config) cell() founding {
	return founding{Region: cfg.region, Cluster: cfg.cluster, Cells: map[string]string{cfg.region: cfg.cluster}}
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
	if err := decodeStrict(value, &record); err != nil {
		return founding{}, version, fmt.Errorf("%s is malformed: %w", FounderRecord, err)
	}
	if record.Region == "" || record.Cluster == "" || slices.Contains(slices.Collect(maps.Values(record.Cells)), "") {
		return founding{}, version, fmt.Errorf("%s names no cell: %s", FounderRecord, value)
	}
	return record, version, nil
}

func claimFounding(cfg config) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	record, version, err := readFounding(ctx, cfg.records)
	if err == nil && version == 0 {
		if err = peerCells(ctx, cfg, nil); err == nil {
			if err = cfg.records.Create(ctx, FounderRecord, encodeRecord(cfg.cell())); err == nil {
				record, _, err = readFounding(ctx, cfg.records)
			}
		}
	}
	if err != nil {
		slog.Info("mesh founder record not claimed before the mesh starts", "region", cfg.region, "reason", err)
	}
	if err := ensureOwnSeeds(ctx, cfg); err != nil {
		slog.Warn("mesh own seed record not published", "region", cfg.region, "error", err)
	}
	return err == nil && cfg.owns(record) && !record.Formed
}

func peerCells(ctx context.Context, cfg config, routed map[string]bool) error {
	for _, peer := range Regions(cfg.region) {
		if peer == cfg.region {
			continue
		}
		_, version, err := cfg.records.Read(ctx, SeedRecord(peer))
		if err != nil {
			return err
		}
		if version != 0 {
			if !routed[peer] {
				return fmt.Errorf("%s has a cell and no route reaches it", peer)
			}
			continue
		}
		joined, err := cfg.records.Exists(ctx, JoinRecord(peer))
		if err != nil {
			return err
		}
		if joined {
			return fmt.Errorf("%s has a cell that publishes no seed record", peer)
		}
	}
	return nil
}

func (n *Node) replaced(ctx context.Context, record founding) error {
	for region, cluster := range record.members() {
		if region == n.cfg.region {
			if cluster == n.cfg.cluster {
				return fmt.Errorf("cell %s of %s still runs here", cluster, region)
			}
			continue
		}
		value, version, err := n.cfg.records.Read(ctx, SeedRecord(region))
		if err != nil {
			return err
		}
		if version == 0 {
			return fmt.Errorf("%s is absent, so cell %s of %s is not known to be replaced", SeedRecord(region), cluster, region)
		}
		seeds, _, err := parseSeeds(region, value)
		if err != nil {
			return err
		}
		if seeds.Cluster == cluster {
			return fmt.Errorf("cell %s of %s still publishes its seeds", cluster, region)
		}
	}
	return nil
}

func (n *Node) routedRegions() map[string]bool {
	routed := map[string]bool{}
	for _, route := range n.routes() {
		routed[serverRegion(route.RemoteName)] = true
	}
	return routed
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
	if n.cfg.lone && n.cfg.owns(record) && !record.Formed {
		meta.SetObserver(false)
		slog.Info("mesh JetStream metadata forms a new group", "region", n.cfg.region, "cluster", n.cfg.cluster)
		return true
	}
	if version == 0 {
		if err := peerCells(ctx, n.cfg, n.routedRegions()); err != nil {
			slog.Info("mesh JetStream metadata not founded here", "region", n.cfg.region, "reason", err)
			return false
		}
		err = n.cfg.records.Create(ctx, FounderRecord, encodeRecord(n.cfg.cell()))
	} else if err := n.replaced(ctx, record); err != nil {
		slog.Info("mesh founder record kept", "founder", record.Region, "reason", err)
		return false
	} else {
		slog.Warn("mesh founder record names cells that were all replaced; replacing it", "founder", record.Region, "cells", record.members())
		err = n.cfg.records.Swap(ctx, FounderRecord, version, encodeRecord(n.cfg.cell()))
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

func (n *Node) enroll() error {
	if n.cfg.cluster == "" {
		return errors.New("this host has no SwarmKit cluster to enroll")
	}
	ctx, cancel := context.WithTimeout(n.ctx, time.Minute)
	defer cancel()
	record, version, err := readFounding(ctx, n.cfg.records)
	if err != nil {
		return err
	}
	switch {
	case version == 0:
		adopted := n.cfg.cell()
		adopted.Formed = true
		err = n.cfg.records.Create(ctx, FounderRecord, encodeRecord(adopted))
	case record.members()[n.cfg.region] == n.cfg.cluster:
		return nil
	default:
		record.Cells = record.members()
		record.Cells[n.cfg.region] = n.cfg.cluster
		err = n.cfg.records.Swap(ctx, FounderRecord, version, encodeRecord(record))
	}
	if err != nil {
		return err
	}
	if record, _, err = readFounding(ctx, n.cfg.records); err != nil || record.members()[n.cfg.region] != n.cfg.cluster {
		return errors.Join(err, fmt.Errorf("%s does not list cell %s of %s yet", FounderRecord, n.cfg.cluster, n.cfg.region))
	}
	slog.Info("mesh cell enrolled in the JetStream metadata group's founder record", "region", n.cfg.region, "cluster", n.cfg.cluster)
	return nil
}

func (n *Node) markFormed() error {
	ctx, cancel := context.WithTimeout(n.ctx, time.Minute)
	defer cancel()
	record, version, err := readFounding(ctx, n.cfg.records)
	if err != nil || !n.cfg.owns(record) || record.Formed {
		return err
	}
	record.Formed = true
	return n.cfg.records.Swap(ctx, FounderRecord, version, encodeRecord(record))
}

func (n *Node) formMeta() {
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	var checked time.Time
	formed := false
	settle := func() bool {
		if time.Since(checked) < foundingEvery {
			return false
		}
		checked = time.Now()
		if err := n.enroll(); err != nil {
			slog.Warn("mesh cell not enrolled in the founder record; it does not vote yet", "region", n.cfg.region, "error", err)
			return false
		}
		if !n.cfg.lone {
			return true
		}
		if err := n.markFormed(); err != nil {
			slog.Warn("mesh founder record not marked formed", "error", err)
			return false
		}
		return true
	}
	for {
		if meta := n.metaNode(); meta != nil {
			switch {
			case formed || !meta.IsObserver():
				if meta.GroupLeader() != "" && settle() {
					return
				}
			case meta.HadPreviousLeader():
				if settle() {
					meta.SetObserver(false)
					slog.Info("mesh JetStream metadata joined its group", "region", n.cfg.region, "leader", meta.GroupLeader())
					return
				}
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
	expected := map[string]bool{serverName(n.cfg): true}
	for _, route := range n.routes() {
		expected[route.RemoteName] = true
	}
	seen := map[string]bool{}
	var stateful []string
	for {
		if !slices.ContainsFunc(slices.Collect(maps.Keys(expected)), func(name string) bool { return !seen[name] }) {
			return stateful, nil
		}
		message, err := sub.NextMsgWithContext(ctx)
		if err != nil {
			if len(stateful) != 0 {
				return stateful, nil
			}
			return nil, errors.Join(parent.Err(), fmt.Errorf("routed servers did not all answer for metadata state: %d of %d", len(seen), len(expected)))
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

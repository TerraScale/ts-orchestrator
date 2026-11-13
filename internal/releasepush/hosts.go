package releasepush

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go"
)

type Refusal struct {
	SHA    string `json:"sha"`
	Reason string `json:"reason"`
}

type HostVersion struct {
	Host    string   `json:"host"`
	Version string   `json:"version,omitempty"`
	Refusal *Refusal `json:"refusal,omitempty"`
	Error   string   `json:"error,omitempty"`
}

func (h *Handler) ServeHostVersion(conn *nats.Conn, region, host string) error {
	return h.serve(conn, map[string]func(context.Context, []byte) Reply{
		hostVersionSubject(region, host): func(context.Context, []byte) Reply { return h.version() },
	})
}

func hostVersionSubject(region, host string) string {
	return protocol.ReleaseVersion + "." + region + "." + host
}

func ReadHostVersions(ctx context.Context, conn *nats.Conn, region string, nodes []*api.Node) []HostVersion {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	rows := make([]HostVersion, len(nodes))
	var pending sync.WaitGroup
	for i, node := range nodes {
		name := node.ID
		if node.Description != nil && node.Description.Hostname != "" {
			name = node.Description.Hostname
		}
		rows[i].Host = name
		pending.Go(func() {
			if name == "" || strings.ContainsAny(name, " *>\t\r\n") {
				rows[i].Error = "registered host has no valid hostname"
				return
			}
			reply, err := request(ctx, conn, hostVersionSubject(region, name), nil, 2*time.Second)
			if err != nil {
				rows[i].Error = "host reports no running revision"
				return
			}
			rows[i].Version, rows[i].Refusal = reply.Version, reply.Refusal
		})
	}
	pending.Wait()
	slices.SortFunc(rows, func(a, b HostVersion) int { return strings.Compare(a.Host, b.Host) })
	return rows
}

func (h *Handler) reportVersion(ctx context.Context, _ []byte) Reply {
	reply := h.version()
	if h.HostVersions == nil {
		reply.Error = "regional host revision inventory unavailable"
		return reply
	}
	var err error
	reply.Hosts, err = h.HostVersions(ctx)
	if err != nil {
		reply.Error = fmt.Sprintf("regional host revision inventory: %s", err)
	}
	return reply
}

func CheckHostVersions(hosts []HostVersion, sha string) error {
	if len(hosts) == 0 {
		return errors.New("region reports no registered hosts")
	}
	var failures error
	for _, host := range hosts {
		if host.Version == sha && host.Error == "" {
			continue
		}
		reason := fmt.Sprintf("reports revision %q, want %s", host.Version, sha)
		if host.Error != "" {
			reason = host.Error
		}
		if host.Refusal != nil && host.Refusal.SHA == sha {
			reason += "; refused: " + host.Refusal.Reason
		}
		failures = errors.Join(failures, fmt.Errorf("host %s not updated: %s", host.Host, reason))
	}
	return failures
}

func AwaitHostVersions(ctx context.Context, conn *nats.Conn, sha string) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Minute)
	defer cancel()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	known := map[string]HostVersion{}
	last := errors.New("regional host revision inventory unavailable")
	for {
		reply, err := request(ctx, conn, SubjectVersion, nil, 8*time.Second)
		if err == nil {
			current := map[string]HostVersion{}
			for _, host := range reply.Hosts {
				current[host.Host] = host
			}
			for host := range known {
				if _, ok := current[host]; !ok {
					current[host] = HostVersion{Host: host, Error: "host reports no running revision"}
				}
			}
			known = current
			rows := make([]HostVersion, 0, len(known))
			for _, row := range known {
				rows = append(rows, row)
			}
			slices.SortFunc(rows, func(a, b HostVersion) int { return strings.Compare(a.Host, b.Host) })
			last = CheckHostVersions(rows, sha)
			if reply.RolledBack == sha {
				return errors.Join(last, fmt.Errorf("region rolled back to %s: %s", reply.Version, reply.Error))
			}
			if last == nil && reply.Version == sha && reply.Error == "" && ctx.Err() == nil {
				return nil
			}
			if reply.Version != sha {
				last = errors.Join(last, fmt.Errorf("region revision %s, want %s", reply.Version, sha))
			}
			if reply.Error != "" {
				last = errors.Join(last, errors.New(reply.Error))
			}
		}
		select {
		case <-ctx.Done():
			return fmt.Errorf("region did not update every registered host to %s: %w", sha, errors.Join(ctx.Err(), last))
		case <-tick.C:
		}
	}
}

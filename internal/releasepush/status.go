package releasepush

import (
	"context"
	"errors"
	"github.com/TerraScale/ts-orchestrator/internal/secretpreflight"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go"
)

type Refusal struct {
	SHA        string `json:"sha"`
	RunID      string `json:"run_id"`
	RunAttempt string `json:"run_attempt"`
	Reason     string `json:"reason,omitempty"`
}

type HostVersion struct {
	ID      string   `json:"id"`
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
		rows[i].ID = node.ID
		pending.Go(func() {
			if node.ID == "" || strings.ContainsAny(node.ID, " *>\t\r\n") {
				rows[i].Error = "registered host has no valid node id"
				return
			}
			reply, err := request(ctx, conn, hostVersionSubject(region, node.ID), nil, 2*time.Second)
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

func (h *Handler) recordAttempt(attempt *Refusal) error {
	attempt.Reason = secretpreflight.Scrub(attempt.Reason)
	h.attempt.Store(attempt)
	if h.RefusalFile != "" {
		if err := writeJSON(h.RefusalFile, attempt); err != nil {
			return errors.New("cannot persist release attempt")
		}
	}
	return nil
}

func (h *Handler) refusal() *Refusal {
	attempt := h.attempt.Load()
	if attempt == nil || attempt.Reason == "" {
		return nil
	}
	return attempt
}

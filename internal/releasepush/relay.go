package releasepush

import (
	"context"
	"encoding/json"
	"strings"
	"time"

	"github.com/moby/swarmkit/v2/api"
	"github.com/nats-io/nats.go"
)

const WorkerReplyWait = 90 * time.Second

func RelayWorkers(ctx context.Context, conn *nats.Conn, subject string, data []byte, nodes []*api.Node) []HostVersion {
	ctx, cancel := context.WithTimeout(ctx, WorkerReplyWait)
	defer cancel()
	var release OrchRelease
	if json.Unmarshal(data, &release) != nil {
		return nil
	}
	rows := []HostVersion{}
	pending := map[string]int{}
	for _, node := range nodes {
		if node.Role != api.NodeRoleWorker {
			continue
		}
		name := node.ID
		if node.Description != nil && node.Description.Hostname != "" {
			name = node.Description.Hostname
		}
		pending[node.ID] = len(rows)
		rows = append(rows, HostVersion{ID: node.ID, Host: scrub(name), Error: "no answer"})
	}
	if nodes == nil {
		rows = append(rows, HostVersion{Host: "worker inventory", Error: "no answer"})
	}
	inbox := nats.NewInbox()
	sub, err := conn.SubscribeSync(inbox)
	if err != nil {
		return rows
	}
	defer sub.Unsubscribe()
	if conn.Flush() != nil || conn.PublishRequest(subject, inbox, data) != nil || conn.Flush() != nil {
		return rows
	}
	answered := map[string]bool{}
	for len(pending) != 0 || nodes == nil {
		message, err := sub.NextMsgWithContext(ctx)
		if err != nil {
			break
		}
		var reply Reply
		if json.Unmarshal(message.Data, &reply) != nil || reply.Host == "" {
			continue
		}
		index, known := pending[reply.Host]
		if answered[reply.Host] {
			continue
		}
		if !known {
			if (reply.Refusal == nil || reply.Refusal.SHA != release.SHA || reply.Refusal.Reason == "") && (reply.State == "installed" || reply.State == "current" || reply.Error == "") {
				continue
			}
			index = len(rows)
			rows = append(rows, HostVersion{ID: reply.Host, Host: scrub(reply.Host)})
		}
		if reply.Refusal != nil && reply.Refusal.SHA == release.SHA && reply.Refusal.Reason != "" {
			refusal := *reply.Refusal
			refusal.Reason = scrub(refusal.Reason)
			rows[index].Refusal = &refusal
		} else if reply.State != "installed" && reply.State != "current" && reply.Error != "" {
			rows[index].Refusal = &Refusal{SHA: release.SHA, Reason: scrub(reply.Error)}
		} else if reply.State != "installed" && reply.State != "current" {
			continue
		}
		rows[index].Error = ""
		rows[index].Version = reply.Version
		delete(pending, reply.Host)
		answered[reply.Host] = true
	}
	return rows
}

func RefusedOn(rows []HostVersion) string {
	names := []string{}
	for _, row := range rows {
		if row.Refusal != nil {
			names = append(names, row.Host)
		}
	}
	if len(names) == 0 {
		return ""
	}
	return "refused on " + strings.Join(names, ", ")
}

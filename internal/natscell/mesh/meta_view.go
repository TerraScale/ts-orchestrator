package mesh

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
)

const metaViewWindow = time.Second

type MetaView struct {
	Server  string       `json:"server"`
	Region  string       `json:"region"`
	Members []MetaMember `json:"members,omitempty"`
	Error   string       `json:"error,omitempty"`
}

type MetaMember struct {
	Server    string                        `json:"server"`
	ID        string                        `json:"id"`
	State     string                        `json:"state"`
	Leader    string                        `json:"leader,omitempty"`
	Term      uint64                        `json:"term"`
	Size      int                           `json:"size"`
	Quorum    int                           `json:"quorum"`
	Observer  bool                          `json:"observer,omitempty"`
	Committed uint64                        `json:"committed"`
	Applied   uint64                        `json:"applied"`
	Peers     []MetaPeer                    `json:"peers"`
	Change    *server.RaftzMembershipChange `json:"membership_change,omitempty"`
}

type MetaPeer struct {
	ID         string `json:"id"`
	Name       string `json:"name,omitempty"`
	Known      bool   `json:"known"`
	LastSeen   string `json:"last_seen,omitempty"`
	Replicated uint64 `json:"replicated,omitempty"`
}

func metaMember(name string, group server.RaftzGroup) MetaMember {
	member := MetaMember{Server: name, ID: group.ID, State: group.State, Leader: group.Leader, Term: group.Term, Size: group.Size,
		Quorum: group.QuorumNeeded, Observer: group.Observer, Committed: group.Committed, Applied: group.Applied, Peers: []MetaPeer{}, Change: group.Change}
	for id, peer := range group.Peers {
		member.Peers = append(member.Peers, MetaPeer{ID: id, Name: peer.Name, Known: peer.Known, LastSeen: peer.LastSeen, Replicated: peer.LastReplicatedIndex})
	}
	slices.SortFunc(member.Peers, func(a, b MetaPeer) int { return cmp.Compare(a.ID, b.ID) })
	return member
}

func (n *FabricLifecycle) metaMembers(parent context.Context) ([]MetaMember, error) {
	if n.monitor == nil {
		return nil, errors.New("this host runs no JetStream")
	}
	ctx, cancel := context.WithTimeout(parent, metaViewWindow)
	defer cancel()
	account := n.server.SystemAccount().Name
	payload, err := json.Marshal(server.RaftzOptions{AccountFilter: account, GroupFilter: metaGroup})
	if err != nil {
		return nil, err
	}
	inbox := n.monitor.NewRespInbox()
	sub, err := n.monitor.SubscribeSync(inbox)
	if err != nil {
		return nil, err
	}
	defer sub.Unsubscribe()
	if err := n.monitor.PublishRequest("$SYS.REQ.SERVER.PING.RAFTZ", inbox, payload); err != nil {
		return nil, err
	}
	members := map[string]MetaMember{}
	for {
		message, err := sub.NextMsgWithContext(ctx)
		if err != nil {
			break
		}
		var reply struct {
			Server struct {
				Name string `json:"name"`
			} `json:"server"`
			Data server.RaftzStatus `json:"data"`
		}
		if err := json.Unmarshal(message.Data, &reply); err != nil {
			return nil, err
		}
		if group, ok := reply.Data[account][metaGroup]; ok {
			members[reply.Server.Name] = metaMember(reply.Server.Name, group)
		}
	}
	if err := parent.Err(); err != nil {
		return nil, err
	}
	return slices.SortedFunc(maps.Values(members), func(a, b MetaMember) int { return cmp.Compare(a.Server, b.Server) }), nil
}

func (n *Node) serveMetaView(m *nats.Msg) {
	view := MetaView{Server: n.cfg.server, Region: n.cfg.region}
	members, err := n.lifecycle.metaMembers(n.ctx)
	if err != nil {
		view.Error = err.Error()
	}
	view.Members = members
	n.respond(m, view)
}

func metaSubject(server string) string { return protocol.MeshMetaPrefix + server }

func Meta(ctx context.Context, conn *nats.Conn, asJSON bool, output io.Writer) error {
	host, err := os.Hostname()
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	message, err := conn.RequestWithContext(ctx, metaSubject(host), nil)
	if err != nil {
		return fmt.Errorf("mesh metadata view from %s: %w", host, err)
	}
	var view MetaView
	if err := protocol.DecodeStrict(message.Data, &view, maxWire); err != nil {
		return err
	}
	if asJSON {
		_, err = output.Write(append(message.Data, '\n'))
	} else {
		err = printMeta(view, output)
	}
	if view.Error != "" {
		return errors.Join(err, fmt.Errorf("%s: %s", view.Server, view.Error))
	}
	return err
}

func printMeta(view MetaView, output io.Writer) error {
	names := map[string]string{}
	for _, member := range view.Members {
		names[member.ID] = member.Server
		for _, peer := range member.Peers {
			if peer.Name != "" {
				names[peer.ID] = peer.Name
			}
		}
	}
	label := func(id string) string {
		if name := names[id]; name != "" {
			return name
		}
		return "?"
	}
	fmt.Fprintf(output, "%s metadata group, as each JetStream server that answered %s in %s sees it\n", metaGroup, view.Server, view.Region)
	table := tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
	fmt.Fprintln(table, "SERVER\tID\tSTATE\tTERM\tLEADER\tSIZE\tQUORUM\tCOMMITTED\tAPPLIED\tPEERS")
	for _, member := range view.Members {
		ids := []string{member.ID}
		for _, peer := range member.Peers {
			ids = append(ids, peer.ID)
		}
		slices.Sort(ids)
		state := member.State
		if member.Observer {
			state += "/observer"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\t%d\t%s\t%d\t%d\t%d\t%d\t%s\n", member.Server, member.ID, state, member.Term, label(member.Leader),
			member.Size, member.Quorum, member.Committed, member.Applied, strings.Join(ids, ","))
	}
	if err := table.Flush(); err != nil {
		return err
	}
	for _, member := range view.Members {
		if change := member.Change; change != nil {
			operation := "adding"
			if change.Removing {
				operation = "removing"
			}
			fmt.Fprintf(output, "%s has not committed %s %s (%s) at index %d\n", member.Server, operation, label(change.Peer), change.Peer, change.Index)
		}
	}
	for _, member := range view.Members {
		if member.State != "LEADER" {
			continue
		}
		fmt.Fprintf(output, "\npeers of leader %s (%s), term %d, committed %d\n", member.Server, member.ID, member.Term, member.Committed)
		table = tabwriter.NewWriter(output, 0, 0, 2, ' ', 0)
		fmt.Fprintln(table, "ID\tNAME\tKNOWN\tLAST SEEN\tREPLICATED")
		for _, peer := range member.Peers {
			seen := peer.LastSeen
			if seen == "" {
				seen = "never"
			}
			fmt.Fprintf(table, "%s\t%s\t%t\t%s\t%d\n", peer.ID, label(peer.ID), peer.Known, seen, peer.Replicated)
		}
		if err := table.Flush(); err != nil {
			return err
		}
	}
	return nil
}

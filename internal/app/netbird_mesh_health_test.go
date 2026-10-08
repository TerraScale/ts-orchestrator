package app

import (
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/host"
	network "git.terrascale.tech/TerraScale/ts-orchestrator/internal/netbird/rollout"
)

type netbirdMeshHosts struct {
	roles   []string
	desired []host.Desired
}

func (h netbirdMeshHosts) ListHosts(context.Context) ([]host.HostStatus, error) {
	status := host.HostStatus{Registration: host.Registration{Node: "joining-node", Roles: h.roles}}
	for _, desired := range h.desired {
		status.Reports = append(status.Reports, host.Report{Node: desired.Node, Role: desired.Role,
			Generation: desired.Generation, State: "running", ObservedAt: time.Now()})
	}
	return []host.HostStatus{status}, nil
}

func (h netbirdMeshHosts) ListDesired(_ context.Context, role string) ([]host.Desired, error) {
	var desired []host.Desired
	for _, entry := range h.desired {
		if entry.Role == role {
			desired = append(desired, entry)
		}
	}
	return desired, nil
}

func TestNetBirdMeshConfirmationRequiresSelectedIPTraffic(t *testing.T) {
	// DNS and ready host reports can succeed while the selected peer tunnel
	// carries no traffic. Keep the real health path and provide only DNS.
	netbirdMeshDNS(t, [4]byte{10, 200, 1, 2})
	for _, test := range []struct {
		name  string
		hosts netbirdMeshHosts
	}{
		{name: "no roles"},
		{name: "all roles withdrawn", hosts: netbirdMeshHosts{
			roles: []string{"terrabase", "ts-auth"},
			desired: []host.Desired{
				{Node: "joining-node", Role: "terrabase", Generation: 1, Withdrawn: true},
				{Node: "joining-node", Role: "ts-auth", Generation: 1, Withdrawn: true},
			},
		}},
		{name: "unsupported active role", hosts: netbirdMeshHosts{
			roles:   []string{"worker"},
			desired: []host.Desired{{Node: "joining-node", Role: "worker", Generation: 1}},
		}},
	} {
		t.Run(test.name, func(t *testing.T) {
			r := netbirdRollout{fence: &releaseFence{hosts: test.hosts,
				spec: func() (*cellspec.ReleaseFence, map[string]string) {
					return &cellspec.ReleaseFence{}, map[string]string{}
				}}}
			status := network.Status{Connected: true, IP: "10.200.1.2", DNS: "joining-node.nb.ts.internal"}
			if err := r.healthy(t.Context(), "joining-node", status, time.Time{}); err == nil || !strings.Contains(err.Error(), "no active service endpoint") {
				t.Fatalf("management, DNS and host reports confirmed an unprobed mesh IP: %v", err)
			}
		})
	}
}

func netbirdMeshDNS(t *testing.T, address [4]byte) {
	t.Helper()
	listener, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		packet := make([]byte, 4096)
		for {
			size, peer, err := listener.ReadFrom(packet)
			if err != nil {
				return
			}
			var question dnsmessage.Message
			if err := question.Unpack(packet[:size]); err != nil || len(question.Questions) != 1 {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: question.ID, Response: true,
				Authoritative: true, RecursionAvailable: true}, Questions: question.Questions}
			if query := question.Questions[0]; query.Type == dnsmessage.TypeA {
				response.Answers = []dnsmessage.Resource{{Header: dnsmessage.ResourceHeader{
					Name: query.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1},
					Body: &dnsmessage.AResource{A: address}}}
			}
			wire, err := response.Pack()
			if err == nil {
				_, _ = listener.WriteTo(wire, peer)
			}
		}
	}()
	previous := net.DefaultResolver
	net.DefaultResolver = &net.Resolver{PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, "udp", listener.LocalAddr().String())
		}}
	t.Cleanup(func() {
		net.DefaultResolver = previous
		_ = listener.Close()
		<-done
	})
}

//go:build linux

package app

import (
	"context"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/hostenroll"
	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
)

func TestNativeMaintenanceRejectsSameSessionOwnhostReplacement(t *testing.T) {
	for _, replacement := range []string{"agent", "request", "response", "session", "ended session"} {
		t.Run(replacement, func(t *testing.T) {
			session, cancel := context.WithCancel(t.Context())
			defer cancel()
			agent := new(host.Agent)
			transport := hostenroll.WorkerTransport{Request: []byte("original request"), Response: []byte("original response")}
			ownhost := new(managedRuntimeHost)
			ownhost.bind(session, agent, transport, nil, "")
			proof := &rootNativeMaintenanceSource{ownhost: ownhost, observation: &rootReleaseObservation{b: new(rootReleaseChannels)},
				origin: new(swarmruntime.ManagerRuntimeCandidate), generation: ownhost.generation,
				agent: agent, session: session, request: []byte("original request"), response: []byte("original response")}
			if !proof.matchesOwnhostLocked() {
				t.Fatal("unchanged ownhost pins rejected")
			}
			switch replacement {
			case "agent":
				agent = new(host.Agent)
			case "request":
				transport.Request = []byte("replacement request")
			case "response":
				transport.Response = []byte("replacement response")
			case "session":
				session, cancel = context.WithCancel(t.Context())
				defer cancel()
			case "ended session":
				cancel()
			}
			ownhost.bind(session, agent, transport, nil, "")
			if replacement != "session" && ownhost.generation != proof.generation {
				t.Fatal("test did not exercise the same session generation")
			}
			if proof.matchesOwnhostLocked() {
				t.Fatal("original ownhost pins accepted replacement", replacement)
			}
		})
	}
}

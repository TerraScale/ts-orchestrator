package edge

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"slices"
	"strconv"
	"sync"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

func (e *Edge) SetInventoryFollower() {
	e.follower.Store(true)
	e.inventoryMissing.Store(true)
}

func (e *Edge) JoinMesh(node *mesh.Node) {
	peers, changed := node.EdgePeers(e.ReadyServices, e.peerAdvertised)
	e.readyChanged.Store(&changed)
	e.SetPeerEdges(peers)
	e.SetRegionalNodes(node.RegionalNodes)
	e.SetMesh(node)
}

func (e *Edge) FollowInventory(ctx context.Context, inventory func() (mesh.EdgeInventory, bool), proof func(context.Context, string) error) {
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	var nextProof time.Time
	proofRef := ""
	for {
		current, ok := inventory()
		e.inventoryMissing.Store(!ok)
		if !ok {
			e.SetServiceRoutes(map[string]int{}, map[string]int{}, map[string]string{}, nil)
			e.SetReadinessRoutes(nil)
		} else {
			if time.Now().After(nextProof) || current.ProofRef != proofRef {
				proofRef = current.ProofRef
				proofCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
				if err := proof(proofCtx, current.ProofRef); err != nil {
					slog.WarnContext(ctx, "edge request proof credential unavailable", "error", err)
				}
				cancel()
				nextProof = time.Now().Add(time.Minute)
			}
			routes := make([]ReadinessRoute, 0, len(current.Readiness))
			for _, route := range current.Readiness {
				routes = append(routes, ReadinessRoute{Host: route.Host, Port: route.Port, Path: route.Path})
			}
			e.SetServiceRoutes(current.Web, current.Postgres, current.Services, localReadyServices(ctx, routes, current.Services))
			e.SetReadinessRoutes(routes)
		}
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
		}
	}
}

func probeLocal(ctx context.Context, route ReadinessRoute) bool {
	probeCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(probeCtx, http.MethodGet, "http://"+net.JoinHostPort("127.0.0.1", strconv.Itoa(route.Port))+route.Path, nil)
	if err != nil {
		return false
	}
	request.Host = route.Host
	transport := &http.Transport{Proxy: nil, DialContext: (&net.Dialer{Timeout: time.Second}).DialContext, DisableKeepAlives: true, MaxResponseHeaderBytes: 8 << 10}
	defer transport.CloseIdleConnections()
	response, err := (&http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(request)
	if err != nil {
		return false
	}
	response.Body.Close()
	return response.StatusCode == http.StatusOK
}

func localReadyServices(ctx context.Context, routes []ReadinessRoute, services map[string]string) []string {
	var mu sync.Mutex
	ready := []string{}
	var probes sync.WaitGroup
	for _, route := range routes {
		service := services[route.Host]
		if service == "" {
			continue
		}
		probes.Go(func() {
			if probeLocal(ctx, route) {
				mu.Lock()
				ready = append(ready, service)
				mu.Unlock()
			}
		})
	}
	probes.Wait()
	slices.Sort(ready)
	return slices.Compact(ready)
}

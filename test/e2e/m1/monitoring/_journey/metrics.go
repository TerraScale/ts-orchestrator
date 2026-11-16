package mesh

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nats-server/v2/server"
)

func JourneyMonitoring(ctx context.Context, state string) error {
	ca, err := DeriveCA([]byte(strings.Repeat("j", 32)))
	if err != nil {
		return err
	}
	node, err := start(config{region: "sjc", server: "monitoring-journey", nodeID: strings.Repeat("a", 25), founder: true,
		dir: filepath.Join(state, "mesh"), ca: ca, terrabaseToken: strings.Repeat("t", 32),
		clusterHost: "127.0.0.1", clusterPort: 16222, localPort: 14222,
		peersDir: filepath.Join(state, "peers"), every: time.Second, peersEvery: time.Second,
		address: func() (string, error) { return "127.0.0.1", nil }})
	if err != nil {
		return err
	}
	defer node.ForceClose()
	go node.servePeerMetrics(ctx)
	<-ctx.Done()
	return nil
}

func JourneyAlertBudget(ctx context.Context, state, region, address string, peers []string) error {
	cfg := config{region: region, server: "budget", dir: state, terrabaseToken: strings.Repeat("t", 32), clusterHost: address, clusterAdvertise: address, clusterPort: 16223, localPort: LocalPort}
	for _, peer := range peers {
		cfg.routes = append(cfg.routes, "nats://"+peer+":16223")
	}
	orch, err := randomHex()
	if err != nil {
		return err
	}
	alerts, err := persistentToken(state, "alerts.token")
	if err != nil {
		return err
	}
	options, err := serverOptions(cfg, nil, orch, orch, alerts, orch, newInRegionGossip(cfg.region, time.Now()))
	if err != nil {
		return err
	}
	options.Host, options.Cluster.TLSConfig = address, nil
	options.JetStream, options.StoreDir, options.JetStreamUniqueTag = true, filepath.Join(state, "jetstream"), regionTag
	embedded, err := server.NewServer(options)
	if err != nil {
		return err
	}
	options.CustomClientAuthentication.(*clientAuth).server = embedded
	go embedded.Start()
	defer embedded.WaitForShutdown()
	defer embedded.Shutdown()
	if !embedded.ReadyForConnections(10 * time.Second) {
		return errors.New("alert budget server did not start")
	}
	<-ctx.Done()
	return nil
}

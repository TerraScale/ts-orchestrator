package mesh

import (
	"context"
	"path/filepath"
	"strings"
	"time"
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

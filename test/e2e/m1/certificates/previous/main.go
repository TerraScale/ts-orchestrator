package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type meshPeer struct{ config *tls.Config }

func (m meshPeer) Region() string                { return "gru" }
func (m meshPeer) TLS() *tls.Config              { return m.config }
func (m meshPeer) RTT() map[string]time.Duration { return nil }
func (m meshPeer) AdmittedRegions() []string     { return mesh.Regions() }

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer cancel()
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var cfg struct{ Work string }
	if err = json.Unmarshal(data, &cfg); err != nil {
		panic(err)
	}
	ca, err := mesh.DeriveCA([]byte(strings.Repeat("certificate-journey", 2)))
	if err != nil {
		panic(err)
	}
	e := edge.New(cfg.Work + "/previous")
	e.SetRoutes(map[string]int{"shared.e2e.test": 8080}, nil)
	e.SetMesh(meshPeer{ca.TLS("journey." + mesh.Domain)})
	go e.Run(ctx)
	for {
		var b strings.Builder
		observability.WriteEdgeListenerMetrics(&b)
		if strings.Count(b.String(), " 1\n") == 4 {
			break
		}
		if ctx.Err() != nil {
			return
		}
		runtime.Gosched()
	}
	fmt.Println("READY previous")
	<-ctx.Done()
}

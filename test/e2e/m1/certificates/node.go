package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

type meshPeer struct {
	region string
	config *tls.Config
}

func (m meshPeer) Region() string                { return m.region }
func (m meshPeer) TLS() *tls.Config              { return m.config }
func (m meshPeer) RTT() map[string]time.Duration { return nil }
func (m meshPeer) AdmittedRegions() []string     { return mesh.Regions() }

func nodeMain(ctx context.Context, cfg configuration) error {
	ca, err := mesh.DeriveCA([]byte(strings.Repeat("certificate-journey", 2)))
	if err != nil {
		return err
	}
	e := edge.New(cfg.Work + "/" + os.Args[3])
	e.SetRoutes(map[string]int{"shared.e2e.test": 8080}, nil)
	e.SetMesh(meshPeer{os.Args[4], ca.TLS("journey." + mesh.Domain)})
	e.SetReadinessRoutes([]edge.ReadinessRoute{{Host: "shared.e2e.test", Port: 8080, Path: "/readyz"}})
	backend, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		return err
	}
	backendServer := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) })}
	go backendServer.Serve(backend)
	defer backendServer.Close()
	listener, err := net.Listen("tcp", ":9108")
	if err != nil {
		return err
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/edge/certificates", edge.ServeLocal)
	mux.HandleFunc("/edge/ready", edge.ServeLocal)
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) { e.WriteCertificateMetrics(r.Context(), w) })
	server := &http.Server{Handler: mux}
	go server.Serve(listener)
	defer server.Close()
	go e.Run(ctx)
	for {
		var b strings.Builder
		observability.WriteEdgeListenerMetrics(&b)
		if strings.Count(b.String(), " 1\n") == 4 {
			break
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		runtime.Gosched()
	}
	fmt.Println("READY node")
	<-ctx.Done()
	return nil
}

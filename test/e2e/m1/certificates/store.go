package main

import (
	"context"
	"encoding/hex"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

func storeMain(ctx context.Context, cfg configuration) error {
	seed, err := hex.DecodeString(cfg.MeshSeed)
	if err != nil {
		return err
	}
	ca, err := mesh.DeriveCA(seed)
	clear(seed)
	if err != nil {
		return err
	}
	addresses := []string{"10.77.0.1", "10.77.0.4", "10.77.0.5"}
	var routes []*url.URL
	for _, address := range addresses {
		route, err := url.Parse("nats://" + net.JoinHostPort(address, strconv.Itoa(mesh.ClusterPort)))
		if err != nil {
			return err
		}
		routes = append(routes, route)
	}
	var nodes []*server.Server
	reads := &storeReads{}
	control := &http.Server{Addr: "10.77.0.1:8090", Handler: reads}
	go func() { _ = control.ListenAndServe() }()
	defer control.Close()
	defer func() {
		for _, node := range nodes {
			node.Shutdown()
		}
		for _, node := range nodes {
			node.WaitForShutdown()
		}
	}()
	for i, address := range addresses {
		options := &server.Options{}
		if err := options.ProcessConfigString("accounts {\n $SYS { users: [{user:sys, password:journey}] }\n ORCH { jetstream: {max_memory:1M, max_file:64M, max_streams:3, max_consumers:64}, users: [{user:orch,password:journey}] }\n TERRABASE { jetstream: {max_memory:1M,max_file:1M,max_streams:1} }\n }\nsystem_account:'$SYS'"); err != nil {
			return err
		}
		options.Host, options.Port, options.NoSigs = address, mesh.LocalPort, true
		options.ServerName = fmt.Sprintf("store-%d", i)
		options.JetStream, options.StoreDir = true, filepath.Join(cfg.Work, options.ServerName)
		options.SyncAlways = true
		options.JetStreamUniqueTag = "region:"
		options.Tags.Add(fmt.Sprintf("region:store-%d", i))
		options.Routes = routes
		options.Cluster = server.ClusterOpts{Name: mesh.ClusterName, Host: address, Port: mesh.ClusterPort, TLSConfig: ca.TLS(options.ServerName), TLSTimeout: 5, PinnedAccounts: []string{mesh.FabricAccount}}
		node, err := server.NewServer(options)
		if err != nil {
			return err
		}
		node.SetLogger(reads, false, true)
		nodes = append(nodes, node)
		go node.Start()
		if !node.ReadyForConnections(5 * time.Second) {
			return fmt.Errorf("store listener unavailable")
		}
	}
	conn, err := nats.Connect(nodes[0].ClientURL(), nats.UserInfo("sys", "journey"))
	if err != nil {
		return err
	}
	defer conn.Close()
	events, err := conn.SubscribeSync("$SYS.SERVER.*.STATSZ")
	if err != nil {
		return err
	}
	defer events.Unsubscribe()
	if err := conn.Flush(); err != nil {
		return err
	}
	bounded, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
ready:
	for {
		for _, node := range nodes {
			if len(node.JetStreamClusterPeers()) == 3 {
				break ready
			}
		}
		if _, err := events.NextMsgWithContext(bounded); err != nil {
			return err
		}
	}
	app, err := nats.Connect(nodes[0].ClientURL(), nats.UserInfo("orch", "journey"))
	if err != nil {
		return err
	}
	defer app.Close()
	js, err := jetstream.New(app)
	if err != nil {
		return err
	}
	for _, config := range []jetstream.KeyValueConfig{
		{Bucket: "edge-certs", Replicas: 3, History: 1, MaxBytes: 16 << 20, MaxValueSize: 64 << 10},
		{Bucket: "edge-cert-tokens", Replicas: 3, History: 1, TTL: 10 * time.Minute, MaxBytes: 1 << 20},
	} {
		if _, err := js.CreateKeyValue(bounded, config); err != nil {
			return err
		}
	}
	fmt.Println("READY store")
	<-ctx.Done()
	return nil
}

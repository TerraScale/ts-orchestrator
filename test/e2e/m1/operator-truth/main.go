package main

import (
	"context"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/regionhealth"
	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

type routeLog struct{ subscriptions chan struct{} }

func (l routeLog) Noticef(string, ...any) {}
func (l routeLog) Warnf(string, ...any)   {}
func (l routeLog) Errorf(string, ...any)  {}
func (l routeLog) Fatalf(f string, args ...any) {
	panic(fmt.Sprintf(f, args...))
}
func (l routeLog) Debugf(string, ...any) {}
func (l routeLog) Tracef(f string, args ...any) {
	line := fmt.Sprintf(f, args...)
	if strings.Contains(line, "<<- [RS+") && strings.Contains(line, protocol.MeshHealthSubject) {
		l.subscriptions <- struct{}{}
	}
}

func run() error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	var servers []*server.Server
	var conns []*nats.Conn
	defer func() {
		for _, conn := range conns {
			conn.Close()
		}
		for _, node := range servers {
			node.Shutdown()
			node.WaitForShutdown()
		}
	}()
	subscriptions := make(chan struct{}, 64)
	var routes []*url.URL
	for _, region := range mesh.Regions() {
		node, err := server.NewServer(&server.Options{ServerName: region, Host: "127.0.0.1", Port: -1,
			Cluster: server.ClusterOpts{Name: mesh.ClusterName, Host: "127.0.0.1", Port: -1, PoolSize: -1},
			Routes:  routes, NoSigs: true, NoLog: true})
		if err != nil {
			return err
		}
		servers = append(servers, node)
		node.SetLogger(routeLog{subscriptions}, false, true)
		go node.Start()
		if !node.ReadyForConnections(5 * time.Second) {
			return fmt.Errorf("%s did not listen", region)
		}
		route, err := url.Parse("nats://" + node.ClusterAddr().String())
		if err != nil {
			return err
		}
		routes = append(routes, route)
		conn, err := nats.Connect(node.ClientURL())
		if err != nil {
			return err
		}
		conns = append(conns, conn)
		if err := regionhealth.Serve(conn, func() regionhealth.Report {
			return regionhealth.Report{State: regionhealth.StateOK, At: time.Now().UTC()}
		}); err != nil {
			return err
		}
	}
	for range len(servers) * (len(servers) - 1) {
		select {
		case <-ctx.Done():
			return fmt.Errorf("health subscriptions did not reach all routes: %w", ctx.Err())
		case <-subscriptions:
		}
	}
	for i, conn := range conns {
		reports, err := regionhealth.Ask(ctx, conn)
		if err != nil {
			return err
		}
		for _, region := range mesh.Regions() {
			if report, ok := reports[region]; !ok || report.State != regionhealth.StateOK {
				return fmt.Errorf("from %s: %s = %+v", mesh.Regions()[i], region, report)
			}
			fmt.Printf("from %s: %s: %s\n", mesh.Regions()[i], region, reports[region].State)
		}
	}
	return nil
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

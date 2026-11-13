package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/swarmruntime"
	"github.com/moby/swarmkit/v2/api"
)

func seed() error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	state := os.Args[1]
	executor, err := swarmruntime.NewExecutor(swarmruntime.HostContainerdSocket, state)
	if err != nil {
		return err
	}
	defer executor.Close()
	manager, err := swarmruntime.StartSingleHost(ctx, filepath.Join(state, "manager"), executor,
		"127.0.0.1:4242", "127.0.0.1:4242", swarmruntime.FounderAdmission())
	if err != nil {
		return err
	}
	defer func() {
		stop, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_ = manager.Stop(stop)
	}()
	if os.Args[2] == "worker" {
		client, conn, err := swarmruntime.DialSingleHost(filepath.Join(state, "manager"))
		if err != nil {
			return err
		}
		defer conn.Close()
		clusters, err := client.ListClusters(ctx, &api.ListClustersRequest{})
		if err != nil {
			return err
		}
		worker, err := swarmruntime.StartSingleHost(ctx, filepath.Join(state, "worker"), executor,
			"127.0.0.1:4243", "127.0.0.1:4243", swarmruntime.JoinerAdmission("worker", "instance", "127.0.0.1:4242", clusters.Clusters[0].RootCA.JoinTokens.Worker))
		if err != nil {
			return err
		}
		stop, done := context.WithTimeout(context.Background(), 15*time.Second)
		err = worker.Stop(stop)
		done()
		if err != nil {
			return err
		}
	}
	fmt.Println("seed ready")
	var command string
	_, err = fmt.Fscanln(os.Stdin, &command)
	return err
}

func main() {
	if err := seed(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

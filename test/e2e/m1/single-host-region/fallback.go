package main

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/oraclehost"
)

func fallbackPair(ctx context.Context, fleet *oraclehost.Fleet, from, to *oraclehost.Host) {
	for _, pair := range [][2]*oraclehost.Host{{from, to}, {to, from}} {
		until(ctx, pair[0].Name+" NetBird route to "+pair[1].Name, func() error {
			peers, err := pair[0].Established(ctx, 6222)
			if err != nil {
				return err
			}
			if !slices.Contains(peers, pair[1].NetBird) {
				return fmt.Errorf("no fallback to %s in %v", pair[1].Name, peers)
			}
			return nil
		})
		delivered(ctx, fleet, pair[0], pair[1])
	}
}

func fallbackJourney(binary, work string) {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	fleet, err := oraclehost.New(ctx, work, binary, filepath.Join(work, "registry"), []string{"gru", "sjc", "fra"}, []int{3, 2, 1})
	must(err)
	defer fleet.Close()
	defer func() {
		if value := recover(); value != nil {
			for _, host := range fleet.Hosts {
				fmt.Printf("%s journal\n%s\n", host.Name, tail(filepath.Join(host.Dir, "journal.log"), 25))
				peers, err := host.Established(context.Background(), 6222)
				fmt.Printf("%s route sockets: %v (%v)\n", host.Name, peers, err)
			}
			panic(value)
		}
	}()
	managers, workers := roles(fleet)
	must(fleet.Boot(managers...))
	for _, manager := range managers {
		_, err := manager.WaitReady(ctx, 0, revision(binary))
		must(err)
		_, err = fleet.WaitSecret(ctx, regionjoin.SecretName(manager.Region.Name), func(value string) bool {
			var material regionjoin.Material
			return json.Unmarshal([]byte(value), &material) == nil && material.WorkerToken != "" && len(material.Routes) != 0
		})
		must(err)
	}
	gru, sjc := fleet.Regions[0], fleet.Regions[1]
	var material regionjoin.Material
	must(json.Unmarshal([]byte(fleet.PinSecret(regionjoin.SecretName(gru.Name))), &material))
	for _, worker := range gru.Hosts[1:] {
		require(!strings.Contains(strings.Join(material.Routes, " "), "//"+worker.Address+":"), "pinned material lists %s: %v", worker.Name, material.Routes)
	}
	regionRouteFirewall(ctx, gru.Hosts[0], "-I")
	regionRouteFirewall(ctx, sjc.Hosts[0], "-I")
	must(fleet.Boot(workers...))
	for _, worker := range workers {
		_, err := worker.WaitReady(ctx, 0, revision(binary))
		must(err)
	}
	for _, worker := range workers {
		peers, err := worker.Established(ctx, 6222)
		must(err)
		for _, peer := range worker.Region.Hosts {
			if peer != worker {
				require(!slices.Contains(peers, peer.Address) && !slices.Contains(peers, peer.NetBird), "%s already reached %s: %v", worker.Name, peer.Name, peers)
			}
		}
	}
	manager := gru.Hosts[0]
	must(manager.Kill())
	fleet.Hosts = slices.DeleteFunc(fleet.Hosts, func(host *oraclehost.Host) bool { return host == manager })
	step("gru manager stopped before its workers ever reached their region; pinned material lists neither worker; sjc VCN :6222 rejected while NetBird remains open")
	fallbackPair(ctx, fleet, gru.Hosts[1], gru.Hosts[2])
	step("manager remains down: workers connected over NetBird and delivered ORCH, TERRABASE and ALERTS both ways")
	fallbackPair(ctx, fleet, sjc.Hosts[0], sjc.Hosts[1])
	for _, host := range sjc.Hosts {
		peers, err := host.Established(ctx, 6222)
		must(err)
		for _, peer := range sjc.Hosts {
			if peer != host {
				require(!slices.Contains(peers, peer.Address), "%s bypassed VCN firewall to %s: %v", host.Name, peer.Name, peers)
			}
		}
	}
	step("VCN :6222 remains rejected: manager and worker connected over NetBird and delivered all three accounts both ways")
	step("region fallback lane passed in %s", time.Since(started).Round(time.Second))
}

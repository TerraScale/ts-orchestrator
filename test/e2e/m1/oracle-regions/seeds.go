package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
	"github.com/TerraScale/ts-orchestrator/internal/regionjoin"
	"github.com/TerraScale/ts-orchestrator/test/e2e/m1/oraclehost"
)

const wipedCell = "cluster-of-a-wiped-cell"

type foundingRecord struct {
	Region  string `json:"region"`
	Cluster string `json:"cluster"`
	Formed  bool   `json:"formed"`
}

func vaultRead(name string) {
	_, version, err := mesh.VaultRecords().Read(context.Background(), name)
	must(err)
	fmt.Printf("version %d\n", version)
}

func plantWipedFounder(fleet *oraclehost.Fleet) {
	data, err := json.Marshal(foundingRecord{Region: fleet.Regions[0].Name, Cluster: wipedCell, Formed: true})
	must(err)
	fleet.PutSecret(mesh.FounderRecord, string(data))
	step("Vault holds a founder record left by a wiped cell: %s", data)
}

func seedsOf(fleet *oraclehost.Fleet, region string) mesh.Seeds {
	value, _ := fleet.Secret(mesh.SeedRecord(region))
	var seeds mesh.Seeds
	_ = json.Unmarshal([]byte(value), &seeds)
	return seeds
}

func meshSeeds(ctx context.Context, fleet *oraclehost.Fleet) {
	for _, region := range fleet.Regions {
		until(ctx, mesh.SeedRecord(region.Name)+" lists the region's manager", func() error {
			if seeds := seedsOf(fleet, region.Name); seeds.Region != region.Name || seeds.Cluster == "" || !slices.Equal(seeds.Hosts, []string{region.Hosts[0].Name}) {
				return fmt.Errorf("seed record %+v", seeds)
			}
			return nil
		})
	}
	var record foundingRecord
	until(ctx, mesh.FounderRecord+" formed", func() error {
		value, _ := fleet.Secret(mesh.FounderRecord)
		record = foundingRecord{}
		if err := json.Unmarshal([]byte(value), &record); err != nil {
			return err
		}
		if !record.Formed || record.Cluster == wipedCell || record.Cluster != seedsOf(fleet, record.Region).Cluster {
			return fmt.Errorf("founder record %+v", record)
		}
		return nil
	})
	step("the wiped cell's founder record was replaced: %s founded the metadata group as SwarmKit cluster %s and marked it formed", record.Region, record.Cluster)
	pool := fleet.Regions[len(fleet.Regions)-1]
	access := fleet.VaultAccess()
	for _, region := range fleet.Regions {
		for _, peer := range fleet.Regions {
			if peer != region {
				name := "granted " + mesh.SeedRecord(peer.Name) + " for " + region.Hosts[0].Address
				require(access[name] > 0, "%s never read %s: %v", region.Hosts[0].Name, mesh.SeedRecord(peer.Name), access)
			}
		}
	}
	step("%s, made only of pool-named hosts (%s), published %v as its seeds; every manager read every peer region's seed record and routes to every other manager", pool.Name, hostNames(pool.Hosts), seedsOf(fleet, pool.Name).Hosts)
}

func hostNames(hosts []*oraclehost.Host) string {
	names := []string{}
	for _, host := range hosts {
		names = append(names, host.Name)
	}
	return strings.Join(names, ", ")
}

func vaultGrants(ctx context.Context, fleet *oraclehost.Fleet) {
	self, err := os.Executable()
	must(err)
	home, peer := fleet.Regions[1].Hosts[0], fleet.Regions[0]
	output, err := home.Exec(ctx, self, "vault-read", regionjoin.SecretName(peer.Name))
	require(err != nil && strings.Contains(string(output), "exists but this host's Vault grants do not let it read it"), "%s reading %s: %v: %s", home.Name, regionjoin.SecretName(peer.Name), err, output)
	output, err = home.Exec(ctx, self, "vault-read", mesh.SeedRecord(peer.Name))
	require(err == nil && strings.HasPrefix(string(output), "version ") && !strings.Contains(string(output), "version 0"), "%s reading %s: %v: %s", home.Name, mesh.SeedRecord(peer.Name), err, output)
	access := fleet.VaultAccess()
	probe := "denied " + regionjoin.SecretName(peer.Name) + " for " + home.Address
	require(access[probe] > 0, "the stand-in did not deny %s: %v", probe, access)
	for entry := range access {
		require(!strings.HasPrefix(entry, "denied ") || entry == probe, "a host was denied a Vault read the shipped policy must grant: %s", entry)
	}
	step("the Vault stand-in enforces the shipped host policy per caller compartment: %s reads %s's seed record; its join bundle exists and reads as denied, not absent; no host was denied anything else", home.Name, peer.Name)
}

func refusedSeeds(ctx context.Context, host *oraclehost.Host) int {
	var count int
	until(ctx, host.Name+" metrics", func() error {
		text, err := metrics(ctx, host)
		if err != nil {
			return err
		}
		for _, line := range strings.Split(text, "\n") {
			if value, ok := strings.CutPrefix(line, "ts_orch_mesh_seed_routes_refused_total "); ok {
				_, err := fmt.Sscan(value, &count)
				return err
			}
		}
		return errors.New("no refused-seed counter")
	})
	return count
}

func badPeerRecords(ctx context.Context, fleet *oraclehost.Fleet, release string) {
	gru, sjc, pool := fleet.Regions[0], fleet.Regions[1], fleet.Regions[len(fleet.Regions)-1]
	disguised := sjc.Name + "-node-97"
	must(fleet.Alias(disguised, gru.Hosts[0].NetBird))
	current := seedsOf(fleet, sjc.Name)
	wrong, err := json.Marshal(mesh.Seeds{Region: sjc.Name, Version: current.Version + 1, Cluster: current.Cluster, Hosts: []string{disguised, gru.Hosts[0].Name}})
	must(err)
	fleet.PutSecret(mesh.SeedRecord(sjc.Name), string(wrong))
	fleet.PinSecret(mesh.SeedRecord(sjc.Name))
	fleet.PutSecret(mesh.SeedRecord(gru.Name), `{"region":"`+gru.Name+`","hosts":["`+gru.Hosts[0].Name+`"]}`)
	fleet.PinSecret(mesh.SeedRecord(gru.Name))
	manager := pool.Hosts[0]
	after := manager.LastRun()
	must(manager.Restart())
	_, err = manager.WaitReady(ctx, after, release)
	must(err)
	until(ctx, manager.Name+" refuses the disguised seed's certificate", func() error {
		if count := refusedSeeds(ctx, manager); count == 0 {
			return errors.New("no seed refused yet")
		}
		return nil
	})
	journal := tail(manager.Dir+"/journal.log", 4000)
	for _, line := range []string{"mesh peer seed hosts from another region refused", "mesh peer seeds unavailable", "mesh seed host presented another region's certificate; connection refused"} {
		require(strings.Contains(journal, line), "%s journal lacks %q", manager.Name, line)
	}
	meshRoutes(ctx, fleet)
	healthy(ctx, manager, release)
	fleet.UnpinSecret(mesh.SeedRecord(sjc.Name))
	fleet.UnpinSecret(mesh.SeedRecord(gru.Name))
	step("%s restarted with %s's seed record naming %s and a disguised %s host, and %s's record missing its version and cluster: it refused the other region's host, refused the TLS connection to the disguised seed because %s's manager presented a %s certificate, started its local NATS, routes to every manager and is release-healthy", manager.Name, sjc.Name, gru.Hosts[0].Name, disguised, gru.Name, gru.Name, gru.Name)
}

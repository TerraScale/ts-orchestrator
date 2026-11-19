package main

import (
	"fmt"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/app"
	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

func main() {
	if os.Args[1] == "host" {
		if err := edge.FleetHost(os.Args[2:]); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL fleet host:", err)
			os.Exit(1)
		}
		return
	}
	if os.Args[1] == "fleet" {
		if err := edge.FleetEdgeJourney(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL edge fleet:", err)
			os.Exit(1)
		}
		return
	}
	if os.Args[1] == "single-region" {
		if err := mesh.RegionalPeersJourney(os.Args[2], true, app.WorkerReleaseJourney, app.PullRolloutJourney); err != nil {
			fmt.Fprintln(os.Stderr, "FAIL single region:", err)
			os.Exit(1)
		}
		return
	}
	if err := mesh.RegionalPeersJourney(os.Args[1], false, app.WorkerReleaseJourney, app.PullRolloutJourney); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL regional peers:", err)
		os.Exit(1)
	}
	if err := mesh.MetaBootJourney(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL metadata boot:", err)
		os.Exit(1)
	}
}

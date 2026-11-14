package main

import (
	"fmt"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

func main() {
	nodes, closeNodes, err := mesh.FleetEdgeNodes(os.Args[1])
	if err != nil {
		fmt.Fprintln(os.Stderr, "FAIL edge mesh:", err)
		os.Exit(1)
	}
	defer closeNodes()
	if err := edge.FleetEdgeJourney(os.Args[1], nodes); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL edge fleet:", err)
		os.Exit(1)
	}
	if err := mesh.RegionalPeersJourney(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL regional peers:", err)
		os.Exit(1)
	}
	if err := mesh.MetaBootJourney(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL metadata boot:", err)
		os.Exit(1)
	}
}

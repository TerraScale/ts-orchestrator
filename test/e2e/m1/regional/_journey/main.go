package main

import (
	"fmt"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/natscell/mesh"
)

func main() {
	if err := mesh.RegionalPeersJourney(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, "FAIL regional peers:", err)
		os.Exit(1)
	}
}

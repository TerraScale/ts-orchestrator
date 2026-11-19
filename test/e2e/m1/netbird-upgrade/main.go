package main

import (
	"context"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/netbird/client"
)

func main() {
	if len(os.Args) != 2 {
		panic("usage: netbird-upgrade <expected binary sha256>")
	}
	if err := client.ReconcileService(context.Background(), "/usr/local/bin/netbird", os.Args[1]); err != nil {
		panic(err)
	}
}

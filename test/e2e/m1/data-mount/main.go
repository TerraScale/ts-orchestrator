package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/TerraScale/ts-orchestrator/internal/datamount"
)

func main() {
	report, err := datamount.Read(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		panic(err)
	}
}

package main

import (
	"fmt"
	"os"
	"strings"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/regionhost"
)

func main() {
	script, err := regionhost.CloudInit(m1.Files, "https://example.com/ts-orch", strings.Repeat("0", 64), false)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(script)
}

package main

import (
	"fmt"
	"os"
	"strings"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/nodeinit"
)

func main() {
	script, err := nodeinit.CloudInit(m1.Files, "https://example.com/ts-orch", strings.Repeat("0", 64), "ocid1.volume.oc1.test.data", "", "", true)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(script)
}

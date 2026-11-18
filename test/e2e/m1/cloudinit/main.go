package main

import (
	"fmt"
	"os"
	"strings"

	m1 "github.com/TerraScale/ts-orchestrator/deploy/m1"
	"github.com/TerraScale/ts-orchestrator/internal/nodeinit"
	"github.com/TerraScale/ts-orchestrator/internal/releasegate"
)

func main() {
	script, err := nodeinit.CloudInit(m1.Files, "https://example.com/ts-orch", strings.Repeat("0", 64), "ocid1.volume.oc1.test.data", "", "", true, releasegate.Receipt{Target: releasegate.Target{Tag: "ci-" + strings.Repeat("1", 40) + "-run-1", Binaries: map[string]string{"arm64": strings.Repeat("0", 64)}}, Region: "stg"})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Print(script)
}

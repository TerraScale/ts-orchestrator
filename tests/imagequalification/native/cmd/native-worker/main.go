// native-worker is deployed only to /run on explicitly disposable image hosts.
package main

import (
	"context"
	"fmt"
	"os"

	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/native"
)

func main() {
	if len(os.Args) != 2 || os.Args[1] != "serve" {
		fmt.Fprintln(os.Stderr, "native-worker requires serve")
		os.Exit(2)
	}
	if err := native.Serve(context.Background(), os.Stdin, os.Stdout); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

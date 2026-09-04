// Child-process fixture that holds the workspace topology lease on stdin.
package main

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"strings"
	"time"
)

type workspaceTopologyLeaseHolderCommand struct{}

// WorkspaceTopologyLeaseHolderCommand implements the lease-holder fixture
// command.
var WorkspaceTopologyLeaseHolderCommand = workspaceTopologyLeaseHolderCommand{}

func (workspaceTopologyLeaseHolderCommand) RunAsync(ctx context.Context, arguments []string) (int, error) {
	usage := newToolValidationException([]string{"workspace-topology-lease-holder requires --namespace <value>"})
	var leaseNamespace string
	var noisyStderr, ignoreStandardInput bool
	switch {
	case len(arguments) == 2 && arguments[0] == "--namespace":
		leaseNamespace = arguments[1]
	case len(arguments) == 4 && arguments[0] == "--namespace" &&
		arguments[2] == "--noisy-stderr" && arguments[3] == "--ignore-stdin":
		leaseNamespace, noisyStderr, ignoreStandardInput = arguments[1], true, true
	default:
		return 0, usage
	}

	if leaseNamespace == "" {
		return 0, usage
	}

	os.Setenv(workspaceTopologyNamespaceVariable, leaseNamespace)
	lease, err := AcquireWorkspaceTopologyLease(context.Background(), workspaceTopologyDevelopmentLabOwner, 10*time.Second)
	if err != nil {
		return 0, err
	}
	defer lease.Close()
	if noisyStderr {
		for written := 0; written < 128*1024; written += 1024 {
			fmt.Fprint(os.Stderr, strings.Repeat("x", 1024))
		}
	}
	fmt.Println("held")
	if ignoreStandardInput {
		// The hostile-holder fixture must ignore a closed stdin forever: an
		// unbounded wait.
		select {}
	}
	reader := bufio.NewReader(os.Stdin)
	// One line is read and discarded from stdin: the parent releases the
	// holder by closing its standard input.
	_, _ = reader.ReadString('\n')
	return 0, nil
}

// Port of tools/TerraScale.Orchestrator.Tooling/ToolDispatcher.cs: the
// manual command dispatcher plus the json-format command that shares the file.
package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type toolCommand struct {
	name string
	run  func(context.Context, []string) (int, error)
}

// toolCommands mirrors the C# dispatcher dictionary; the slice keeps the C#
// insertion order for the usage inventory.
var toolCommands = []toolCommand{
	{"json-format", func(_ context.Context, arguments []string) (int, error) {
		return JsonFormatCommand.Run(arguments)
	}},
	{"test", func(_ context.Context, arguments []string) (int, error) {
		return ToolingTests.Run(arguments)
	}},
	{"workspace-topology-lease-holder", WorkspaceTopologyLeaseHolderCommand.RunAsync},
}

type toolDispatcher struct{}

// ToolDispatcher mirrors the C# ToolDispatcher static class.
var ToolDispatcher = toolDispatcher{}

func (toolDispatcher) RunAsync(ctx context.Context, arguments []string) int {
	if len(arguments) == 0 {
		writeUsage()
		return 2
	}
	var selected *toolCommand
	for index := range toolCommands {
		if toolCommands[index].name == arguments[0] {
			selected = &toolCommands[index]
			break
		}
	}
	if selected == nil {
		writeUsage()
		return 2
	}

	exitCode, err := selected.run(ctx, arguments[1:])
	if err == nil {
		return exitCode
	}
	var validation *toolValidationException
	if errors.As(err, &validation) {
		for _, validationError := range validation.errorsList {
			fmt.Fprintln(os.Stderr, validationError)
		}
		return 1
	}
	fmt.Fprintln(os.Stderr, err.Error())
	return 1
}

func writeUsage() {
	names := make([]string, 0, len(toolCommands))
	for _, command := range toolCommands {
		names = append(names, command.name)
	}
	fmt.Fprintf(os.Stderr, "Usage: terrascale-orchestrator-tooling <%s> [options]\n", strings.Join(names, "|"))
}

type jsonFormatCommand struct{}

// JsonFormatCommand mirrors the C# JsonFormatCommand static class.
var JsonFormatCommand = jsonFormatCommand{}

func (jsonFormatCommand) Run(arguments []string) (int, error) {
	if len(arguments) != 1 {
		return 0, newToolValidationException([]string{"json-format requires exactly one file"})
	}
	path := fullPathFromRoot(ToolingSupport.Root(), arguments[0])
	content, err := os.ReadFile(path)
	if err != nil {
		return 0, err
	}
	node, err := parseJSONNode(content)
	if err != nil {
		return 0, err
	}
	if node == nil {
		return 0, errors.New("empty JSON document")
	}
	serialized, err := ToolingSupport.Serialize(node)
	if err != nil {
		return 0, err
	}
	fmt.Print(serialized)
	return 0, nil
}

// fullPathFromRoot mirrors Path.GetFullPath(path, baseDirectory).
func fullPathFromRoot(baseDirectory, path string) string {
	if filepath.IsAbs(path) {
		return filepath.Clean(path)
	}
	return filepath.Join(baseDirectory, path)
}

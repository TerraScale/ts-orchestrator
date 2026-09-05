package vmguest

import "testing"

func TestStartupDiagnosticsAdmitOnlyFixedReadOnlyCommands(t *testing.T) {
	for _, unit := range []string{"terrascale-ts-node.service", "terrascale-orchestrator.service", "terrascale-terrabase.service"} {
		for _, request := range []Request{
			{SchemaVersion: SchemaVersion, Operation: OperationExecute, Path: "/usr/bin/systemctl", Args: []string{"show", unit, "--property=MainPID,ActiveState,SubState,Result,ExecMainCode,ExecMainStatus"}},
			{SchemaVersion: SchemaVersion, Operation: OperationExecute, Path: "/usr/bin/journalctl", Args: []string{"--unit", unit, "--lines=20", "--no-pager", "--output=json", "--output-fields=MESSAGE,PRIORITY", "--boot"}},
		} {
			if err := request.Validate(); err != nil {
				t.Fatal(err)
			}
			for index := range request.Args {
				mutated := request
				mutated.Args = append([]string(nil), request.Args...)
				mutated.Args[index] = "--all"
				if mutated.Validate() == nil {
					t.Fatalf("accepted widened diagnostic: %+v", mutated)
				}
			}
		}
	}
}

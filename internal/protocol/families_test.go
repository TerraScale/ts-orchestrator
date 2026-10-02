package protocol

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// The builders must reproduce the pre-existing wire subjects byte for byte;
// changing any of these strings is a protocol change that breaks running
// controllers, issued credentials, and the durable control log.
func TestSubjectFamiliesKeepWireFormat(t *testing.T) {
	t.Parallel()

	const key = "UDXU4RCSJNZOIQHZNWXHXORDPRTGNJAHAHFRGZNEEJCPQTT2M7NLCNF4"
	cases := map[string]string{
		HostRegisterSubject("gru"):                    "ts.orch.v1.gru.host.register",
		BackupOperationSubject("gru"):                 "ts.orch.v1.gru.backup.operation",
		BrokerClaimApplySubject("gru"):                "ts.orch.v1.gru.broker.claim.apply",
		PlacementApplySubject("sfo"):                  "ts.orch.v1.sfo.placement.apply",
		ManagedUpdatePrepareSubject("gru"):            "ts.orch.v1.gru.managed-update.prepare",
		MaterialPrepareSubject("gru"):                 "ts.orch.v1.gru.material.prepare",
		TerminalSubject("gru", "plan"):                "ts.orch.v1.gru.terminal.plan",
		TerminalSubject("gru", ">"):                   "ts.orch.v1.gru.terminal.>",
		DeliveryIntentSubject("fra"):                  "ts.orch.v1.fra.delivery.intent",
		DeliveryArtifactAdmitSubject("gru"):           "ts.orch.v1.gru.delivery.artifact.admit",
		RegionHealthSubject("GRU"):                    "ts.orch.v1.gru.region.health",
		InboxPrefix("gru", key):                       "ts.orch.v1.gru.inbox." + key,
		InboxGrant("gru", key):                        "ts.orch.v1.gru.inbox." + key + ".>",
		InboxGrant("gru", TemplateSubject):            "ts.orch.v1.gru.inbox.{{subject()}}.>",
		AgentObservation("gru", "*", "*"):             "ts.orch.v1.gru.agent.*.observation.*",
		AgentObservation("gru", key, "*"):             "ts.orch.v1.gru.agent." + key + ".observation.*",
		Regional("gru", ">"):                          "ts.orch.v1.gru.>",
		Control("gru", ">"):                           "ts.control.gru.>",
		Control("global", "lease"):                    "ts.control.global.lease",
		Control("gru", "broker", "claim", key):        "ts.control.gru.broker.claim." + key,
		Control("gru", "host", "registration", "gru"): "ts.control.gru.host.registration.gru",
		ControlStreamSubject():                        "ts.control.*.>",
		Broker("gru", "ticket", ">"):                  "ts.broker.gru.ticket.>",
		Broker("gru", "fence", "broker-a"):            "ts.broker.gru.fence.broker-a",
		GlobalState("directory", "db-1"):              "ts.global.v1.directory.db-1",
		GlobalStateStreamSubject():                    "ts.global.v1.>",
		GlobalControlRequest("directory-put"):         "ts.orch.v1.global.control.directory-put",
	}
	for got, want := range cases {
		if got != want {
			t.Errorf("subject = %q, want %q", got, want)
		}
	}
	if legacy, err := GlobalControlSubject("directory-put"); err != nil || legacy != GlobalControlRequest("directory-put") {
		t.Fatalf("GlobalControlSubject = %q, %v", legacy, err)
	}
}

func TestSubjectFamiliesFailClosed(t *testing.T) {
	t.Parallel()

	for name, subject := range map[string]string{
		"global regional root": Regional("global", "x"),
		"global broker root":   Broker("global", "ticket", ">"),
		"empty cell":           HostRegisterSubject(""),
		"bad cell":             PlacementApplySubject("gru.sfo"),
		"inner full wildcard":  Regional("gru", ">", "x"),
		"dotted wildcard":      Regional("gru", "terminal.>.x"),
		"whitespace token":     TerminalSubject("gru", "a b"),
		"empty token":          TerminalSubject("gru", ""),
		"empty inner token":    Regional("gru", "a..b"),
		"bad global action":    GlobalControlRequest(">"),
	} {
		if subject != "" {
			t.Errorf("%s: subject = %q, want fail-closed empty subject", name, subject)
		}
	}
}

// TestNoSubjectLiteralsOutsideProtocol keeps subject construction in this
// package. Tests may pin literal wire strings; production code may not.
func TestNoSubjectLiteralsOutsideProtocol(t *testing.T) {
	t.Parallel()

	roots := []string{filepath.Join("..", "..", "internal"), filepath.Join("..", "..", "cmd")}
	files := token.NewFileSet()
	for _, root := range roots {
		err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if entry.IsDir() {
				if path == filepath.Join("..", "..", "internal", "protocol") {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			parsed, err := parser.ParseFile(files, path, nil, parser.SkipObjectResolution)
			if err != nil {
				return err
			}
			ast.Inspect(parsed, func(node ast.Node) bool {
				literal, ok := node.(*ast.BasicLit)
				if !ok || literal.Kind != token.STRING {
					return true
				}
				value, err := strconv.Unquote(literal.Value)
				if err == nil && strings.HasPrefix(value, "ts.") {
					t.Errorf("%s: subject literal %q must be built by internal/protocol", files.Position(literal.Pos()), value)
				}
				return true
			})
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
}

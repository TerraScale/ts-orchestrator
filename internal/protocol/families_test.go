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
		HostRegisterSubject("gru"):                             "ts.orch.v1.gru.host.register",
		BackupOperationSubject("gru"):                          "ts.orch.v1.gru.backup.operation",
		BrokerClaimApplySubject("gru"):                         "ts.orch.v1.gru.broker.claim.apply",
		MembershipReplaceSubject("gru"):                        "ts.orch.v1.gru.membership.replace",
		PlacementApplySubject("sjc"):                           "ts.orch.v1.sjc.placement.apply",
		ManagedUpdatePrepareSubject("gru"):                     "ts.orch.v1.gru.managed-update.prepare",
		MaterialPrepareSubject("gru"):                          "ts.orch.v1.gru.material.prepare",
		TerminalSubject("gru", "plan"):                         "ts.orch.v1.gru.terminal.plan",
		TerminalSubject("gru", ">"):                            "ts.orch.v1.gru.terminal.>",
		DeliveryIntentSubject("fra"):                           "ts.orch.v1.fra.delivery.intent",
		DeliveryArtifactAdmitSubject("gru"):                    "ts.orch.v1.gru.delivery.artifact.admit",
		RegionHealthSubject("GRU"):                             "ts.orch.v1.gru.region.health",
		AnyRegionHealthSubject():                               "ts.orch.v1.*.region.health",
		InboxPrefix("gru", key):                                "ts.orch.v1.gru.inbox." + key,
		InboxGrant("gru", key):                                 "ts.orch.v1.gru.inbox." + key + ".>",
		InboxGrant("gru", TemplateSubject):                     "ts.orch.v1.gru.inbox.{{subject()}}.>",
		AgentObservation("gru", "*", "*"):                      "ts.orch.v1.gru.agent.*.observation.*",
		AgentObservation("gru", key, "*"):                      "ts.orch.v1.gru.agent." + key + ".observation.*",
		Regional("gru", ">"):                                   "ts.orch.v1.gru.>",
		ObservabilityGrant("gru"):                              "ts.orch.v1.gru.obs.>",
		RolloutStatusSubject("gru"):                            "ts.orch.v1.gru.rollout.status",
		ReleaseStatusSubject("gru"):                            "ts.orch.v1.gru.release.status",
		RolloutProofSubject("gru", ""):                         "ts.orch.v1.gru.rollout.proof.*",
		RolloutProofSubject("gru", "controller-a"):             "ts.orch.v1.gru.rollout.proof." + HashToken("controller-a")[:32],
		Control("gru", ">"):                                    "ts.control.gru.>",
		Control("global", "lease"):                             "ts.control.global.lease",
		Control("gru", "broker", "claim", key):                 "ts.control.gru.broker.claim." + key,
		Control("gru", "host", "registration", "gru"):          "ts.control.gru.host.registration.gru",
		ControlStreamSubject():                                 "ts.control.*.>",
		Broker("gru", "ticket", ">"):                           "ts.broker.gru.ticket.>",
		Broker("gru", "fence", "broker-a"):                     "ts.broker.gru.fence.broker-a",
		GlobalState("directory", "00000000004SJMRETVW39JX054"): "ts.global.v1.directory.00000000004SJMRETVW39JX054",
		GlobalStateStreamSubject():                             "ts.global.v1.>",
		GlobalControlRequest("directory-put"):                  "ts.orch.v1.global.control.directory-put",
		JSDomainAPIPrefix("gru"):                               "$JS.gru.API",
		InterRegionGlobalDeliverSubject("sjc"):                 "ts.interregion.v1.sjc.global",
		GlobalMirrorConsumer("SJC"):                            "global-mirror-sjc",
		JSConsumerResetSubject(JSLocalAPIPrefix, GlobalControlStream, "global-mirror-sjc"): "$JS.API.CONSUMER.RESET.TS_GLOBAL_CONTROL.global-mirror-sjc",
		JSFlowControlSubject(GlobalControlStream, "global-mirror-sjc"):                     "$JS.FC.TS_GLOBAL_CONTROL.global-mirror-sjc.*",
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
		"bad cell":             PlacementApplySubject("gru.sjc"),
		"inner full wildcard":  Regional("gru", ">", "x"),
		"dotted wildcard":      Regional("gru", "terminal.>.x"),
		"whitespace token":     TerminalSubject("gru", "a b"),
		"empty token":          TerminalSubject("gru", ""),
		"empty inner token":    Regional("gru", "a..b"),
		"bad global action":    GlobalControlRequest(">"),
		"global mirror scope":  GlobalMirrorConsumer("global"),
		"global deliver scope": InterRegionGlobalDeliverSubject("global"),
		"bad deliver cell":     InterRegionGlobalDeliverSubject("s.fo"),
		"bad api home":         JSDomainAPIPrefix("g>"),
		"reset of no consumer": JSConsumerResetSubject(JSLocalAPIPrefix, GlobalControlStream, GlobalMirrorConsumer("x.y")),
		"reset without prefix": JSConsumerResetSubject(JSDomainAPIPrefix("global"), GlobalControlStream, "c"),
		"fc of no consumer":    JSFlowControlSubject(GlobalControlStream, ""),
		"rollout global scope": RolloutStatusSubject("global"),
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

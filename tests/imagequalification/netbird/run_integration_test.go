package netbird

import (
	"bufio"
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	native "github.com/TerraScale/ts-orchestrator/tests/imagequalification/host"
	"github.com/TerraScale/ts-orchestrator/tests/imagequalification/netbird/protocol"
)

func TestMain(m *testing.M) {
	if len(os.Args) == 2 && os.Args[1] == "netbird-protocol-fixture" {
		if serveProtocolFixture() != nil {
			os.Exit(1)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// This local process fixture tests rejection and secret handling, never native NetBird acceptance.
func serveProtocolFixture() error {
	scanner := bufio.NewScanner(os.Stdin)
	for scanner.Scan() {
		var command protocol.Command
		if err := json.Unmarshal(scanner.Bytes(), &command); err != nil {
			return err
		}
		response := protocol.Response{Private: []byte(`{"credential":"private-fixture-credential"}`)}
		if command.Operation == "identity" {
			response.Observation.Identity = command.Host.ExpectedIdentity
			response.Observation.Identity.BinarySHA256 = strings.Repeat("b", 64)
			response.Observation.WorkerSHA256 = strings.Repeat("c", 64)
			response.Observation.WorkerSourceRevision = command.SourceRevision
		} else if command.Operation != "cleanup" {
			return errors.New("runner continued after an identity mismatch")
		}
		wire, err := json.Marshal(response)
		if err != nil {
			return err
		}
		if _, err := os.Stdout.Write(append(wire, '\n')); err != nil {
			return err
		}
	}
	return scanner.Err()
}

type processFixture struct {
	command *exec.Cmd
	input   io.WriteCloser
	output  *bufio.Scanner
}

func startProcessFixture(t *testing.T) *processFixture {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), executable, "netbird-protocol-fixture")
	input, err := command.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	output, err := command.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := command.Start(); err != nil {
		t.Fatal(err)
	}
	return &processFixture{command: command, input: input, output: bufio.NewScanner(output)}
}

func (p *processFixture) Exchange(ctx context.Context, input, output any) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	wire, err := json.Marshal(input)
	if err != nil {
		return err
	}
	if _, err := p.input.Write(append(wire, '\n')); err != nil {
		return err
	}
	if !p.output.Scan() {
		return errors.Join(io.ErrUnexpectedEOF, p.output.Err())
	}
	return json.Unmarshal(p.output.Bytes(), output)
}

func (p *processFixture) Close() error {
	return errors.Join(p.input.Close(), p.command.Wait())
}

func TestRunnerRejectsChangedNativeImageAcrossProcessBoundary(t *testing.T) {
	first, second := startProcessFixture(t), startProcessFixture(t)
	hash := strings.Repeat("a", 64)
	req := Request{RunID: "protocol1", WorkerSHA256: strings.Repeat("c", 64)}
	req.Candidate.SourceRevision = strings.Repeat("d", 40)
	for i := range req.Hosts {
		req.Hosts[i] = native.Host{OCID: []string{"ocid1.instance.primary", "ocid1.instance.replacement"}[i], ExpectedIdentity: native.Identity{BinarySHA256: hash}}
	}
	report, err := run(t.Context(), req, native.Report{StartedAt: time.Now().UTC()}, [2]exchange{first, second})
	if err == nil || !strings.Contains(err.Error(), "differs from exact candidate") {
		t.Fatalf("changed native binary was accepted: %v", err)
	}
	if !report.CompletedAt.IsZero() || len(report.Scenarios) != 1 || report.Scenarios[0].Gate != "" {
		t.Fatalf("failed native identity emitted a qualification gate: %+v", report.Scenarios)
	}
	if strings.Contains(string(report.Scenarios[0].Transcript), "private-fixture-credential") {
		t.Fatal("private SSH response entered retained evidence")
	}
	if report.Scenarios[0].TranscriptSHA256 == "" {
		t.Fatal("failure evidence has no retained digest")
	}
}

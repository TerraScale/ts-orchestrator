package cli

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
)

func TestObservedDigestsReportsReplicaMatches(t *testing.T) {
	fixture := newDeployFixture(t)
	digest := strings.Repeat("ab", 32)
	observed := time.Date(2026, 11, 9, 12, 0, 0, 0, time.UTC)
	status := `{"schema":"service-status","cell":"SJC","role":"terrabase","digest":"` + digest + `","state":"complete",` +
		`"updated_at":"` + observed.Format(time.RFC3339) + `","replicas":[` +
		`{"node":"node-a","running_digest":"` + digest + `","state":"running","observed_at":"` + observed.Format(time.RFC3339) + `"},` +
		`{"node":"node-b","running_digest":"` + strings.Repeat("cd", 32) + `","state":"running","observed_at":"` + observed.Format(time.RFC3339) + `"}]}`
	fixture.buckets["SJC"].objects[releasechannel.ServiceStatusObject("terrabase")] = []byte(status)
	var output bytes.Buffer
	c := command{ctx: t.Context(), output: &output}
	if err := c.observedDigestsWith([]string{"--namespace", "ns", "--cell", "SJC", "--role", "terrabase"}, fixture.env); err != nil {
		t.Fatalf("observed-digests: %v\n%s", err, output.String())
	}
	text := output.String()
	row := func(node, running, match string) bool {
		for _, line := range strings.Split(text, "\n") {
			fields := strings.Fields(line)
			if len(fields) != 8 || fields[0] != "SJC" || fields[1] != "terrabase" || fields[2] != "complete" ||
				fields[3] != digest[:12] || fields[4] != node || fields[5] != running || fields[6] != "2026-11-09T12:00:00Z" ||
				fields[7] != match {
				continue
			}
			return true
		}
		return false
	}
	if !row("node-a", digest[:12], "yes") || !row("node-b", strings.Repeat("cd", 32)[:12], "no") {
		t.Fatalf("observed-digests:\n%s", text)
	}
}

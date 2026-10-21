package cli

import (
	"context"
	"encoding/json/v2"
	"errors"
	"io"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
)

func omitDeploymentFlags(args []string, flags ...string) []string {
	var kept []string
	for i := 0; i < len(args); i += 2 {
		if !slices.Contains(flags, args[i]) {
			kept = append(kept, args[i:i+2]...)
		}
	}
	return kept
}

func TestDeployDiscoversEveryCellAndKeepsBadRegionalScopeIndependent(t *testing.T) {
	for _, broken := range []string{"", "missing", "stale", "environment", "architecture"} {
		t.Run(broken, func(t *testing.T) {
			f := newDeployFixture(t)
			for _, cell := range []string{"GRU", "SJC"} {
				f.buckets[cell].scope = &releasechannel.Status{Schema: releasechannel.StatusSchema, Cell: cell,
					Environment: "production", Architectures: []string{"amd64"}, State: releasechannel.StateFailed, UpdatedAt: time.Now().UTC()}
			}
			switch broken {
			case "missing":
				f.buckets["SJC"].scope = nil
			case "stale":
				f.buckets["SJC"].scope.UpdatedAt = time.Now().Add(-time.Hour)
			case "environment":
				f.buckets["SJC"].scope.Environment = "canary"
			case "architecture":
				f.buckets["SJC"].scope.Architectures = []string{"arm64"}
			}
			args := omitDeploymentFlags(f.args(), "--environment", "--arch")
			err := (command{ctx: t.Context(), output: io.Discard}).deployWith(args, f.env)
			if (err != nil) != (broken != "") || !f.touched("GRU") || f.touched("SJC") != (broken == "") || f.touched("FRA") {
				t.Fatalf("scope failure blocked/skipped a required region or deployed unfounded FRA: broken=%s err=%v log=%v", broken, err, f.log)
			}
			if broken != "" && !strings.Contains(err.Error(), "SJC") {
				t.Fatal(err)
			}
		})
	}
}

func TestServiceDeployDiscoversPerCellEnvironmentsAndReportsMissingScope(t *testing.T) {
	for _, missingSJC := range []bool{false, true} {
		f := newServiceDeployFixture(t)
		for cell, environment := range map[string]string{"GRU": "canary", "SJC": "production"} {
			f.buckets[cell].environment = environment
			scope := releasechannel.Status{Schema: releasechannel.StatusSchema, Cell: cell,
				Environment: environment, Architectures: []string{"arm64"}, UpdatedAt: time.Now().UTC()}
			wire, err := json.Marshal(scope)
			if err != nil {
				t.Fatal(err)
			}
			f.buckets[cell].objects[releasechannel.StatusObject] = wire
		}
		if missingSJC {
			delete(f.buckets["SJC"].objects, releasechannel.StatusObject)
		}
		err := (command{ctx: t.Context(), output: io.Discard}).serviceDeployWith(omitDeploymentFlags(f.args(), "--environment"), f.env)
		if (err != nil) != missingSJC || !slices.Contains(f.log, "put GRU "+releasechannel.ServiceReleaseObject("ts-auth")) ||
			slices.Contains(f.log, "put SJC "+releasechannel.ServiceReleaseObject("ts-auth")) == missingSJC {
			t.Fatalf("per-cell environment or failure isolation lost: missing=%v err=%v log=%v", missingSJC, err, f.log)
		}
	}
}

func TestDeploymentDiscoveryCannotSucceedEmptyUnreadableOrDuplicated(t *testing.T) {
	for _, cells := range [][]string{nil, {"GRU", "GRU"}, {"UNKNOWN"}} {
		if _, err := deploymentCells(t.Context(), nil, func(context.Context) ([]string, error) { return cells, nil }); err == nil {
			t.Fatalf("invalid discovered membership accepted: %v", cells)
		}
	}
	unavailable := errors.New("roster unavailable")
	if _, err := deploymentCells(t.Context(), nil, func(context.Context) ([]string, error) { return nil, unavailable }); !errors.Is(err, unavailable) {
		t.Fatal(err)
	}
}

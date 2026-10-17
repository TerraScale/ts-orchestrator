package bootstrapstart

import (
	"errors"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/ociclient"
)

func TestRuntimeIAMRejectsMissingSourcesAndCustomBinaryChecker(t *testing.T) {
	for _, name := range []string{"reader", "factory", "observer", "imds", "binary-checker"} {
		t.Run(name, func(t *testing.T) {
			reader, factory, observer := new(CurrentFounderAuthorityReader), new(ociclient.Factory), new(OCIInstanceObserver)
			imds, gate := NewIMDSClient(), Gate{}
			switch name {
			case "reader":
				reader = nil
			case "factory":
				factory = nil
			case "observer":
				observer = nil
			case "imds":
				imds = IMDSClient{}
			case "binary-checker":
				gate.Binary = executableBinaryChecker{}
			}
			proof, err := verifyRuntimeIAMWithSources(t.Context(), reader, AcceptedIdentity{}, factory, observer, imds, gate)
			if !errors.Is(err, ErrSourceFounder) || proof.IsVerified() {
				t.Fatalf("unsealed runtime IAM source admitted: verified=%v err=%v", proof.IsVerified(), err)
			}
		})
	}
}

package qualification

import (
	"errors"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

const (
	Domain                        = "terrascale.test.image-qualification"
	RootCredentialBoundaryPurpose = "root-credential-boundary"
)

// Scope preserves historical slots and requires an explicit slot for the writer.
func Scope(runID string, candidate release.ProductionExpectation, role string) trust.Scope {
	slot := candidate.Runtime + "/linux-" + candidate.Architecture
	if candidate.Role == release.FoundationWriterRole {
		slot += "/" + RootCredentialBoundaryPurpose
	}
	return trust.Scope{Domain: Domain, DeploymentID: entityid.Derive("qualification", runID), Cell: candidate.Cell,
		Environment: "qualification", Role: role, Slot: slot}
}

func ValidatePurpose(candidate release.ProductionExpectation, purpose string) error {
	if candidate.Role == release.FoundationWriterRole {
		if purpose != RootCredentialBoundaryPurpose || candidate.Runtime != release.ProductionRuntime || candidate.Architecture != "arm64" {
			return errors.New("foundation writer qualification requires explicit root credential boundary purpose")
		}
	} else if purpose != "" {
		return errors.New("qualification purpose is not authorized for candidate role")
	}
	return nil
}

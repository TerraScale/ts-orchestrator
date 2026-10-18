package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/region"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/releasechannel"
)

func retainGenericGenesisOwners(ctx context.Context, foundation region.FoundationResolver, hosts *host.Controller, cell, environment string) error {
	origins, err := foundation.GenericWorkloadGeneses(ctx, strings.ToUpper(cell), environment)
	if err != nil {
		return err
	}
	for _, original := range origins {
		guard := func(check context.Context) error {
			current, _, err := foundation.WorkloadGenesis(check, original.Origin().Cell, original.Origin().Role, original.Origin().Environment)
			if err != nil {
				return err
			}
			if current.Fingerprint() != original.Fingerprint() || current.Origin() != original.Origin() {
				return errors.New("original generic genesis changed before native owner fencing")
			}
			return check.Err()
		}
		if err := hosts.ClaimGenesisContainer(ctx, original, guard); err != nil {
			return err
		}
	}
	return nil
}

// Retained native records and their original signed claims remain unchanged.
func (history *nativeHistory) retainedContainerFloor(ctx context.Context, role, environment string) (release.SequenceFloor, error) {
	if history == nil || history.deliveries == nil || history.hosts == nil {
		return release.SequenceFloor{}, errors.New("retained native release evidence unavailable")
	}
	state, _, err := history.load(ctx, role)
	if err != nil {
		return release.SequenceFloor{}, err
	}
	var floor release.SequenceFloor
	bindings := nativeBindings(&state)
	for _, binding := range bindings {
		if binding.Intent.Environment != environment {
			return release.SequenceFloor{}, errors.New("retained native release names another environment")
		}
		if err := history.verifyProfile(role, binding.Profile, binding.Provenance); err != nil {
			return release.SequenceFloor{}, err
		}
		wire, err := history.deliveries.RetainedArtifactClaim(ctx, binding.Artifact.Digest, role, environment)
		if err != nil {
			return release.SequenceFloor{}, err
		}
		issued, err := releasechannel.ClaimIssuedAt(wire)
		if err != nil {
			return release.SequenceFloor{}, err
		}
		if issued.After(floor.IssuedAt) {
			digest := sha256.Sum256(wire)
			floor = release.SequenceFloor{Cell: strings.ToUpper(history.services.cell), IssuedAt: issued, EvidenceSHA256: hex.EncodeToString(digest[:])}
		}
	}
	if floor.IssuedAt.IsZero() {
		return release.SequenceFloor{}, errors.New("no retained authenticated native release floor; explicit root-authorized baseline required")
	}
	desired, err := history.hosts.ListDesired(ctx, role)
	if err != nil {
		return release.SequenceFloor{}, err
	}
	for _, target := range desired {
		if target.Environment != environment || target.Digest == "" {
			continue
		}
		covered := false
		for _, binding := range bindings {
			if target.ManagedMember == nil && target.Digest == binding.Artifact.Digest &&
				delivery.ConfigDigestOf(target.Args, target.Env, target.Secrets) == binding.Intent.ConfigDigest {
				covered = true
				break
			}
		}
		if !covered {
			return release.SequenceFloor{}, errors.New("current native desired lacks authenticated retained release and profile coverage")
		}
	}
	return floor, nil
}

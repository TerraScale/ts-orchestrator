package native

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
)

// RunRootCredentialBoundary qualifies the final disk's root credential boundary
// without fabricating a running cluster or granting workload admission.
func RunRootCredentialBoundary(ctx context.Context, req Request) (Report, release.RootCredentialBoundaryEvidence, error) {
	report := Report{RunID: req.RunID, Candidate: req.Candidate, ImageOCID: req.ImageOCID, StartedAt: time.Now().UTC()}
	evidence := release.RootCredentialBoundaryEvidence{Schema: release.RootCredentialBoundarySchema, Candidate: req.Candidate}
	if err := validateRootCredentialRequest(req); err != nil {
		return report, evidence, err
	}
	return runRootCredentialBoundary(ctx, req, report, evidence, func(ctx context.Context, h Host) (peer, error) { return connect(ctx, req, h) })
}

func validateRootCredentialRequest(req Request) error {
	if err := validateHostRequest(req); err != nil {
		return err
	}
	if req.Candidate.Role != release.FoundationWriterRole || req.Candidate.ImageOCID != req.ImageOCID || !shaPattern.MatchString(req.RootCredentialNamespaceSHA256) {
		return errors.New("root credential qualification requires the approved foundation-writer purpose and namespace")
	}
	if len(req.RootCredentialProofs) != len(req.Hosts) {
		return errors.New("root credential qualification requires one exact signed proof per approved host")
	}
	for _, h := range req.Hosts {
		proof, found := req.RootCredentialProofs[h.OCID]
		if !found || len(proof) == 0 || len(proof) > maxRootCredentialProofBytes {
			return errors.New("root credential qualification host proof absent or oversized")
		}
	}
	return nil
}

func runRootCredentialBoundary(ctx context.Context, req Request, report Report, evidence release.RootCredentialBoundaryEvidence, dial func(context.Context, Host) (peer, error)) (Report, release.RootCredentialBoundaryEvidence, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Minute)
	defer cancel()
	rec := new(recorder)
	for index, h := range req.Hosts {
		role := "manager"
		if index == 3 {
			role = "container"
		}
		if err := func() error {
			p, err := dial(ctx, h)
			if err != nil {
				return err
			}
			defer p.close()
			identityCommand := command{Operation: "credential-identity", RunID: req.RunID, SourceRevision: req.Candidate.SourceRevision, Host: h, Mode: role, ContainerdPath: req.ContainerdPath, RuncPath: req.RuncPath}
			observed, err := p.call(ctx, identityCommand)
			rec.event(h.OCID, identityCommand, observed, err)
			if err != nil {
				return err
			}
			if observed.Role != role || observed.Identity != h.ExpectedIdentity || observed.WorkerSHA256 != req.WorkerSHA256 || observed.WorkerSourceRevision != req.Candidate.SourceRevision {
				return errors.New("root credential host identity differs from approved native candidate")
			}
			report.Hosts = append(report.Hosts, HostReport{Role: role, OCID: h.OCID, Address: h.Address, Observed: observed.Identity, WorkerSHA256: observed.WorkerSHA256, WorkerSourceRevision: observed.WorkerSourceRevision})
			request := command{Operation: "root-credential-boundary", RootCredentialProof: req.RootCredentialProofs[h.OCID]}
			result, err := p.call(ctx, request)
			// Retain observations, never the signed credential-reader admission itself.
			rec.event(h.OCID, command{Operation: request.Operation}, result, err)
			if err != nil {
				return err
			}
			if result.RootCredentialBoundary == nil {
				return errors.New("installed candidate returned no root credential boundary evidence")
			}
			host := *result.RootCredentialBoundary
			if host.Role != role || host.InstanceID != h.OCID || host.ImageOCID != req.ImageOCID || host.SourceRevision != req.Candidate.SourceRevision || host.NamespaceSHA256 != req.RootCredentialNamespaceSHA256 {
				return errors.New("root credential result differs from approved host, image, source or namespace")
			}
			// A host observation must independently satisfy the release evidence shape;
			// the complete four-host topology is validated after collection.
			if host.RootUID != 0 || host.OrdinaryUID == 0 || host.RootOCIRead != "authenticated" || host.OrdinaryUIDIMDS != "refused" || host.OrdinaryUIDSigning != "refused" || host.UnauthorizedIPC != "refused" || len(host.Transcript) == 0 || len(host.Transcript) > maxFrame || digest(host.Transcript) != host.TranscriptSHA256 {
				return errors.New("root credential boundary operation did not prove authenticated reads and actual ordinary-user refusals")
			}
			host.Transcript = append([]byte(nil), host.Transcript...)
			evidence.Hosts = append(evidence.Hosts, host)
			return nil
		}(); err != nil {
			report.Scenarios = append(report.Scenarios, rec.scenario("failed-root-credential-boundary", "", report.StartedAt, req.Hosts))
			return report, evidence, fmt.Errorf("root credential host %s: %w", h.OCID, err)
		}
	}
	evidence.CompletedAt = time.Now().UTC()
	if err := evidence.Validate(req.Candidate); err != nil {
		return report, evidence, err
	}
	report.CompletedAt = evidence.CompletedAt
	report.Scenarios = append(report.Scenarios, rec.scenario(release.RootCredentialBoundaryGate, release.RootCredentialBoundaryGate, report.StartedAt, req.Hosts))
	return report, evidence, nil
}

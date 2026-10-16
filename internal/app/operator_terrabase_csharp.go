package app

import (
	"context"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/authority"

	"github.com/TerraScale/ts-orchestrator/internal/delivery"
	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/host"
	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/rollout"
	"github.com/TerraScale/ts-orchestrator/internal/seatrollout"
	"github.com/TerraScale/ts-orchestrator/internal/terrabase"
	"github.com/TerraScale/ts-orchestrator/internal/tsauth"
	"github.com/TerraScale/ts-orchestrator/internal/workload"
)

// terraBaseReleaseOptions select one C# TerraBase release and its rollout.
type terraBaseReleaseOptions struct {
	Binary, Checksum string // terrabase-linux-<arch> and its .sha256 release asset
	SourceCheckout   string // a TerraBase checkout that contains Commit
	Commit           string
	Environment      string
	Profile          string        // the controller's signed workloads.terrabase profile
	Wait             time.Duration // readiness gate per rollout; zero means the fixed observation budget
}

// operatorTerraBaseRelease admits a C# TerraBase release and rolls every
// member the profile's peer list names through native preparation. The release passes its readiness gate
// when every member reports the new digest running, which the host reports
// only after the member's /healthz answers. A release that fails the gate is
// rolled back to the digest the members ran before, which must pass the
// same gate; the command then fails.
func operatorTerraBaseRelease(ctx context.Context, cfg Config, runtime *natscell.Runtime, options terraBaseReleaseOptions, output io.Writer) error {
	// A progress line that cannot be written must not read as a failed gate.
	progress := &stickyWriter{writer: output}
	err := releaseTerraBase(ctx, cfg, runtime, options, progress)
	return errors.Join(err, progress.err)
}

func releaseTerraBase(ctx context.Context, cfg Config, runtime *natscell.Runtime, options terraBaseReleaseOptions, output io.Writer) error {
	digest, err := terrabase.VerifyRelease(options.Binary, options.Checksum)
	if err != nil {
		return err
	}
	profile, err := readReleaseProfile(options.Profile)
	if err != nil {
		return err
	}
	members, err := terrabase.ParseProfile(profile.Env)
	if err != nil {
		return err
	}
	return releaseNative(ctx, cfg, runtime, nativeRelease{Role: terrabase.Role, Repository: terrabase.Repository,
		Digest: digest, Replicas: len(members.Peers), Profile: profile}, options, output)
}

// operatorTSAuthRelease admits a ts-auth release and rolls its replicas to
// it through the same readiness gate and rollback as a TerraBase release. A
// replica reports running only while its /healthz and /readyz answer.
func operatorTSAuthRelease(ctx context.Context, cfg Config, runtime *natscell.Runtime, options terraBaseReleaseOptions, output io.Writer) error {
	progress := &stickyWriter{writer: output}
	err := func() error {
		digest, err := tsauth.VerifyRelease(options.Binary, options.Checksum)
		if err != nil {
			return err
		}
		profile, err := readReleaseProfile(options.Profile)
		if err != nil {
			return err
		}
		if err := tsauth.ValidateProfile(cfg.NATS.Cell, profile.Args, profile.Env, profile.Secrets); err != nil {
			return err
		}
		return releaseNative(ctx, cfg, runtime, nativeRelease{Role: tsauth.Role, Repository: tsauth.Repository,
			Digest: digest, Replicas: tsauth.Replicas, Profile: profile}, options, progress)
	}()
	return errors.Join(err, progress.err)
}

// readReleaseProfile reads the role's signed controller workload profile.
func readReleaseProfile(path string) (WorkloadProfile, error) {
	data, err := readBoundedConfigFile(path)
	if err != nil {
		return WorkloadProfile{}, err
	}
	var profile WorkloadProfile
	if err := json.Unmarshal(data, &profile, json.RejectUnknownMembers(true)); err != nil {
		return WorkloadProfile{}, fmt.Errorf("parse workload profile: %w", err)
	}
	return profile, nil
}

// nativeRelease is one verified single-file release of a role and the
// replica count its readiness gate waits for.
type nativeRelease struct {
	Role, Repository, Digest string
	Replicas                 int
	Profile                  WorkloadProfile
}

func releaseNative(ctx context.Context, cfg Config, runtime *natscell.Runtime, target nativeRelease, options terraBaseReleaseOptions, output io.Writer) error {
	if options.Wait == 0 {
		options.Wait = rollout.ObservationBudget
	}
	tree, err := release.SourceTreeDigest(ctx, options.SourceCheckout, options.Commit)
	if err != nil {
		return err
	}
	deadline := time.Now().UTC().Add(min(options.Wait, rollout.ObservationBudget))
	deployer, err := operatorNativeDeployer(ctx, cfg, runtime, deadline)
	if err != nil {
		return err
	}
	previous, generation, err := deployer.current(ctx, target.Role, options.Environment)
	if err != nil {
		return err
	}
	record, err := pushArtifact(ctx, cfg, runtime, options.Binary, delivery.ArtifactClaimRequest{
		Source: delivery.ArtifactSource{Repository: target.Repository, Commit: options.Commit, TreeDigest: tree},
		Cell:   cfg.NATS.Cell, Role: target.Role, Environment: options.Environment,
	})
	if err != nil {
		return err
	}
	if record.Digest != target.Digest {
		return fmt.Errorf("controller admitted %s, the release pins %s", record.Digest, target.Digest)
	}
	if err := printJSON(output, terraBaseReleaseStep{Step: "artifact", Digest: record.Digest, Previous: previous}); err != nil {
		return err
	}
	return deployer.roll(ctx, nativeIntent(record, target, generation), options.Wait, output)
}

func operatorNativeDeployer(ctx context.Context, cfg Config, runtime *natscell.Runtime, deadline time.Time) (nativeDeployer, error) {
	setupCtx, stopSetup := context.WithTimeout(ctx, operatorSubmitSetupTimeout)
	defer stopSetup()
	reader, err := retryOperatorMetadata(setupCtx, func(attempt context.Context) (*host.Reader, error) {
		return operatorHostReader(attempt, cfg, runtime)
	})
	if err != nil {
		return nativeDeployer{}, err
	}
	service, err := retryOperatorMetadata(setupCtx, func(attempt context.Context) (*delivery.Service, error) {
		return operatorService(attempt, cfg, runtime, true)
	})
	if err != nil {
		return nativeDeployer{}, err
	}
	return nativeDeployer{service: service, hosts: reader,
		prepare: func(ctx context.Context, intent delivery.Intent, recoveryOf, resumeOf string) (delivery.Intent, *nativeRollbackTarget, error) {
			if intent.SchemaVersion == 0 {
				intent.SchemaVersion = delivery.SchemaVersion
			}
			if intent.Cell == "" {
				intent.Cell = cfg.NATS.Cell
			}
			if intent.OperationID == "" {
				intent.OperationID = entityid.New()
			}
			if intent.AuthorityEpoch == 0 {
				readCtx, stopRead := context.WithTimeout(ctx, operatorSubmitSetupTimeout)
				epoch, err := observeOperatorAuthority(readCtx, func(attempt context.Context) (authority.Snapshot, error) {
					return authority.Observe(attempt, runtime.JetStream(), cfg.NATS.Cell)
				})
				stopRead()
				if err != nil {
					return intent, nil, err
				}
				intent.AuthorityEpoch = epoch
			}
			reply, err := requestNativeRelease(ctx, cfg, runtime, nativePrepareKind, nativePrepareRequest{Intent: intent, RecoveryOf: recoveryOf, ResumeOf: resumeOf, Deadline: deadline})
			return reply.Intent, reply.Previous, err
		},
		observe: func(ctx context.Context, intent delivery.Intent) (bool, error) {
			reply, err := requestNativeRelease(ctx, cfg, runtime, nativeObserveKind, nativePrepareRequest{Intent: intent})
			return reply.Ready, err
		},
		submit: func(ctx context.Context, intent delivery.Intent) (delivery.Intent, string, error) {
			return submitTerraBaseIntent(ctx, cfg, runtime, intent)
		}}, nil
}

// errReplicasDisagree refuses a release while the role's running replicas
// serve different digests.
var errReplicasDisagree = errors.New("finish the previous release first")

// errRollbackUnfinished reports a rollback that did not pass its gate: it
// may still be applying.
var errRollbackUnfinished = errors.New("the rollback has not finished")

// errRecoveryNotStarted reports a rollback that recovering refused before it
// was submitted.
var errRecoveryNotStarted = errors.New("the rollback was not started")

// errBadRelease is evidence against a release itself: a replica reported it
// failed, or its canary failed the gate. A timeout or a lost lease is not.
var errBadRelease = errors.New("the release is bad")

// nativeDeployer rolls a native role out to an admitted release through the
// readiness gate and rolls a release that fails it back. The operator's
// release commands and the leader's service release channel (TS-610) share
// it; submit signs, or records as verified, and publishes one intent.
type nativeDeployer struct {
	service *delivery.Service
	hosts   seatrollout.Hosts
	submit  func(context.Context, delivery.Intent) (delivery.Intent, string, error)
	prepare func(context.Context, delivery.Intent, string, string) (delivery.Intent, *nativeRollbackTarget, error)
	observe func(context.Context, delivery.Intent) (bool, error)
	target  *nativeRollbackTarget
	bound   bool
	// recovering, when set, records the rollback intent, and the gate error
	// that caused it, before roll submits it and returns the intent to
	// submit.
	recovering func(context.Context, delivery.Intent, error) (delivery.Intent, error)
	// sequence, when set, restarts an accepted intent's nodes one at a
	// time (a release fence) before the readiness gate counts them, the
	// first passing canary when it is set (TS-623).
	sequence func(context.Context, delivery.Intent, canaryGate) error
	canary   canaryGate
}

// current returns the digest the role's running replicas serve, the
// rollback target, and the next intent generation (releaseCurrent).
func (d nativeDeployer) current(ctx context.Context, role, environment string) (string, uint64, error) {
	statuses, err := d.hosts.ListHosts(ctx)
	if err != nil {
		return "", 0, err
	}
	desired, err := d.hosts.ListDesired(ctx, role)
	if err != nil {
		return "", 0, err
	}
	return releaseCurrent(statuses, desired, role, environment)
}

// nativeIntent is the intent that moves every replica of release's role to
// the admitted record.
func nativeIntent(record delivery.ArtifactRecord, release nativeRelease, generation uint64) delivery.Intent {
	profile := release.Profile
	return delivery.Intent{Source: record.Source, ArtifactDigest: record.Digest, ManifestDigest: record.ManifestDigest,
		Cell: record.Cell, Role: record.Role, Environment: record.Environment, Generation: generation, DesiredReplicas: release.Replicas,
		ConfigDigest: delivery.ConfigDigestOf(profile.Args, profile.Env, profile.Secrets)}
}

// roll submits intent and waits for its readiness gate. A release that
// fails the gate is rolled back to its persisted target, which must
// pass the same gate; roll then fails.
func (d nativeDeployer) roll(ctx context.Context, intent delivery.Intent, wait time.Duration, output io.Writer) error {
	if d.prepare == nil || d.observe == nil {
		return errors.New("native deployer requires signed profile preparation and verified observation")
	}
	good := d.target
	var rollback delivery.ArtifactRecord
	if !d.bound {
		var err error
		intent, good, err = d.prepare(ctx, intent, "", "")
		if err != nil {
			return fmt.Errorf("%s release %s did not reach the members: prepare native release before host changes: %w", intent.Role, intent.ArtifactDigest, err)
		}
	}
	if good != nil {
		rollback = good.Artifact
	}
	role, digest, generation := intent.Role, intent.ArtifactDigest, intent.Generation
	forwardIntent := intent
	previous := rollback.Digest
	changed, gateErr := d.rollOut(ctx, intent, wait, output)
	switch {
	case gateErr == nil:
		return nil
	case !changed:
		return fmt.Errorf("%s release %s did not reach the members: %w", role, digest, gateErr)
	case rollback.Digest == "":
		return fmt.Errorf("%s release %s failed its readiness gate and there is no previous digest to roll back to: %w", role, digest, gateErr)
	}
	intent.Source, intent.ArtifactDigest, intent.ManifestDigest = rollback.Source, rollback.Digest, rollback.ManifestDigest
	if good != nil {
		intent.ConfigDigest, intent.DesiredReplicas = good.ConfigDigest, good.Replicas
	}
	intent.OperationID, intent.AuthorityEpoch, intent.Generation = "", 0, generation+1
	// A rollback restores what served before; no canary gates it.
	d.canary = nil
	// A fresh context with its own deadline: the command's context may be
	// the one that expired or was interrupted.
	recoveryWait := rollout.ObservationBudget
	recovery, cancel := context.WithTimeout(context.Background(), recoveryWait+time.Minute)
	defer cancel()
	desired, err := d.hosts.ListDesired(recovery, role)
	if err != nil {
		return fmt.Errorf("%w: read committed rollback generation: %w", errRecoveryNotStarted, err)
	}
	intent.Generation = max(intent.Generation, nextReleaseGeneration(desired))
	if generation == ^uint64(0) || intent.Generation == 0 {
		return fmt.Errorf("%w: %w", errRecoveryNotStarted, workload.ErrGenerationSpace)
	}
	if d.recovering != nil {
		var err error
		if intent, err = d.recovering(recovery, intent, gateErr); err != nil {
			return fmt.Errorf("%s release %s failed its readiness gate (%w): %w: %w", role, digest, gateErr, errRecoveryNotStarted, err)
		}
	}
	if d.prepare != nil {
		var err error
		if intent, _, err = d.prepare(recovery, intent, forwardIntent.OperationID, ""); err != nil {
			return fmt.Errorf("%w: %w", errRecoveryNotStarted, err)
		}
	}
	if _, err := d.rollOut(recovery, intent, recoveryWait, output); err != nil {
		return fmt.Errorf("%s release %s failed its readiness gate (%w) and rollback to %s failed: %w: %w", role, digest, gateErr, previous, errRollbackUnfinished, err)
	}
	return fmt.Errorf("%s release %s failed its readiness gate and was rolled back to %s: %w", role, digest, previous, gateErr)
}

// submitTerraBaseIntent is submitIntent; tests replace it to lose a publish
// acknowledgement.
var submitTerraBaseIntent = submitIntent

// rollOut submits one release intent and waits for its readiness
// gate. changed reports whether the release may have written, or may still
// write, any member's desired; a rollback is due whenever it is set. A
// submit that failed before Submit was called published nothing. Any later
// submit error or an interrupt proves nothing, since the intent may have
// been published: the durable operation is read back, and only a receipt
// that proves no member changed clears changed. Read errors are retried
// until wait.
func (d nativeDeployer) rollOut(ctx context.Context, intent delivery.Intent, wait time.Duration, output io.Writer,
) (changed bool, _ error) {
	wait = min(wait, rollout.ObservationBudget)
	service := d.service
	if d.observe == nil {
		return false, errors.New("native release requires verified observation")
	}
	if wait <= 0 {
		// An expired persisted intent may already have changed members.
		return true, context.DeadlineExceeded
	}
	gateCtx, cancel := context.WithTimeout(ctx, wait)
	defer cancel()
	intent, fingerprint, submitErr := d.submit(gateCtx, intent)
	if submitErr != nil && fingerprint == "" {
		return false, submitErr
	}
	tick := time.NewTicker(time.Second)
	defer tick.Stop()
	accepted := false
	var last error
	for {
		if !accepted {
			receipt, err := service.StatusFor(gateCtx, intent)
			switch {
			case err != nil:
				last = err
			case receipt.Status == "accepted":
				accepted = true
				if err := printJSON(output, terraBaseReleaseStep{Step: "deploy", Digest: intent.ArtifactDigest, Generation: intent.Generation}); err != nil {
					return true, err
				}
				if d.sequence != nil {
					if err := d.sequence(gateCtx, intent, d.canary); err != nil {
						return true, err
					}
				}
			default:
				return !unchanged(receipt), errors.Join(submitErr, fmt.Errorf("delivery %s: %s", receipt.Status, receipt.Error))
			}
		}
		if accepted {
			ready, err := d.observe(gateCtx, intent)
			last = err
			if errors.Is(err, errBadRelease) {
				return true, err
			}
			if err == nil && ready {
				return true, printJSON(output, terraBaseReleaseStep{Step: "ready", Digest: intent.ArtifactDigest, Members: intent.DesiredReplicas})
			}
		}
		select {
		case <-gateCtx.Done():
			if accepted {
				return true, errors.Join(gateCtx.Err(), fmt.Errorf(
					"%s replicas did not report %s running within %s (last error: %v)", intent.Role, intent.ArtifactDigest, wait, last))
			}
			// Interrupted or undecided: read the stored outcome once more on a
			// fresh context. Without a receipt that proves no change, the
			// release may still land; the rollback's higher generation keeps
			// it from landing.
			readCtx, cancelRead := context.WithTimeout(context.Background(), 10*time.Second)
			receipt, err := service.StatusFor(readCtx, intent)
			cancelRead()
			undecided := fmt.Errorf("delivery of operation %s was not decided within %s (last error: %v)", intent.OperationID, wait, last)
			if err == nil && unchanged(receipt) {
				return false, errors.Join(submitErr, gateCtx.Err(), fmt.Errorf("delivery %s: %s", receipt.Status, receipt.Error))
			}
			return true, errors.Join(submitErr, gateCtx.Err(), undecided)
		case <-tick.C:
		}
	}
}

func requestNativeRelease(ctx context.Context, cfg Config, runtime *natscell.Runtime, kind string, request nativePrepareRequest) (nativePrepareReply, error) {
	wire, err := json.Marshal(request)
	if err != nil {
		return nativePrepareReply{}, err
	}
	if len(wire) > maxRegistrationBytes || int64(len(wire)+nativePayloadOverhead) > runtime.Conn().MaxPayload() {
		return nativePrepareReply{}, errors.New("native release request exceeds broker payload bound")
	}
	wire, err = requestLeader(ctx, cfg, runtime, kind, "native release", wire)
	if err != nil {
		return nativePrepareReply{}, err
	}
	var reply nativePrepareReply
	if err := protocol.DecodeStrict(wire, &reply, maxRegistrationBytes); err != nil {
		return reply, err
	}
	if reply.Error != "" {
		if strings.Contains(reply.Error, errBadRelease.Error()) {
			return reply, fmt.Errorf("%w: %s", errBadRelease, reply.Error)
		}
		return reply, errors.New(reply.Error)
	}
	return reply, nil
}

// unchanged reports whether a durable delivery receipt proves that no
// member's desired was written: a rejection, or a hold from the placement
// planner, which comes before every write.
func unchanged(receipt delivery.Receipt) bool {
	return receipt.Status == "rejected" || receipt.Status == "held" && !heldAfterPlanning(receipt)
}

// heldAfterPlanning reports whether a held delivery may have written members:
// only a hold from the placement planner comes before every write.
func heldAfterPlanning(receipt delivery.Receipt) bool {
	return !strings.HasPrefix(receipt.Error, delivery.PlannerRefusedHold)
}

// terraBaseReleaseStep is one progress line of terrabase-release.
type terraBaseReleaseStep struct {
	Step       string `json:"step"`
	Digest     string `json:"digest"`
	Previous   string `json:"previous,omitempty"`
	Generation uint64 `json:"generation,omitzero"`
	Members    int    `json:"members,omitzero"`
}

// releaseCurrent returns the running replicas' digest for progress and the
// next intent generation, above every
// committed desired of the role, withdrawals included. A role the workload
// reconciler owns commits release-scoped generations (release <<
// workload.ReleaseShift), so its next intent is the next release. Running
// replicas that disagree must be reconciled first.
func releaseCurrent(statuses []host.HostStatus, desired []host.Desired, role, environment string) (string, uint64, error) {
	current := ""
	for _, status := range statuses {
		for _, report := range status.Reports {
			if report.Role != role || report.Environment != environment || report.State != "running" {
				continue
			}
			if current != "" && report.Digest != current {
				return "", 0, fmt.Errorf("%s replicas run %s and %s: %w", role, current, report.Digest, errReplicasDisagree)
			}
			current = report.Digest
		}
	}
	return current, nextReleaseGeneration(desired), nil
}

// nextReleaseGeneration is the next intent generation of a role, above every
// committed desired of it (releaseCurrent).
func nextReleaseGeneration(desired []host.Desired) uint64 {
	highest := uint64(0)
	for _, d := range desired {
		highest = max(highest, d.Generation)
	}
	if release := workload.ReleaseOf(highest); release > 0 {
		highest = release
	}
	return highest + 1
}

// stickyWriter keeps the first write error and drops later output, so a
// broken stdout cannot interrupt a rollout or its rollback.
type stickyWriter struct {
	writer io.Writer
	err    error
}

func (w *stickyWriter) Write(data []byte) (int, error) {
	if w.err == nil {
		_, w.err = w.writer.Write(data)
	}
	return len(data), nil
}

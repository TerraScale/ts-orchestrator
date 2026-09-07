package hostcontrol

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/delivery"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	runtimeplan "terrascale.tech/orchestrator/src/orchestrator/runtime"
)

// Release is an immutable desired manifest and CAS predecessor admitted for
// this delivery request. It must include every component on the host. Artifact
// URL, signature URL, version, digest, architecture and configuration must come
// from the authenticated release/catalog records, never from a status sample.
type Release struct {
	Manifest            hostmanifest.HostManifest
	ExpectedManifestSHA string
	Architecture        runtimeplan.HostArchitecture
}

type DeliveryConfig struct {
	Client         *Client
	ResolveRelease func(context.Context, string, runtimeplan.HostRuntimePlan) (Release, error)
	Timeout        time.Duration
	PollInterval   time.Duration
}

type DeliveryControl struct{ config DeliveryConfig }

var _ delivery.HostControl = (*DeliveryControl)(nil)

func NewDeliveryControl(config DeliveryConfig) (*DeliveryControl, error) {
	if config.Client == nil || config.ResolveRelease == nil || config.Timeout <= 0 || config.Timeout > 10*time.Minute || config.PollInterval <= 0 || config.PollInterval > time.Second {
		return nil, errors.New("hostcontrol: delivery requires client, authenticated release resolver, bounded timeout and poll interval")
	}
	// Bind the delivery journal fence to the final publication check too,
	// after admission resolution; a separate bootstrap consumer of the
	// original client keeps its own authority protocol.
	client, err := New(config.Client.config)
	if err != nil {
		return nil, err
	}
	authorize := client.config.Authorize
	client.config.Authorize = func(ctx context.Context, host Host) error {
		if err := authorize(ctx, host); err != nil {
			return err
		}
		return delivery.CheckExecutionFence(ctx)
	}
	config.Client = client
	return &DeliveryControl{config: config}, nil
}
func commandIdentity(ctx context.Context, host, action string, payload any) (string, error) {
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(data)
	return delivery.HostCommandID(ctx, host, action, hex.EncodeToString(sum[:]))
}
func (d *DeliveryControl) Cordon(ctx context.Context, host string, cordoned bool) error {
	id, err := commandIdentity(ctx, host, "drain", cordoned)
	if err != nil {
		return err
	}
	if err = delivery.CheckExecutionFence(ctx); err != nil {
		return err
	}
	_, err = d.config.Client.SetDrain(ctx, host, id, cordoned)
	if err != nil {
		return err
	}
	report, err := d.config.Client.Status(ctx, host)
	if err != nil {
		return err
	}
	if (report.State != hostagent.NodeStateServing) != cordoned {
		return errors.New("hostcontrol: fresh status differs from drain receipt")
	}
	return nil
}
func (d *DeliveryControl) DrainStatus(ctx context.Context, host string) (delivery.DrainReport, error) {
	report, err := d.config.Client.Status(ctx, host)
	if err != nil {
		return delivery.DrainReport{}, err
	}
	return delivery.DrainReport{Cordoned: report.State != hostagent.NodeStateServing, Drained: report.Quiesced}, nil
}

func (d *DeliveryControl) ObserveRelease(ctx context.Context, host string) (delivery.HostReleaseState, error) {
	if ctx == nil {
		return delivery.HostReleaseState{}, errors.New("hostcontrol: context is required")
	}
	report, err := d.config.Client.Status(ctx, host)
	if err != nil {
		return delivery.HostReleaseState{}, err
	}
	for _, component := range report.Facts.Components {
		if component.Name == "terrabase" {
			if component.ArtifactSHA256 == "" || report.Facts.ManifestSha256 == "" {
				return delivery.HostReleaseState{}, errors.New("hostcontrol: status lacks exact release identity")
			}
			return delivery.HostReleaseState{ArtifactDigest: "sha256:" + component.ArtifactSHA256, ManifestDigest: "sha256:" + report.Facts.ManifestSha256, Serving: report.State == hostagent.NodeStateServing}, nil
		}
	}
	return delivery.HostReleaseState{}, errors.New("hostcontrol: status lacks terrabase identity")
}

// Converge installs and activates the exact authenticated manifest/version.
// Rollback reaches this same path with its explicitly admitted rollback digest;
// it never guesses that the previous symlink is the requested artifact.
func (d *DeliveryControl) Converge(ctx context.Context, host string, encoded []byte) error {
	if ctx == nil {
		return errors.New("hostcontrol: context is required")
	}
	ctx, cancel := context.WithTimeout(ctx, d.config.Timeout)
	defer cancel()
	if err := delivery.CheckExecutionFence(ctx); err != nil {
		return err
	}
	if len(encoded) == 0 || len(encoded) > 64*1024 {
		return errors.New("hostcontrol: runtime plan exceeds bound")
	}
	var plan runtimeplan.HostRuntimePlan
	if err := json.Unmarshal(encoded, &plan); err != nil {
		return err
	}
	admitted, err := d.config.Client.AdmittedHost(ctx, host)
	if err != nil {
		return err
	}
	if plan.Role != runtimeplan.AdmittedRoleTerraBaseMember || plan.AllocationId.Value != "terrabase" || plan.Systemd == nil || plan.Driver != runtimeplan.RuntimeDriverNativeSystemd || plan.Architecture != admitted.Architecture {
		return errors.New("hostcontrol: runtime plan does not match admitted host architecture and driver")
	}
	release, err := d.config.ResolveRelease(ctx, host, plan)
	if err != nil {
		return err
	}
	if release.Architecture != admitted.Architecture {
		return errors.New("hostcontrol: release architecture differs from admitted host")
	}
	canonical, err := hostmanifest.CanonicalHostManifestJSON(release.Manifest)
	if err != nil {
		return err
	}
	manifest, err := hostmanifest.ParseHostManifest(canonical)
	if err != nil {
		return err
	}
	targetSHA, err := hostmanifest.HostManifestSha256(manifest)
	if err != nil {
		return err
	}
	var target *hostmanifest.ComponentSpec
	for i := range manifest.Components {
		spec := &manifest.Components[i]
		if spec.Name == plan.AllocationId.Value {
			target = spec
			break
		}
	}
	if target == nil || target.Sha256 != plan.ArtifactDigest.Value || hostagent.UnitName(target.Name) != plan.Systemd.UnitName {
		return errors.New("hostcontrol: runtime plan has no exact admitted signed release mapping")
	}
	if _, err := hostmanifest.NewApplyManifestCommand("validate", release.ExpectedManifestSHA, manifest); err != nil {
		return err
	}
	report, err := d.config.Client.Status(ctx, host)
	if err != nil {
		return err
	}
	// A fresh exact installed/current observation makes replay after an
	// acknowledged deployment idempotent without stopping the target again.
	if exactActive(report, targetSHA, *target) {
		return nil
	}
	if report.State == hostagent.NodeStateServing || !report.Quiesced {
		// This also handles rollback after a failed release-drain. Its identity
		// differs from the rollout's initial drain, whose old receipt may replay.
		id, err := commandIdentity(ctx, host, "converge-drain", plan.ArtifactDigest.Value)
		if err != nil {
			return err
		}
		if err = delivery.CheckExecutionFence(ctx); err != nil {
			return err
		}
		if _, err = d.config.Client.SetDrain(ctx, host, id, true); err != nil {
			return err
		}
	}
	if err := d.poll(ctx, host, func(report hostagent.NodeStatusReport) bool {
		return report.State != hostagent.NodeStateServing && report.Quiesced
	}); err != nil {
		return err
	}
	if report.Facts.ManifestSha256 != targetSHA {
		id, err := commandIdentity(ctx, host, "apply-manifest", struct {
			Expected string
			Manifest json.RawMessage
		}{release.ExpectedManifestSHA, canonical})
		if err != nil {
			return err
		}
		if err = delivery.CheckExecutionFence(ctx); err != nil {
			return err
		}
		if _, err = d.config.Client.ApplyManifest(ctx, host, id, release.ExpectedManifestSHA, manifest); err != nil {
			return err
		}
	}
	if err := d.poll(ctx, host, func(report hostagent.NodeStatusReport) bool {
		if report.Facts.ManifestSha256 != targetSHA {
			return false
		}
		for _, fact := range report.Facts.Components {
			if fact.Name == target.Name {
				return fact.Desired == target.Version && fact.Installed
			}
		}
		return false
	}); err != nil {
		return err
	}
	id, err := commandIdentity(ctx, host, "deploy", struct{ Component, Version, Digest string }{target.Name, target.Version, target.Sha256})
	if err != nil {
		return err
	}
	if err = delivery.CheckExecutionFence(ctx); err != nil {
		return err
	}
	if _, err = d.config.Client.Deploy(ctx, host, id, target.Name, target.Version); err != nil {
		return err
	}
	return d.poll(ctx, host, func(report hostagent.NodeStatusReport) bool { return exactActive(report, targetSHA, *target) })
}
func (d *DeliveryControl) poll(ctx context.Context, host string, ready func(hostagent.NodeStatusReport) bool) error {
	for {
		report, err := d.config.Client.Status(ctx, host)
		if err != nil {
			return err
		}
		if ready(report) {
			return nil
		}
		timer := time.NewTimer(d.config.PollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return ctx.Err()
		case <-timer.C:
		}
	}
}

func exactActive(report hostagent.NodeStatusReport, manifestSHA string, target hostmanifest.ComponentSpec) bool {
	if report.Facts.ManifestSha256 != manifestSHA {
		return false
	}
	for _, fact := range report.Facts.Components {
		if fact.Name == target.Name {
			return fact.Version == target.Version && fact.Desired == target.Version && fact.Installed && fact.UnitActive
		}
	}
	return false
}

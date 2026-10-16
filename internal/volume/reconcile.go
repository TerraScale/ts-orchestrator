package volume

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/authority"
	"github.com/TerraScale/ts-orchestrator/internal/naming"
)

// Ownership tags, the same keys internal/oci gives retained volumes.
const (
	tagManagedBy   = "terrascale-managed-by"
	tagOwner       = "terrascale-owner"
	tagResource    = "terrascale-resource"
	tagCreateKey   = "terrascale-create-key"
	tagApp         = "terrascale-app"
	managedBy      = "ts-orchestrator"
	resourceVolume = "managed-volume"
	resourcePolicy = "managed-volume-backup-policy"
)

// Settings are a cell's managed volume settings.
//
// ponytail: one availability domain per cell, which every current region
// has; a multi-AD region lists its zones here.
type Settings struct {
	CompartmentID string `json:"compartment_id"`
	Zone          string `json:"zone"`
	// KMSKeyID is the regional Vault key every new volume is encrypted with.
	KMSKeyID string `json:"kms_key_id"`
}

// Validate requires a compartment, a zone and a KMS key.
func (s Settings) Validate() error {
	if !isOCID(s.CompartmentID, "compartment") || !zoneRE.MatchString(s.Zone) || !isOCID(s.KMSKeyID, "key") {
		return fmt.Errorf("%w: managed volumes need a compartment OCID, a zone and a KMS key OCID", ErrInvalid)
	}
	return nil
}

// errHold marks a volume the reconciler must not act on: its record is
// marked failed with the reason until an operator resolves it.
var errHold = errors.New("managed volume needs an operator")

func hold(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errHold, fmt.Sprintf(format, args...))
}

// Reconciler converges the cell's volume records with OCI. It runs on the
// authority leader; every OCI effect and status write is guarded at the
// epoch the pass started under.
type Reconciler struct {
	Store    *Store
	Cloud    Cloud
	Fencer   authority.Fencer
	Settings Settings
}

type pass struct {
	*Reconciler
	epoch    uint64
	owner    string
	volumes  []CloudVolume
	listed   bool
	policies []BackupPolicy
}

// Pass reconciles every volume once. A follower does nothing. Errors of one
// volume do not stop the others.
func (r *Reconciler) Pass(ctx context.Context) error {
	snapshot := r.Fencer.Current()
	if !snapshot.CanMutate() {
		return nil
	}
	if err := r.Settings.Validate(); err != nil {
		return err
	}
	owner, err := naming.RegionCell(r.Store.region).Name()
	if err != nil {
		return err
	}
	records, err := r.Store.List(ctx)
	if err != nil {
		return err
	}
	p := &pass{Reconciler: r, epoch: snapshot.Epoch, owner: owner}
	var errs []error
	for _, v := range records {
		if v.Destroying() || v.Status.State == StateDestroyed {
			continue
		}
		if err := p.reconcile(ctx, v); err != nil {
			errs = append(errs, fmt.Errorf("volume %s: %w", v.ID, err))
		}
	}
	return errors.Join(errs...)
}

func (p *pass) guard(ctx context.Context) error { return p.Fencer.Guard(ctx, p.epoch) }

func (p *pass) reconcile(ctx context.Context, v Volume) error {
	status, err := p.converge(ctx, v)
	if errors.Is(err, errHold) {
		status = v.Status
		status.State, status.Message = StateFailed, err.Error()
		err = nil
	}
	if err != nil {
		return err
	}
	if status == v.Status {
		return nil
	}
	status.Epoch = p.epoch
	if err := p.guard(ctx); err != nil {
		return err
	}
	v.Status = status
	_, err = p.Store.Update(ctx, v)
	return err
}

// converge drives one volume a step towards its record and returns the
// status OCI now shows.
func (p *pass) converge(ctx context.Context, v Volume) (Status, error) {
	cloud, err := p.observe(ctx, v)
	if err != nil {
		return Status{}, err
	}
	if cloud.ID == "" {
		if cloud, err = p.create(ctx, v); err != nil {
			return Status{}, err
		}
	}
	status := v.Status
	status.OCID, status.Message = cloud.ID, ""
	switch cloud.State {
	case "PROVISIONING", "RESTORING":
		if status.State != StateCreating {
			return Status{}, hold("OCI volume %s is %s", cloud.ID, cloud.State)
		}
		return status, nil
	case "AVAILABLE":
	default:
		return Status{}, hold("OCI volume %s is %s", cloud.ID, cloud.State)
	}
	status.State, status.SizeGB = StateCreated, cloud.SizeGB
	// One change per pass: OCI applies them one at a time, and the next
	// pass reads the new ETag.
	switch {
	case v.SizeGB > cloud.SizeGB:
		if err := p.guard(ctx); err != nil {
			return Status{}, err
		}
		return status, p.Cloud.ResizeVolume(ctx, cloud.ID, cloud.ETag, v.SizeGB)
	case v.VPUsPerGB != cloud.VPUsPerGB:
		if err := p.guard(ctx); err != nil {
			return Status{}, err
		}
		return status, p.Cloud.SetVolumePerformance(ctx, cloud.ID, cloud.ETag, v.VPUsPerGB)
	}
	return status, p.ensurePolicy(ctx, v, cloud.ID)
}

// observe returns the record's OCI volume, or the zero CloudVolume when it
// has none yet. A volume is the record's only while it carries this
// cell's ownership tags and the record's ID and is encrypted with the
// cell's KMS key; the volume read last, not a listing, is what is checked.
func (p *pass) observe(ctx context.Context, v Volume) (CloudVolume, error) {
	if v.Zone != p.Settings.Zone {
		return CloudVolume{}, hold("zone %s is not this cell's zone %s", v.Zone, p.Settings.Zone)
	}
	id := v.Status.OCID
	if id == "" {
		if !p.listed {
			volumes, err := p.Cloud.ListVolumes(ctx, p.Settings.CompartmentID, p.Settings.Zone)
			if err != nil {
				return CloudVolume{}, err
			}
			p.volumes, p.listed = volumes, true
		}
		var found []string
		for _, cloud := range p.volumes {
			if p.owns(cloud, v) {
				found = append(found, cloud.ID)
			}
		}
		switch len(found) {
		case 0:
			return CloudVolume{}, nil
		case 1:
			id = found[0]
		default:
			return CloudVolume{}, hold("%d OCI volumes carry volume %s", len(found), v.ID)
		}
	}
	cloud, err := p.Cloud.GetVolume(ctx, id)
	switch {
	case errors.Is(err, ErrGone):
		return CloudVolume{}, hold("OCI volume %s is gone", id)
	case err != nil:
		return CloudVolume{}, err
	case !p.owns(cloud, v):
		return CloudVolume{}, hold("OCI volume %s is not this cell's volume %s", id, v.ID)
	case cloud.KMSKeyID != p.Settings.KMSKeyID:
		// A changed cell key holds the volume until an operator re-keys it.
		return CloudVolume{}, hold("OCI volume %s is not encrypted with the cell's KMS key", id)
	}
	return cloud, nil
}

func (p *pass) owns(cloud CloudVolume, v Volume) bool {
	return cloud.Tags[tagManagedBy] == managedBy && cloud.Tags[tagOwner] == p.owner &&
		cloud.Tags[tagResource] == resourceVolume && cloud.Tags[tagCreateKey] == v.ID &&
		cloud.CompartmentID == p.Settings.CompartmentID && cloud.Zone == v.Zone
}

func retryToken(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, ":")))
	return hex.EncodeToString(sum[:])
}

// create makes the record's OCI volume. The retry token is the record's,
// so a create whose response was lost returns the same volume, and the
// tags bind it to the record on the next pass either way.
func (p *pass) create(ctx context.Context, v Volume) (CloudVolume, error) {
	if v.Status.State != StateCreating {
		return CloudVolume{}, hold("volume %s lost its OCI volume", v.ID)
	}
	if err := p.guard(ctx); err != nil {
		return CloudVolume{}, err
	}
	return p.Cloud.CreateVolume(ctx, CreateRequest{
		CompartmentID: p.Settings.CompartmentID, Zone: v.Zone, DisplayName: p.owner + "-" + v.App + "-" + v.ID,
		SizeGB: v.SizeGB, VPUsPerGB: v.VPUsPerGB, KMSKeyID: p.Settings.KMSKeyID,
		Tags: map[string]string{tagManagedBy: managedBy, tagOwner: p.owner, tagResource: resourceVolume,
			tagCreateKey: v.ID, tagApp: v.App},
		RetryToken: retryToken(managedBy, p.owner, resourceVolume, v.ID),
	})
}

// policy returns the cell's policy for days of daily snapshots: one daily
// incremental backup kept days.
func (p *pass) policy(days int) BackupPolicy {
	return BackupPolicy{Name: fmt.Sprintf("%s-volumes-%dd", p.owner, days),
		Tags:      map[string]string{tagManagedBy: managedBy, tagOwner: p.owner, tagResource: resourcePolicy},
		Schedules: []Schedule{{Type: "INCREMENTAL", Period: "ONE_DAY", RetentionSeconds: days * 24 * 3600}}}
}

// ownPolicy finds the cell's policy by name. A policy of that name with
// other tags or schedules is foreign.
func (p *pass) ownPolicy(ctx context.Context, want BackupPolicy) (BackupPolicy, bool, error) {
	if p.policies == nil {
		policies, err := p.Cloud.ListBackupPolicies(ctx, p.Settings.CompartmentID)
		if err != nil {
			return BackupPolicy{}, false, err
		}
		p.policies = policies
	}
	for _, policy := range p.policies {
		if policy.Name != want.Name {
			continue
		}
		if !maps.Equal(policy.Tags, want.Tags) || !slices.Equal(policy.Schedules, want.Schedules) {
			return BackupPolicy{}, false, hold("backup policy %s is not this cell's", want.Name)
		}
		return policy, true, nil
	}
	return BackupPolicy{}, false, nil
}

// cellPolicy reports whether policy is exactly one of the cell's retention
// policies: name, tags and schedule.
func (p *pass) cellPolicy(policy BackupPolicy) bool {
	for days := 1; days <= maxSnapshotRetentionDays; days++ {
		want := p.policy(days)
		if policy.Name == want.Name {
			return maps.Equal(policy.Tags, want.Tags) && slices.Equal(policy.Schedules, want.Schedules)
		}
	}
	return false
}

// ensurePolicy assigns the backup policy of the record's retention. It
// replaces only an assignment of another of the cell's own policies.
func (p *pass) ensurePolicy(ctx context.Context, v Volume, volumeID string) error {
	want := p.policy(v.SnapshotRetentionDays)
	policy, found, err := p.ownPolicy(ctx, want)
	if err != nil {
		return err
	}
	if !found {
		if err := p.guard(ctx); err != nil {
			return err
		}
		if policy, err = p.Cloud.CreateBackupPolicy(ctx, p.Settings.CompartmentID, want,
			retryToken(managedBy, p.owner, resourcePolicy, want.Name)); err != nil {
			return err
		}
		p.policies = append(p.policies, policy)
	}
	current, err := p.Cloud.PolicyAssignment(ctx, volumeID)
	if err != nil || current.PolicyID == policy.ID {
		return err
	}
	if current.ID != "" {
		ours := slices.ContainsFunc(p.policies, func(old BackupPolicy) bool {
			return old.ID == current.PolicyID && p.cellPolicy(old)
		})
		if !ours {
			return hold("OCI volume %s carries backup policy %s, which is not this cell's", volumeID, current.PolicyID)
		}
		if err := p.guard(ctx); err != nil {
			return err
		}
		if err := p.Cloud.DeleteAssignment(ctx, current.ID); err != nil {
			return err
		}
	}
	if err := p.guard(ctx); err != nil {
		return err
	}
	return p.Cloud.AssignPolicy(ctx, volumeID, policy.ID)
}

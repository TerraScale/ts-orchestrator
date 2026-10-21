package region

import (
	"context"
	"errors"
	"regexp"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
)

// VerifiedBackupDestination is a nonsecret destination, never host admission.
// Its name is root-signed and its OCID is checkpointed by the current owned
// foundation; the backup producer must still observe actual bucket settings.
type VerifiedBackupDestination struct {
	region, name, id, cell, grantDigest string
	target                              vaultsecret.Target
	generation                          uint64
	expires                             time.Time
	check                               func(context.Context) error
}

func (v VerifiedBackupDestination) OCIRegion() string               { return v.region }
func (v VerifiedBackupDestination) BucketName() string              { return v.name }
func (v VerifiedBackupDestination) BucketID() string                { return v.id }
func (v VerifiedBackupDestination) VaultTarget() vaultsecret.Target { return v.target }
func (v VerifiedBackupDestination) Check(ctx context.Context) error {
	if v.check == nil || v.generation == 0 || !time.Now().Before(v.expires) {
		return errors.New("verified backup destination is absent or expired")
	}
	return v.check(ctx)
}

var backupBucketName = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

func (s *SignedFootprint) authorizedBackupDestination(ctx context.Context, cell string) (VerifiedBackupDestination, error) {
	footprint, expires, err := s.authorizedRegions(ctx)
	if err != nil {
		return VerifiedBackupDestination{}, err
	}
	for _, intent := range footprint.Regions {
		if intent.Plan["cell"] != cell {
			continue
		}
		buckets, _ := intent.Plan["foundation_buckets"].(map[string]any)
		name, _ := buckets["backup"].(string)
		if !backupBucketName.MatchString(name) {
			return VerifiedBackupDestination{}, errors.New("signed regional foundation has no exact backup bucket name")
		}
		region, _ := intent.Plan["region"].(string)
		return VerifiedBackupDestination{region: region, name: name, cell: cell, generation: intent.Generation, grantDigest: s.home.GrantSHA256, expires: expires}, nil
	}
	return VerifiedBackupDestination{}, errors.New("backup destination is outside signed regional footprint")
}

func (r FoundationResolver) BackupDestination(ctx context.Context, cell string) (VerifiedBackupDestination, error) {
	reader, ok := r.Footprint.(interface {
		authorizedBackupDestination(context.Context, string) (VerifiedBackupDestination, error)
	})
	if !ok {
		return VerifiedBackupDestination{}, errors.New("backup destination requires authenticated signed foundation reader")
	}
	verified, err := reader.authorizedBackupDestination(ctx, cell)
	if err != nil {
		return VerifiedBackupDestination{}, err
	}
	record, err := r.Resolve(ctx, cell)
	if err != nil {
		return VerifiedBackupDestination{}, err
	}
	target, err := record.VaultTarget()
	id := record.AuxiliaryIDs["backup_bucket"]
	if err != nil || id == "" || record.Generation != verified.generation || record.OCIRegion != verified.region || !validAuxiliaryID("backup_bucket", id, verified.region) {
		return VerifiedBackupDestination{}, errors.New("backup destination differs from current owned foundation")
	}
	verified.target, verified.id = target, id
	verified.check = func(ctx context.Context) error {
		current, err := r.BackupDestination(ctx, cell)
		if err != nil {
			return err
		}
		if current.region != verified.region || current.name != verified.name || current.id != verified.id || current.target != verified.target || current.generation != verified.generation || current.grantDigest != verified.grantDigest {
			return errors.New("authenticated backup destination changed")
		}
		return ctx.Err()
	}
	return verified, ctx.Err()
}

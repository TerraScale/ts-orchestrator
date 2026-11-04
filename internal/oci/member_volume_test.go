package oci

import (
	"context"
	"fmt"
	"slices"
)

const (
	testMember       = "gru-1-db-1"
	testMemberVolume = "gru-1-db-1-data"
)

func testMemberVolumeConfig() MemberVolumeConfig {
	return MemberVolumeConfig{Region: "GRU", CompartmentID: "ocid1.compartment.members", AvailabilityDomain: "AD-1", VPUsPerGB: 10}
}

// memberVolumeFixture builds MemberVolumes over the shared fake provider, or
// over provider when one is given. Created volumes become AVAILABLE at once.
func (p *fakeProvider) ListVolumeBackupPolicies(context.Context) ([]CloudBackupPolicy, error) {
	return slices.Clone(p.backupPolicies), nil
}

func (p *fakeProvider) CreateVolumeBackupPolicy(_ context.Context, name string, schedules []BackupSchedule, tags map[string]string, retry string) (CloudBackupPolicy, error) {
	if p.backupPolicyRetryTokens == nil {
		p.backupPolicyRetryTokens = make(map[string]string)
	}
	for _, policy := range p.backupPolicies {
		if p.backupPolicyRetryTokens[retry] == policy.ID {
			return policy, nil
		}
	}
	p.backupPolicyCreates++
	policy := CloudBackupPolicy{ID: fmt.Sprintf("ocid1.volumebackuppolicy.created-%d", p.backupPolicyCreates), DisplayName: name,
		Schedules: slices.Clone(schedules), FreeformTags: cloneStringMap(tags)}
	p.backupPolicies = append(p.backupPolicies, policy)
	p.backupPolicyRetryTokens[retry] = policy.ID
	return policy, nil
}

func (p *fakeProvider) VolumeBackupPolicyAssignment(_ context.Context, volumeID string) (string, error) {
	return p.backupPolicyAssignments[volumeID], nil
}

func (p *fakeProvider) AssignVolumeBackupPolicy(_ context.Context, volumeID, policyID string) error {
	if p.backupPolicyAssignments == nil {
		p.backupPolicyAssignments = make(map[string]string)
	}
	// Like OCI, a new assignment replaces the volume's current one.
	p.backupPolicyAssignments[volumeID] = policyID
	return nil
}

// TestMemberVolumeCarriesTheCellBackupPolicy: every member data volume gets
// the cell's one backup policy, a daily backup kept 7 days and a weekly one
// kept 4 weeks, before it is attached.
func (p *fakeProvider) ListVolumeBackups(_ context.Context, volumeID string) ([]CloudVolumeBackup, error) {
	var backups []CloudVolumeBackup
	for _, backup := range p.volumeBackups {
		if backup.VolumeID == volumeID {
			backups = append(backups, backup)
		}
	}
	return backups, nil
}

func (p *fakeProvider) GetVolumeBackup(_ context.Context, id string) (CloudVolumeBackup, error) {
	for _, backup := range p.volumeBackups {
		if backup.ID == id {
			return backup, nil
		}
	}
	return CloudVolumeBackup{}, fakeNotFound{}
}

// TestMemberVolumeRestoreDrill restores the newest available backup into a
// new volume on a scratch instance, never on a member host, and leaves the
// member's own volume alone.

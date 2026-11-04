package placement

import (
	"fmt"
	"strings"
	"testing"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

func validMemberStateForPins(t *testing.T) MemberState {
	intent := committedTestIntent(t, validIntent(oci.RegionGRU))
	seat := Seat{MemberID: permanentMember(oci.RegionGRU), Region: oci.RegionGRU, FailureDomain: "FAULT-DOMAIN-1", Kind: MemberPermanent}
	return testMemberState(t, intent, seat, StagePreparedHost)
}

func validIntent(regions ...oci.Region) Intent {
	selected := make(map[oci.Region]struct{}, len(regions))
	for _, region := range regions {
		selected[region] = struct{}{}
	}
	active := make([]oci.Region, 0, len(selected))
	profiles := make([]ManagedHostProfile, 0, len(selected))
	for _, region := range regionsInOrder {
		if _, exists := selected[region]; !exists {
			continue
		}
		active = append(active, region)
		profiles = append(profiles, testManagedHostProfile(region))
	}
	roster := testCanonicalRoster(active)
	manifests := make([]RuntimeManifest, 0, len(roster.Rows))
	for index, row := range roster.Rows {
		peer := roster.Rows[index^1]
		manifests = append(manifests, RuntimeManifest{
			Region: row.Region, SeatID: row.SeatID,
			ArtifactDigest: strings.Repeat("d", 64), SourceDigest: strings.Repeat("e", 64),
			ManagedRuntimeRoot: "/srv/terrascale-managed",
			FileSystemUUID:     fmt.Sprintf("%08x-1234-1234-1234-123456789abc", index+1),
			FileSystemType:     "ext4", TrustedKeySHA256: roster.Authority.TrustedKeySHA256,
			ServerCertificateSHA256:             strings.Repeat("1", 64),
			ServerPrivateKeySHA256:              strings.Repeat("2", 64),
			ClientCARootsSHA256:                 strings.Repeat("3", 64),
			ClientManagedMaterialManifestSHA256: strings.Repeat("4", 64),
			LiveS3ConfigSHA256:                  strings.Repeat("5", 64),
			LiveS3TargetSHA256:                  strings.Repeat("6", 64),
			LiveS3Credential:                    oci.SecretVersionReference{SecretOCID: "ocid1.vaultsecret.oc1.sa-saopaulo-1.alpha", VersionNumber: 3},
			ReplicationListenAddress:            fmt.Sprintf("10.0.0.%d:%d", 11+index, 7000+index),
			ReplicationPeerMemberID:             peer.MemberID,
			ReplicationPeerAddress:              fmt.Sprintf("10.0.0.%d:%d", 11+(index^1), 7000+(index^1)),
			ReplicationServerCASHA256:           strings.Repeat("a", 64),
		})
	}
	return Intent{
		SchemaVersion:       IntentSchemaVersion,
		DatabaseID:          testDatabaseID,
		PartitionID:         "0000000000Z3WK359G2W66CVT8",
		ActiveRegions:       active,
		Generation:          1,
		CanonicalRoster:     roster,
		ManagedHostProfiles: profiles,
		RuntimeManifests:    manifests,
	}
}

const testDatabaseID = "0000000000JJVVW9EMWY1PE1VX"

func testCanonicalRoster(regions []oci.Region) CanonicalRoster {
	rows := make([]CanonicalRosterRow, 0, len(regions)*2)
	for regionIndex, region := range regions {
		rows = append(rows,
			CanonicalRosterRow{
				Region: region, SeatID: permanentMember(region), FailureDomain: "FAULT-DOMAIN-1",
				MemberID:    entityid.Derive("fixture-member", fmt.Sprint(regionIndex*2+1)),
				Incarnation: fmt.Sprintf("%032x", regionIndex*2+1), TLSLeafSHA256: fmt.Sprintf("%064x", regionIndex*2+1),
				ServerName: fmt.Sprintf("permanent-%s.tb.example", strings.ToLower(string(region))),
			},
			CanonicalRosterRow{
				Region: region, SeatID: elasticMember(region), FailureDomain: "FAULT-DOMAIN-2",
				MemberID:    entityid.Derive("fixture-member", fmt.Sprint(regionIndex*2+2)),
				Incarnation: fmt.Sprintf("%032x", regionIndex*2+2), TLSLeafSHA256: fmt.Sprintf("%064x", regionIndex*2+2),
				ServerName: fmt.Sprintf("elastic-%s.tb.example", strings.ToLower(string(region))),
			},
		)
	}
	return CanonicalRoster{
		ClusterID: "0123456789abcdef0123456789abcdef", TenantID: "01HW000000E008000000000080",
		DatabaseID: "01HW000000E008000000000081", ShardID: 1,
		Authority: AuthorityReference{
			Version: 2, Epoch: 7, ConfigurationID: strings.Repeat("a", 64),
			CertificateSHA256: strings.Repeat("b", 64), TrustedKeySHA256: strings.Repeat("c", 64),
		},
		Rows: rows,
	}
}

func testManagedHostProfile(region oci.Region) ManagedHostProfile {
	return ManagedHostProfile{
		Region:             region,
		Compute:            ComputeTuple{Shape: "VM.Standard.E4.Flex", WholeOCPUs: 1, MemoryInGBs: 6},
		ProcessMemoryBytes: 4 * managedMemoryGiB, MemoryHeadroomBytes: managedMemoryGiB,
		CgroupMemoryMaxBytes: 4 * managedMemoryGiB, SystemReserveBytes: managedMemoryGiB,
		AllocatableMemoryBytes: 5 * managedMemoryGiB,
	}
}

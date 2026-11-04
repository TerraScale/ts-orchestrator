//go:build linux

package host

import (
	"crypto/ed25519"
	"encoding/base64"

	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

func managedContractFixture() (Registration, Desired, ed25519.PrivateKey) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	registration := Registration{
		ID:   entityid.Derive("host", "gru", "node-a"),
		Cell: "gru", Node: "node-a", Environment: "production", FailureDomain: "FAULT-DOMAIN-1",
		Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), NATSUserPublicKey: testNATSUserKey("node-a"), Generation: 1,
		Capacity: Capacity{MemoryBytes: 8 << 30}, SystemReserveBytes: 1 << 30,
		ManagedOCI:    &ManagedOCIBinding{Region: "GRU", InstanceID: "ocid1.instance.oc1..node-a", Owner: "terrascale", FleetGeneration: 1, CreateKey: "00000000000000000000000001"},
		ManagedMember: &ManagedMemberBinding{Scope: MemberScope{ClusterID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", TenantID: "01HW000000E008000000000001", DatabaseID: "01HW000000E008000000000001", ShardID: 1, MemberID: "01HW000000E008000000000001", Incarnation: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"}, HostAttempt: 1},
	}
	desired := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Generation: 1, AuthorityEpoch: 1, Digest: strings.Repeat("a", 64),
		ManagedMember: &ManagedMemberLaunch{OCI: *registration.ManagedOCI, Member: *registration.ManagedMember,
			Authority:    MemberAuthority{Epoch: 1, ConfigurationID: strings.Repeat("c", 64), CertificateSHA256: strings.Repeat("d", 64), TLSLeafSHA256: strings.Repeat("e", 64)},
			SourceDigest: strings.Repeat("f", 64), VolumeID: "ocid1.volume.retained", AttachmentID: "ocid1.volumeattachment.node-a",
			ProcessMemoryBytes: 4 << 30, MemoryHeadroomBytes: 1 << 30, CgroupMemoryMaxBytes: 6 << 30, SystemReserveBytes: 1 << 30}}
	return registration, desired, key
}

//go:build linux

package host

import (
	"crypto/ed25519"
	"encoding/base64"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func managedContractFixture() (Registration, Desired, ed25519.PrivateKey) {
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	registration := Registration{
		Cell: "gru", Node: "node-a", Environment: "production", FailureDomain: "FAULT-DOMAIN-1",
		Roles: []string{"terrabase"}, PublicKey: base64.StdEncoding.EncodeToString(key.Public().(ed25519.PublicKey)), Generation: 1,
		Capacity: Capacity{MemoryBytes: 8 << 30}, SystemReserveBytes: 1 << 30,
		ManagedOCI:    &ManagedOCIBinding{Region: "GRU", InstanceID: "ocid1.instance.oc1..node-a", Owner: "terrascale", FleetGeneration: 1, CreateKey: "node-a"},
		ManagedMember: &ManagedMemberBinding{Scope: MemberScope{ClusterID: strings.Repeat("a", 32), TenantID: "018f0000-0000-7000-8000-000000000001", DatabaseID: "018f0000-0000-7000-8000-000000000001", ShardID: 1, MemberID: "018f0000-0000-7000-8000-000000000001", Incarnation: strings.Repeat("b", 32)}, HostAttempt: 1},
	}
	desired := Desired{Cell: "gru", Node: "node-a", Environment: "production", Role: "terrabase", Generation: 1, AuthorityEpoch: 1, Digest: strings.Repeat("a", 64),
		ManagedMember: &ManagedMemberLaunch{OCI: *registration.ManagedOCI, Member: *registration.ManagedMember,
			Authority:    MemberAuthority{Epoch: 1, ConfigurationID: strings.Repeat("c", 64), CertificateSHA256: strings.Repeat("d", 64), TLSLeafSHA256: strings.Repeat("e", 64)},
			SourceDigest: strings.Repeat("f", 64), VolumeID: "ocid1.volume.retained", AttachmentID: "ocid1.volumeattachment.node-a",
			ProcessMemoryBytes: 4 << 30, MemoryHeadroomBytes: 1 << 30, CgroupMemoryMaxBytes: 6 << 30}}
	return registration, desired, key
}

func TestManagedDesiredMemoryAndIdentityBoundaries(t *testing.T) {
	checks := []struct {
		name   string
		change func(*Registration, *Desired)
		valid  bool
	}{
		{name: "minimum profile", valid: true},
		{name: "process below minimum", change: func(_ *Registration, d *Desired) { d.ManagedMember.ProcessMemoryBytes-- }},
		{name: "headroom below quarter", change: func(_ *Registration, d *Desired) { d.ManagedMember.MemoryHeadroomBytes-- }},
		{name: "headroom equals process", change: func(_ *Registration, d *Desired) {
			d.ManagedMember.MemoryHeadroomBytes = d.ManagedMember.ProcessMemoryBytes
		}},
		{name: "cap below process", change: func(_ *Registration, d *Desired) { d.ManagedMember.CgroupMemoryMaxBytes = 3 << 30 }},
		{name: "cap above allocatable", change: func(_ *Registration, d *Desired) { d.ManagedMember.CgroupMemoryMaxBytes = 9 << 30 }},
		{name: "cap not page aligned", change: func(_ *Registration, d *Desired) { d.ManagedMember.CgroupMemoryMaxBytes++ }},
		{name: "cap exceeds signed range", change: func(r *Registration, d *Desired) {
			r.Capacity.MemoryBytes = math.MaxInt64
			d.ManagedMember.CgroupMemoryMaxBytes = uint64(math.MaxInt64) + 1
		}},
		{name: "another host attempt", change: func(_ *Registration, d *Desired) { d.ManagedMember.Member.HostAttempt++ }},
		{name: "another member", change: func(_ *Registration, d *Desired) {
			d.ManagedMember.Member.Scope.MemberID = "018f0000-0000-7000-8000-000000000002"
		}},
		{name: "wrong attachment", change: func(_ *Registration, d *Desired) { d.ManagedMember.AttachmentID = "" }},
		{name: "generic arguments", change: func(_ *Registration, d *Desired) { d.Args = []string{"--memory-limit-bytes", "1"} }},
		{name: "generic desired on managed host", change: func(_ *Registration, d *Desired) { d.ManagedMember = nil }},
		{name: "legacy OCI-only registration", change: func(r *Registration, _ *Desired) { r.ManagedMember = nil }},
		{name: "managed desired on generic host", change: func(r *Registration, _ *Desired) {
			r.ManagedOCI = nil
			r.ManagedMember = nil
			r.SystemReserveBytes = 0
			r.FailureDomain = "fd-a"
		}},
	}
	for _, check := range checks {
		t.Run(check.name, func(t *testing.T) {
			r, d, _ := managedContractFixture()
			if check.change != nil {
				check.change(&r, &d)
			}
			if err := validateDesired(d, "gru", r); (err == nil) != check.valid {
				t.Fatalf("validateDesired() error = %v, valid = %t", err, check.valid)
			}
		})
	}
	r, d, _ := managedContractFixture()
	d.Withdrawn = true
	d.Digest = ""
	d.ManagedMember.ProcessMemoryBytes = 0
	d.ManagedMember.MemoryHeadroomBytes = 0
	d.ManagedMember.CgroupMemoryMaxBytes = 0
	if err := validateDesired(d, "gru", r); err != nil {
		t.Fatalf("identity-retaining withdrawal: %v", err)
	}
	d.ManagedMember.CgroupMemoryMaxBytes = 4 << 30
	if err := validateDesired(d, "gru", r); err == nil {
		t.Fatal("withdrawal retained execution cap")
	}
}

func TestManagedMemoryWorkloadAndReplyBinding(t *testing.T) {
	r, d, key := managedContractFixture()
	w := managedMemoryWorkload(d)
	if !slices.Equal(w.Args, []string{"--memory-limit-bytes", "4294967296", "--memory-headroom-bytes", "1073741824"}) || w.CgroupMemoryMaxBytes != 6<<30 {
		t.Fatalf("managed P/H/C profile = %+v", w)
	}
	a := &Agent{cfg: AgentConfig{Cell: r.Cell, Node: r.Node, Environment: r.Environment, Identity: key}, session: session{RegistrationGeneration: r.Generation}}
	reply := desiredReply{Desired: &d, Revision: 4, Registration: &r, RegistrationRevision: 3}
	if err := a.validateDesiredReply(reply); err != nil {
		t.Fatal(err)
	}
	if !sameDesiredReplyBinding(reply, reply) {
		t.Fatal("unchanged reply binding rejected")
	}
	changed := reply
	changed.RegistrationRevision++
	if sameDesiredReplyBinding(reply, changed) {
		t.Fatal("registration revision change accepted before Apply")
	}
	changed = reply
	changed.Revision++
	if sameDesiredReplyBinding(reply, changed) {
		t.Fatal("desired revision change accepted before Apply")
	}
	changed = reply
	rotated := r
	rotated.Generation++
	changed.Registration = &rotated
	if err := a.validateDesiredReply(changed); err == nil {
		t.Fatal("session generation change accepted")
	}
	if sameDesiredReplyBinding(reply, changed) {
		t.Fatal("registration mutation accepted before Apply")
	}
}

func TestManagedHostMemoryUsesPhysicalAndAncestorCaps(t *testing.T) {
	r, _, _ := managedContractFixture()
	root := t.TempDir()
	leaf := filepath.Join(root, "service", "supervisor")
	if err := os.MkdirAll(leaf, 0700); err != nil {
		t.Fatal(err)
	}
	for path, value := range map[string]string{root: "max", filepath.Join(root, "service"): "9663676416", leaf: "max"} {
		if err := os.WriteFile(filepath.Join(path, "memory.max"), []byte(value), 0600); err != nil {
			t.Fatal(err)
		}
	}
	meminfo := filepath.Join(t.TempDir(), "meminfo")
	membership := filepath.Join(t.TempDir(), "cgroup")
	if err := os.WriteFile(meminfo, []byte("MemTotal: 10485760 kB\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(membership, []byte("0::/service/supervisor\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateManagedHostMemoryAt(r, meminfo, membership, root); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "service", "memory.max"), []byte("8589934592"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateManagedHostMemoryAt(r, meminfo, membership, root); err == nil {
		t.Fatal("service cap smaller than allocatable plus reserve accepted")
	}
	if err := os.WriteFile(filepath.Join(root, "service", "memory.max"), []byte("max"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(meminfo, []byte("MemTotal: 8388608 kB\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := validateManagedHostMemoryAt(r, meminfo, membership, root); err == nil {
		t.Fatal("physical memory below allocatable plus reserve accepted")
	}
	if _, err := physicalMemoryBytes("MemTotal: 18446744073709551615 kB\n"); err == nil {
		t.Fatal("overflowing MemTotal accepted")
	}
}

func TestReadRoleMemoryMax(t *testing.T) {
	path := t.TempDir()
	for _, check := range []struct {
		value string
		want  uint64
		valid bool
	}{
		{"max", 0, true}, {"4294967296", 4 << 30, true}, {"4294967295", 4294967295, true}, {"garbage", 0, false},
	} {
		if err := os.WriteFile(filepath.Join(path, "memory.max"), []byte(check.value), 0600); err != nil {
			t.Fatal(err)
		}
		got, err := readCgroupMemoryMax(path)
		if got != check.want || (err == nil) != check.valid {
			t.Fatalf("memory.max %q: got=%d err=%v", check.value, got, err)
		}
	}
}

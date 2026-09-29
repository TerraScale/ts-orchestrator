//go:build linux

package host

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

func TestManagedMaterialChunkIsConfidentialAndBoundToHostSession(t *testing.T) {
	private, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	request := request{Node: "node-a", SessionID: "session-a", Epoch: 9, Nonce: "nonce-a"}
	query := materialQuery{Role: "terrabase", File: "server.key", DesiredGeneration: 7,
		DesiredFingerprint: "fingerprint-a", MemberID: "member-a", HostAttempt: 1,
		RegistrationGeneration: 3, InstanceID: "instance-a", Offset: 0, Length: 100,
		EphemeralPublicKey: private.PublicKey().Bytes()}
	secret := []byte("sensitive replication private key bytes")
	reply, err := encryptMaterialChunk(request, query, secret, len(secret), secret)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(reply.Ciphertext, secret) || len(reply.Nonce) != 12 || reply.File != query.File {
		t.Fatal("managed material response exposed plaintext or changed its file identity")
	}
	serverPublic, err := ecdh.X25519().NewPublicKey(reply.EphemeralPublicKey)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := private.ECDH(serverPublic)
	if err != nil {
		t.Fatal(err)
	}
	aad, err := materialAAD(request, query)
	if err != nil {
		t.Fatal(err)
	}
	aead, err := materialAEAD(shared, aad)
	if err != nil {
		t.Fatal(err)
	}
	decoded, err := aead.Open(nil, reply.Nonce, reply.Ciphertext, aad)
	if err != nil || !bytes.Equal(decoded, secret) {
		t.Fatalf("valid host material chunk did not decrypt: %v", err)
	}
	query.InstanceID = "another-instance"
	wrongAAD, err := materialAAD(request, query)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := aead.Open(nil, reply.Nonce, reply.Ciphertext, wrongAAD); err == nil {
		t.Fatal("material chunk decrypted under another OCI instance")
	}
}

func TestManagedSQLBundleDeliveryIsConditionalAndDigestPinned(t *testing.T) {
	desired := Desired{ManagedMember: &ManagedMemberLaunch{Runtime: &ManagedRuntimePins{}}}
	if slices.Contains(managedHostFilesFor(desired), sqlSchemaBundleName) ||
		managedHostFileEnabled(desired, sqlSchemaBundleName) {
		t.Fatal("SQL bundle was enabled without a signed placement digest")
	}
	digest := strings.Repeat("a", 64)
	desired.ManagedMember.Runtime.SQLSchemaBundleSHA256 = digest
	if !slices.Contains(managedHostFilesFor(desired), sqlSchemaBundleName) ||
		!managedHostFileEnabled(desired, sqlSchemaBundleName) ||
		expectedHostMaterialDigest(desired, sqlSchemaBundleName) != digest ||
		managedHostFileLimit(sqlSchemaBundleName) != 4<<10 {
		t.Fatal("SQL bundle delivery is not tied to the signed digest and 4096-byte cap")
	}
}

func TestManagedMemberLayoutIsCreatedOnceWithExactOwnership(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("root ownership is required for the managed runtime layout")
	}
	parent, err := os.MkdirTemp("/run", "ts-managed-layout-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(parent) })
	if err := os.Chmod(parent, 0o755); err != nil {
		t.Fatal(err)
	}
	identity := WorkloadIdentity{UID: 65534, GID: 65534}
	root := filepath.Join(parent, "ts-managed")
	if err := os.Mkdir(root, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Chown(root, 0, int(identity.GID)); err != nil {
		t.Fatal(err)
	}
	launch := ManagedMemberLaunch{Member: ManagedMemberBinding{Scope: MemberScope{
		ClusterID: strings.Repeat("1", 32), TenantID: "10000000-0000-4000-8000-000000000001",
		DatabaseID: "20000000-0000-4000-8000-000000000001", ShardID: 1,
		MemberID: "30000000-0000-4000-8000-000000000001", Incarnation: strings.Repeat("2", 32),
	}, HostAttempt: 1}}
	paths, err := ensureManagedMemberLayout(root, launch, identity)
	if err != nil {
		t.Fatalf("fresh host layout: %v", err)
	}
	for path, mode := range map[string]os.FileMode{paths.memberDir: 0o750, paths.material: 0o750,
		filepath.Dir(paths.socket): 0o730} {
		if err := verifyManagedDirectory(path, identity, mode); err != nil {
			t.Fatalf("%s: %v", path, err)
		}
	}
	if _, err := ensureManagedMemberLayout(root, launch, identity); err != nil {
		t.Fatalf("existing exact layout was not reused: %v", err)
	}
	if err := os.Chmod(paths.material, 0o770); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureManagedMemberLayout(root, launch, identity); err == nil {
		t.Fatal("group-writable material directory was accepted")
	}
	if err := os.Chmod(paths.material, 0o750); err != nil {
		t.Fatal(err)
	}
	control := filepath.Dir(paths.socket)
	if err := os.Remove(control); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(paths.material, control); err != nil {
		t.Fatal(err)
	}
	if _, err := ensureManagedMemberLayout(root, launch, identity); err == nil {
		t.Fatal("symlinked control directory was accepted")
	}
}

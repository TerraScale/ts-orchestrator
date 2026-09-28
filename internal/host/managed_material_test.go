//go:build linux

package host

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
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

package managedmaterial

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json/v2"
	"errors"
	"testing"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/authority"
)

type fakeCredentialStore struct {
	entry   *authority.LogEntry
	next    uint64
	loseAck bool
}

func (store *fakeCredentialStore) ReadClientCredentials(_ context.Context, database, partition string) (authority.LogEntry, error) {
	if store.entry == nil || store.entry.SubjectKey != database+"."+partition {
		return authority.LogEntry{}, authority.ErrNotFound
	}
	return *store.entry, nil
}

func (store *fakeCredentialStore) CommitClientCredentials(_ context.Context, epoch uint64,
	database, partition, operation string, expected uint64, payload []byte,
) (uint64, error) {
	if epoch != 9 || store.entry == nil && expected != 0 ||
		store.entry != nil && expected != store.entry.Sequence {
		return 0, authority.ErrConflict
	}
	store.next++
	store.entry = &authority.LogEntry{Kind: authority.MutationClientCredentials,
		SubjectKey: database + "." + partition, OperationID: operation, Epoch: epoch,
		Sequence: store.next, Payload: bytes.Clone(payload)}
	if store.loseAck {
		store.loseAck = false
		return 0, authority.ErrOutcomeUnknown
	}
	return store.next, nil
}

func TestManagedCredentialRotationRevocationAndReplay(t *testing.T) {
	preparation, spec, _, _ := preparationFixture(t)
	_, signer, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	preparation.RecipientSigner = signer.Public().(ed25519.PublicKey)
	spec.Recipient.Signature = ed25519.Sign(signer, RecipientGrantMessage(spec))
	now := time.Now().UTC()
	initial, err := preparation.PrepareInitial(t.Context(), 9, spec.PartitionID, spec, now)
	if err != nil {
		t.Fatal(err)
	}
	initialSHA, err := initial.Digest()
	if err != nil {
		t.Fatal(err)
	}
	store := new(fakeCredentialStore)
	service := CredentialService{Preparation: preparation, Store: store}
	first, receipt, err := service.Current(t.Context(), spec.PlacementDatabaseID, spec.PartitionID)
	if err != nil || first.Generation != 1 || receipt != nil {
		t.Fatalf("initial credential generation not recovered: %v", err)
	}
	var initialRegistry apiKeyRegistry
	if err := json.Unmarshal(first.Registry, &initialRegistry); err != nil {
		t.Fatal(err)
	}
	recipient, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	grantSpec := spec
	grantSpec.Recipient = RecipientGrant{PublicKey: recipient.PublicKey().Bytes(),
		ExpiresAt: now.Add(time.Hour).Truncate(time.Second)}
	grantSpec.Recipient.Signature = ed25519.Sign(signer, RecipientGrantMessage(grantSpec))
	rotate := CredentialRequest{DatabaseID: spec.PlacementDatabaseID, PartitionID: spec.PartitionID,
		InitialReceiptSHA: initialSHA, ExpectedGeneration: 1, OperationID: "rotate-one",
		Action: CredentialRotate, Recipient: grantSpec.Recipient}
	store.loseAck = true
	rotated, err := service.Apply(t.Context(), 9, rotate, now)
	if err != nil || rotated.State.Generation != 2 || rotated.Customer == nil {
		t.Fatalf("ambiguous rotate did not reconcile durable generation: %v", err)
	}
	_, bundle, err := preparation.CurrentBundle(t.Context(), spec.PlacementDatabaseID, spec.PartitionID)
	if err != nil {
		t.Fatal(err)
	}
	reply := CredentialReply{Initial: initial, AuthorityKey: bundle.Authority.TrustedKey, Receipt: rotated}
	if err := VerifyCredentialReply(reply, rotate, preparation.ControllerKey.Public().(ed25519.PublicKey), initial.Cell); err != nil {
		t.Fatalf("committed rotation receipt was rejected: %v", err)
	}
	wrongEnvelope := rotated
	wrongCustomer := *rotated.Customer
	wrongCustomer.TokenID = initialRegistry.Keys[0].ID
	wrongEnvelope.Customer = &wrongCustomer
	if err := wrongEnvelope.sign(preparation.ControllerKey); err != nil {
		t.Fatal(err)
	}
	reply.Receipt = wrongEnvelope
	if err := VerifyCredentialReply(reply, rotate, preparation.ControllerKey.Public().(ed25519.PublicKey), initial.Cell); err == nil {
		t.Fatal("signed customer envelope with a foreign key ID was accepted")
	}
	opened, err := OpenCustomerEnvelope(grantSpec, *rotated.Customer, recipient)
	if err != nil || opened.Token == "" {
		t.Fatalf("recipient cannot open committed rotated token: %v", err)
	}
	var rotatedRegistry apiKeyRegistry
	if err := json.Unmarshal(rotated.State.Registry, &rotatedRegistry); err != nil ||
		len(rotatedRegistry.Keys) != 2 || rotatedRegistry.Keys[0].Revoked || rotatedRegistry.Keys[1].Revoked {
		t.Fatal("rotation failed to overlap old and new keys")
	}
	retry, err := service.Apply(t.Context(), 9, rotate, now)
	if err != nil || retry.Signature != rotated.Signature || store.next != 1 {
		t.Fatalf("retry reminted or replaced committed credential: %v", err)
	}
	expiredAt := grantSpec.Recipient.ExpiresAt.Add(time.Second)
	expiredRetry, err := service.Apply(t.Context(), 9, rotate, expiredAt)
	if err != nil || expiredRetry.Signature != rotated.Signature || store.next != 1 {
		t.Fatalf("expired exact retry did not recover the committed token receipt: %v", err)
	}
	expiredNew := rotate
	expiredNew.ExpectedGeneration = 2
	expiredNew.OperationID = "rotate-two"
	if _, err := service.Apply(t.Context(), 9, expiredNew, expiredAt); err == nil || store.next != 1 {
		t.Fatalf("expired grant authorized a new rotation: %v", err)
	}
	revoke := CredentialRequest{DatabaseID: spec.PlacementDatabaseID, PartitionID: spec.PartitionID,
		InitialReceiptSHA: initialSHA, ExpectedGeneration: 2, OperationID: "revoke-one",
		Action: CredentialRevoke, KeyID: initialRegistry.Keys[0].ID}
	revoked, err := service.Apply(t.Context(), 9, revoke, now)
	if err != nil || revoked.State.Generation != 3 || revoked.Customer != nil {
		t.Fatalf("revocation did not commit: %v", err)
	}
	var finalRegistry apiKeyRegistry
	if err := json.Unmarshal(revoked.State.Registry, &finalRegistry); err != nil ||
		!finalRegistry.Keys[0].Revoked || finalRegistry.Keys[1].Revoked {
		t.Fatal("revocation changed the wrong key")
	}
	if _, err := service.Apply(t.Context(), 9, rotate, now); !errors.Is(err, authority.ErrConflict) {
		t.Fatalf("stale rotate replay was accepted: %v", err)
	}
	store.entry.Payload[0] ^= 1
	if _, _, err := service.Current(t.Context(), spec.PlacementDatabaseID, spec.PartitionID); !errors.Is(err, ErrMaterialConflict) {
		t.Fatalf("tampered durable state was accepted: %v", err)
	}
}

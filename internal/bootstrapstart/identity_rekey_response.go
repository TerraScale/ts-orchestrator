package bootstrapstart

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/bootstrap"
	"golang.org/x/sys/unix"
)

// VerifyIdentityRekeyResponseKey binds the new Vault bytes and the installed
// predecessor to the exact response signers in the verified host handoff.
func (store MaterialStore) VerifyIdentityRekeyResponseKey(ctx context.Context, verified VerifiedIdentityRekey, inputs TrustInputs, wire []byte, now time.Time) error {
	dir, _, err := store.identityRekeyResponseKey(ctx, verified, inputs, wire, now)
	if err == nil {
		unix.Close(dir)
	}
	return err
}

func responseKeyPublic(wire []byte) (string, error) {
	key, err := base64.StdEncoding.Strict().DecodeString(strings.TrimSpace(string(wire)))
	if err != nil || len(key) != ed25519.PrivateKeySize {
		clear(key)
		return "", ErrMaterial
	}
	defer clear(key)
	derived := ed25519.NewKeyFromSeed(key[:ed25519.SeedSize])
	defer clear(derived)
	if !bytes.Equal(key, derived) {
		return "", ErrMaterial
	}
	return base64.StdEncoding.EncodeToString(key[ed25519.SeedSize:]), nil
}

func (store MaterialStore) identityRekeyResponseKey(ctx context.Context, verified VerifiedIdentityRekey, inputs TrustInputs, wire []byte, now time.Time) (int, bootstrap.SecretReference, error) {
	if os.Geteuid() != 0 || os.Getegid() != 0 {
		return -1, bootstrap.SecretReference{}, ErrMaterial
	}
	if err := ctx.Err(); err != nil {
		return -1, bootstrap.SecretReference{}, err
	}
	current, err := verified.VerifyCurrent(inputs, now)
	if err != nil {
		return -1, bootstrap.SecretReference{}, err
	}
	accepted := current.Accepted()
	name := accepted.Slot + "-response.key"
	ref, found := materialReferences(accepted, nil)[name]
	public, keyErr := responseKeyPublic(wire)
	if !found || keyErr != nil || public != current.journal.HostObservation.ResponseKey ||
		len(wire) == 0 || int64(len(wire)) > ref.MaxBytes || digest(wire) != ref.SHA256 {
		return -1, bootstrap.SecretReference{}, ErrMaterial
	}
	dir, err := openMaterialDirectory(store.installedDirectory, store.serviceUID, store.serviceGID, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return -1, bootstrap.SecretReference{}, err
	}
	if !memoryFilesystem(dir) {
		unix.Close(dir)
		return -1, bootstrap.SecretReference{}, ErrMaterial
	}
	old, err := readUnpinned(dir, name, store.serviceUID, store.serviceGID, bootstrap.MaxSecretBytes)
	defer clear(old)
	if err == nil && !bytes.Equal(old, wire) {
		previous, keyErr := responseKeyPublic(old)
		if keyErr != nil || previous != current.journal.HostObservation.PreviousResponseKey {
			err = ErrMaterial
		}
	}
	if err != nil {
		unix.Close(dir)
		return -1, bootstrap.SecretReference{}, err
	}
	return dir, ref, nil
}

// InstallIdentityRekeyResponseKey publishes only the exact root-authorized
// replacement. The caller holds the layout lock and rechecks stopped state
// before each effect; retries also accept the already installed exact key.
func (store MaterialStore) InstallIdentityRekeyResponseKey(ctx context.Context, verified VerifiedIdentityRekey, inputs TrustInputs, wire []byte, beforeEffect func(context.Context) error, now time.Time) error {
	if beforeEffect == nil {
		return ErrMaterial
	}
	dir, ref, err := store.identityRekeyResponseKey(ctx, verified, inputs, wire, now)
	if err != nil {
		return err
	}
	defer unix.Close(dir)
	staging, err := openMaterialDirectory(store.stagingDirectory, 0, 0, 0o700, store.allowUnsafeAncestors)
	if err != nil {
		return err
	}
	defer unix.Close(staging)
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return err
	}
	child := ".identity-response-" + hex.EncodeToString(nonce[:])
	if err := beforeEffect(ctx); err != nil {
		return err
	}
	if err := unix.Mkdirat(staging, child, 0o700); err != nil {
		return err
	}
	defer unix.Unlinkat(staging, child, unix.AT_REMOVEDIR)
	stage, err := unix.Openat(staging, child, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return err
	}
	defer unix.Close(stage)
	defer unix.Unlinkat(stage, ref.TargetFile, 0)
	if err := store.writeStaged(stage, ref.TargetFile, wire); err != nil {
		return err
	}
	checked, _, err := store.identityRekeyResponseKey(ctx, verified, inputs, wire, time.Now().Round(0).UTC())
	if err != nil {
		return err
	}
	defer unix.Close(checked)
	if err := beforeEffect(ctx); err != nil {
		return err
	}
	if err := unix.Renameat(stage, ref.TargetFile, checked, ref.TargetFile); err != nil {
		return err
	}
	if err := unix.Fsync(checked); err != nil {
		return err
	}
	installed, err := readMaterial(checked, ref.TargetFile, store.serviceUID, store.serviceGID, ref.SHA256, ref.MaxBytes)
	clear(installed)
	return errors.Join(err, unix.Fsync(stage))
}

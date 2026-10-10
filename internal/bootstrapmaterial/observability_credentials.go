package bootstrapmaterial

import (
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"strings"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nkeys"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/natscell"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// IssueControllerObservabilityCredentials keeps a controller's user key,
// lifetime, binding global authority and telemetry to the reviewed topology.
// The cell account seed stays offline; installation requires a signed generation.
func IssueControllerObservabilityCredentials(current, signerSeed []byte, cell, slot, account string, peers []string, globalHome bool,
) ([]byte, error) {
	peerPublishes, err := natscell.ControllerObservabilityPublishes(peers)
	if err != nil {
		return nil, err
	}
	if err := natscell.ValidateBrokerControllerCredentialBytes(current, cell, slot); err != nil {
		return nil, err
	}
	raw, err := jwt.ParseDecoratedJWT(current)
	if err != nil {
		return nil, err
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return nil, err
	}
	signer, err := nkeys.FromSeed(bytes.TrimSpace(signerSeed))
	if err != nil {
		return nil, errors.New("controller account seed is invalid")
	}
	defer signer.Wipe()
	if public, err := signer.PublicKey(); err != nil || public != account || claim.Issuer != account ||
		claim.IssuerAccount != "" && claim.IssuerAccount != account {
		return nil, errors.New("controller credentials and offline signer must belong to the cell account")
	}
	claim.Sub.Allow.Add(protocol.ObservabilityGrant(cell))
	claim.Pub.Allow = slices.DeleteFunc(claim.Pub.Allow, func(subject string) bool {
		tail, ok := strings.CutPrefix(subject, protocol.SubjectRoot+".")
		if !ok {
			return false
		}
		peer, leaf, ok := strings.Cut(tail, ".obs.")
		if !ok || peer == cell || !slices.Contains(protocol.InterRegionObservabilityLeaves(), leaf) {
			return false
		}
		canonical, err := protocol.ObservabilitySubject(peer, leaf)
		return err == nil && canonical == subject
	})
	for _, grant := range natscell.GlobalControllerPublishes() {
		claim.Pub.Allow.Remove(grant)
	}
	if globalHome {
		claim.Pub.Allow.Add(natscell.GlobalControllerPublishes()...)
	}
	claim.Pub.Allow.Add(peerPublishes...)
	user, err := jwt.ParseDecoratedUserNKey(current)
	if err != nil {
		return nil, err
	}
	defer user.Wipe()
	seed, err := user.Seed()
	if err != nil {
		return nil, err
	}
	defer clear(seed)
	encoded, err := claim.Encode(signer)
	if err != nil {
		return nil, err
	}
	creds, err := jwt.FormatUserConfig(encoded, seed)
	if err != nil {
		return nil, err
	}
	if err := CheckControllerObservabilityCredentials(creds, cell, slot, account, peers, globalHome); err != nil {
		clear(creds)
		return nil, err
	}
	return creds, nil
}

// WriteControllerObservabilityCredentials reads private sources and writes a
// new owner-only file. It never replaces the immutable founding material.
func WriteControllerObservabilityCredentials(currentPath, signerPath, outputPath, cell, slot, account string,
	peers []string, globalHome bool,
) error {
	if !filepath.IsAbs(currentPath) || !filepath.IsAbs(signerPath) || !filepath.IsAbs(outputPath) ||
		secureParents(currentPath) != nil || secureParents(signerPath) != nil || secureParents(outputPath) != nil ||
		nested(filepath.Dir(currentPath), outputPath) || nested(filepath.Dir(signerPath), outputPath) {
		return ErrMaterial
	}
	current, err := readOwnedFile(currentPath, 64<<10)
	if err != nil {
		return err
	}
	defer clear(current)
	signer, err := readOwnedFile(signerPath, 1024)
	if err != nil {
		return err
	}
	defer clear(signer)
	creds, err := IssueControllerObservabilityCredentials(current, signer, cell, slot, account, peers, globalHome)
	if err != nil {
		return err
	}
	defer clear(creds)
	if err := writeOnce(outputPath, creds); err != nil {
		return err
	}
	return syncDirectory(filepath.Dir(outputPath))
}

// CheckControllerObservabilityCredentials binds an offline-issued controller
// user to its cell and slot, and requires the exact peer telemetry grants.
// Global publish grants are admitted only for the configured home region.
func CheckControllerObservabilityCredentials(creds []byte, cell, slot, account string, peers []string, globalHome bool) error {
	required, err := natscell.ControllerObservabilityPublishes(peers)
	if err != nil {
		return err
	}
	for index, peer := range peers {
		if !clusterRE.MatchString(peer) || peer == cell || slices.Contains(peers[:index], peer) {
			return errors.New("controller observability peers must be distinct region names other than this cell")
		}
	}
	if err := natscell.ValidateBrokerControllerCredentialBytes(creds, cell, slot); err != nil {
		return err
	}
	raw, err := jwt.ParseDecoratedJWT(creds)
	if err != nil {
		return err
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return err
	}
	if !nkeys.IsValidPublicAccountKey(account) || claim.Issuer != account ||
		claim.IssuerAccount != "" && claim.IssuerAccount != account ||
		claim.Expires == 0 || claim.Expires <= claim.IssuedAt || claim.NotBefore != 0 ||
		!slices.Contains(claim.Sub.Allow, protocol.ObservabilityGrant(cell)) {
		return errors.New("controller credentials need the cell account signature, finite lifetime and local observability subscription")
	}
	allowed := natscell.ControllerPublishes(cell)
	if globalHome {
		allowed.Add(natscell.GlobalControllerPublishes()...)
	}
	allowed.Add(required...)
	for _, grant := range claim.Pub.Allow {
		if !slices.Contains(allowed, grant) {
			return fmt.Errorf("controller credentials have unscoped publish %q", grant)
		}
	}
	for _, subject := range required {
		if !slices.Contains(claim.Pub.Allow, subject) {
			return fmt.Errorf("controller credentials lack peer observability publish %q", subject)
		}
	}
	return nil
}

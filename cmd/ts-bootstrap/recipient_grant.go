package main

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"flag"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/managedmaterial"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

// signInitialMaterialSpecAt binds an owner-held X25519 recipient to one exact
// initial catalog set and shard scope. The input is an InitialSpec with its
// recipient omitted; the output is the exact spec sent to material-prepare.
func signInitialMaterialSpecAt(args []string, now time.Time) error {
	flags := flag.NewFlagSet("sign-initial-material-spec", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	inputPath := flags.String("input", "", "draft initial material spec with canonical catalogs and no recipient")
	recipientPath := flags.String("recipient-key", "", "owner-only X25519 PKCS#8 recipient private key")
	signerPath := flags.String("signer-key", "", "owner-only Ed25519 recipient signer private key")
	signerPublicPath := flags.String("signer-public-key", "", "independently pinned Ed25519 recipient signer public key")
	expiresText := flags.String("expires-at", "", "recipient grant expiry, UTC RFC3339 without subsecond precision")
	outputPath := flags.String("out", "", "new absolute owner-only signed spec JSON path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *inputPath == "" || *recipientPath == "" || *signerPath == "" ||
		*signerPublicPath == "" || *expiresText == "" || !filepath.IsAbs(*outputPath) || flags.NArg() != 0 {
		return errors.New("sign-initial-material-spec requires --input, --recipient-key, --signer-key, --signer-public-key, --expires-at, and absolute --out")
	}
	expires, err := time.Parse(time.RFC3339, *expiresText)
	if err != nil || expires.Location() != time.UTC || expires.Format(time.RFC3339) != *expiresText ||
		!now.Before(expires) || expires.After(now.Add(30*24*time.Hour)) {
		return errors.New("recipient grant expiry must be future UTC whole seconds within 30 days")
	}
	wire, err := readBoundedRegular(*inputPath, maxCustomerSpecBytes)
	if err != nil {
		return fmt.Errorf("read initial material draft: %w", err)
	}
	var spec managedmaterial.InitialSpec
	if err := protocol.DecodeStrict(wire, &spec, maxCustomerSpecBytes); err != nil {
		return fmt.Errorf("decode initial material draft: %w", err)
	}
	if len(spec.Catalogs) == 0 || len(spec.Catalogs) > 1024 ||
		len(spec.Recipient.PublicKey) != 0 || !spec.Recipient.ExpiresAt.IsZero() || len(spec.Recipient.Signature) != 0 {
		return errors.New("initial material draft needs canonical catalogs and no recipient")
	}
	recipient, err := readOwnerRecipientKey(*recipientPath)
	if err != nil {
		return err
	}
	signer, err := readRootPrivateKey(*signerPath)
	if err != nil {
		return fmt.Errorf("read recipient signer: %w", err)
	}
	defer clear(signer)
	signerPublic, err := readRootPublicKey(*signerPublicPath)
	if err != nil {
		return fmt.Errorf("read pinned recipient signer: %w", err)
	}
	if !bytes.Equal(signer.Public().(ed25519.PublicKey), signerPublic) {
		return errors.New("recipient signer differs from the pinned public key")
	}
	spec.Recipient = managedmaterial.RecipientGrant{
		PublicKey: recipient.PublicKey().Bytes(), ExpiresAt: expires,
	}
	spec.Recipient.Signature = ed25519.Sign(signer, managedmaterial.RecipientGrantMessage(spec))
	output, err := protocol.EncodeJSON(spec)
	if err != nil || len(output) == 0 || len(output) > maxCustomerSpecBytes {
		return errors.New("signed initial material spec exceeds its wire limit")
	}
	return writeNewCustomerMaterial(*outputPath, output)
}

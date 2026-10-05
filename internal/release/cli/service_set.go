package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/serviceset"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func (c command) signServiceDelegation(args []string) error {
	return c.signServiceDelegationAt(args, time.Now().UTC())
}

// signServiceDelegationAt is the offline root operation that lets the
// online release leaf sign service sets for one deployment, cell and
// environment.
func (c command) signServiceDelegationAt(args []string, now time.Time) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	flags := flag.NewFlagSet("sign-service-delegation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	leafPath := flags.String("subject-public-key", "", "online leaf Ed25519 PKIX public key PEM")
	rootPath := flags.String("root-key", "", "offline root Ed25519 PKIX public key PEM")
	privatePath := flags.String("signing-key", "", "owner-only offline root Ed25519 PKCS#8 private key PEM")
	var id serviceset.Identity
	flags.StringVar(&id.DeploymentID, "deployment-id", "", "deployment the delegation is bound to")
	flags.StringVar(&id.Cell, "cell", "", "cell the delegation is bound to")
	flags.StringVar(&id.Environment, "environment", "", "environment the delegation is bound to")
	issuedAtText := flags.String("issued-at", "", "canonical UTC RFC3339 issuance instant")
	expiresAtText := flags.String("expires-at", "", "canonical UTC RFC3339 expiry instant")
	output := flags.String("out", "", "new root-signed service set delegation")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *leafPath == "" || *rootPath == "" || *privatePath == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("sign-service-delegation requires keys, --deployment-id, --cell, --environment, a UTC interval and --out")
	}
	if err := id.Validate(); err != nil {
		return err
	}
	issuedAt, err := parseDelegationUTC(*issuedAtText)
	if err != nil {
		return fmt.Errorf("issued-at: %w", err)
	}
	expiresAt, err := parseDelegationUTC(*expiresAtText)
	if err != nil {
		return fmt.Errorf("expires-at: %w", err)
	}
	if now.IsZero() || issuedAt.After(now) || !expiresAt.After(now) ||
		!expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > serviceset.MaxDelegationLifetime {
		return fmt.Errorf("service set delegation must be current and valid for no more than %s", serviceset.MaxDelegationLifetime)
	}
	leafPublic, err := readLeafPublicKey(*leafPath)
	if err != nil {
		return err
	}
	rootPublic, err := readRootPublicKey(*rootPath)
	if err != nil {
		return err
	}
	if bytes.Equal(leafPublic, rootPublic) {
		return errors.New("delegated service set leaf must differ from offline root")
	}
	rootPrivate, err := readOfflineRootPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(rootPrivate)
	if !bytes.Equal(rootPrivate.Public().(ed25519.PublicKey), rootPublic) {
		return errors.New("offline root signing key does not match root public key")
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	envelope, err := serviceset.SignDelegation(leafPublic, id, issuedAt, expiresAt, rootPrivate)
	if err != nil {
		return err
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	if err := c.writeNew(*output, wire, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(wire)
	return c.printJSON(struct {
		Delegation string `json:"delegation"`
		SHA256     string `json:"sha256"`
		ExpiresAt  string `json:"expires_at"`
	}{*output, hex.EncodeToString(sum[:]), expiresAt.Format(time.RFC3339)})
}

func (c command) signServiceSet(args []string) error {
	return c.signServiceSetAt(args, time.Now().UTC())
}

// signServiceSetAt is the online leaf operation that signs an unsigned
// candidate written by `ts-orch service add|update|remove --out`.
func (c command) signServiceSetAt(args []string, now time.Time) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	flags := flag.NewFlagSet("sign-service-set", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidate := flags.String("candidate", "", "unsigned canonical service set JSON")
	delegationPath := flags.String("delegation", "", "root-signed service set delegation envelope")
	rootPath := flags.String("root-key", "", "baked root public key PEM")
	privatePath := flags.String("signing-key", "", "owner-only delegated Ed25519 PKCS#8 private key PEM")
	validFor := flags.Duration("valid-for", time.Hour, "time the signed set may wait to be applied")
	output := flags.String("out", "", "new signed service set path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidate == "" || *delegationPath == "" || *rootPath == "" || *privatePath == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("sign-service-set requires --candidate, --delegation, --root-key, --signing-key and --out")
	}
	encoded, err := readBoundedRegular(*candidate, serviceset.MaxSetBytes)
	if err != nil {
		return err
	}
	set, err := serviceset.Decode(encoded)
	if err != nil {
		return err
	}
	delegationWire, err := readBoundedRegular(*delegationPath, trust.MaxEnvelopeBytes)
	if err != nil {
		return err
	}
	if _, err := trust.DecodeEnvelope(delegationWire); err != nil {
		return fmt.Errorf("service set delegation: %w", err)
	}
	root, err := readRootPublicKey(*rootPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		return err
	}
	private, err := readDelegatedPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(private)
	if err := c.ctx.Err(); err != nil {
		return err
	}
	wire, err := serviceset.Sign(set, delegationWire, roots, now, *validFor, private)
	if err != nil {
		return err
	}
	if err := c.writeNew(*output, wire, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(wire)
	return c.printJSON(struct {
		Generation   uint64 `json:"generation"`
		SHA256       string `json:"sha256"`
		DeploymentID string `json:"deployment_id"`
		Cell         string `json:"cell"`
		Environment  string `json:"environment"`
	}{set.Generation, hex.EncodeToString(sum[:]), set.DeploymentID, set.Cell, set.Environment})
}

func (c command) printJSON(value any) error {
	encoded, err := protocol.EncodeJSON(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.output, "%s\n", encoded)
	return err
}

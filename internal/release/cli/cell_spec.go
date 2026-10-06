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

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/cellspec"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/trust"
)

func (c command) signSpecDelegation(args []string) error {
	return c.signSpecDelegationAt(args, time.Now().UTC())
}

// signSpecDelegationAt is the offline root operation that lets the online
// release leaf sign ordinary cell spec amendments for one deployment, cell
// and environment.
func (c command) signSpecDelegationAt(args []string, now time.Time) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	flags := flag.NewFlagSet("sign-spec-delegation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	leafPath := flags.String("subject-public-key", "", "online leaf Ed25519 PKIX public key PEM")
	rootPath := flags.String("root-key", "", "offline root Ed25519 PKIX public key PEM")
	privatePath := flags.String("signing-key", "", "owner-only offline root Ed25519 PKCS#8 private key PEM")
	var id cellspec.Identity
	flags.StringVar(&id.DeploymentID, "deployment-id", "", "deployment the delegation is bound to")
	flags.StringVar(&id.Cell, "cell", "", "cell the delegation is bound to")
	flags.StringVar(&id.Environment, "environment", "", "environment the delegation is bound to")
	issuedAtText := flags.String("issued-at", "", "canonical UTC RFC3339 issuance instant")
	expiresAtText := flags.String("expires-at", "", "canonical UTC RFC3339 expiry instant")
	output := flags.String("out", "", "new root-signed cell spec delegation")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *leafPath == "" || *rootPath == "" || *privatePath == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("sign-spec-delegation requires keys, --deployment-id, --cell, --environment, a UTC interval and --out")
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
		!expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > cellspec.MaxDelegationLifetime {
		return fmt.Errorf("cell spec delegation must be current and valid for no more than %s", cellspec.MaxDelegationLifetime)
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
		return errors.New("delegated cell spec leaf must differ from offline root")
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
	envelope, err := cellspec.SignDelegation(leafPublic, id, issuedAt, expiresAt, rootPrivate)
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

func (c command) signSpec(args []string) error {
	return c.signSpecAt(args, time.Now().UTC())
}

// signSpecAt signs an unsigned candidate written by `ts-orch service
// add|update|remove --out` or by hand. The online release leaf signs under
// its delegation; with --root the offline root signs the spec itself, which
// an amendment that widens authority needs.
func (c command) signSpecAt(args []string, now time.Time) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	flags := flag.NewFlagSet("sign-spec", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	candidate := flags.String("candidate", "", "unsigned canonical cell spec JSON")
	delegationPath := flags.String("delegation", "", "root-signed cell spec delegation envelope (leaf signing)")
	asRoot := flags.Bool("root", false, "sign with the offline root key itself instead of the delegated leaf")
	rootPath := flags.String("root-key", "", "baked root public key PEM")
	privatePath := flags.String("signing-key", "", "owner-only delegated, or with --root offline root, Ed25519 PKCS#8 private key PEM")
	validFor := flags.Duration("valid-for", time.Hour, "time the signed spec may wait to be applied")
	output := flags.String("out", "", "new signed cell spec path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *candidate == "" || *asRoot == (*delegationPath != "") || *rootPath == "" || *privatePath == "" || *output == "" || flags.NArg() != 0 {
		return errors.New("sign-spec requires --candidate, either --delegation or --root, --root-key, --signing-key and --out")
	}
	encoded, err := readBoundedRegular(*candidate, cellspec.MaxSpecBytes)
	if err != nil {
		return err
	}
	spec, err := cellspec.Decode(encoded)
	if err != nil {
		return err
	}
	var delegationWire []byte
	if !*asRoot {
		if delegationWire, err = readBoundedRegular(*delegationPath, trust.MaxEnvelopeBytes); err != nil {
			return err
		}
		if _, err := trust.DecodeEnvelope(delegationWire); err != nil {
			return fmt.Errorf("cell spec delegation: %w", err)
		}
	}
	root, err := readRootPublicKey(*rootPath)
	if err != nil {
		return err
	}
	roots, err := trust.ParseKeyring(root)
	if err != nil {
		return err
	}
	readKey := readDelegatedPrivateKey
	if *asRoot {
		readKey = readOfflineRootPrivateKey
	}
	private, err := readKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(private)
	if err := c.ctx.Err(); err != nil {
		return err
	}
	wire, err := cellspec.Sign(spec, delegationWire, roots, now, *validFor, private)
	if err != nil {
		return err
	}
	if err := c.writeNew(*output, wire, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(wire)
	return c.printJSON(struct {
		Generation     uint64 `json:"generation"`
		RequiresBinary uint64 `json:"requires_binary"`
		Signer         string `json:"signer"`
		SHA256         string `json:"sha256"`
		DeploymentID   string `json:"deployment_id"`
		Cell           string `json:"cell"`
		Environment    string `json:"environment"`
	}{spec.Generation, spec.RequiresBinary, map[bool]string{true: "root", false: "leaf"}[*asRoot],
		hex.EncodeToString(sum[:]), spec.DeploymentID, spec.Cell, spec.Environment})
}

func (c command) printJSON(value any) error {
	encoded, err := protocol.EncodeJSON(value)
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(c.output, "%s\n", encoded)
	return err
}

package cli

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

// pathList collects a repeated path flag.
type pathList []string

func (list *pathList) String() string { return strings.Join(*list, ",") }

func (list *pathList) Set(value string) error {
	*list = append(*list, value)
	return nil
}

func (c command) signRootRotation(args []string) error {
	return c.signRootRotationAt(args, time.Now().UTC())
}

// signRootRotationAt adds one root's signature to the statement that
// replaces the cell's current root set. Old and new root holders run it in
// turn on the same --signed file; the statement is complete once a majority
// of the current roots and every new root signed.
func (c command) signRootRotationAt(args []string, now time.Time) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	flags := flag.NewFlagSet("sign-root-rotation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	var genesisPaths, newRootPaths pathList
	flags.Var(&genesisPaths, "genesis-root", "baked image root public key PEM (repeat for each)")
	flags.Var(&newRootPaths, "new-root", "new root public key PEM (repeat for each)")
	chainPath := flags.String("chain", "", "current root chain from ts-orch operator trust-roots --out")
	var id trust.ChainIdentity
	flags.StringVar(&id.DeploymentID, "deployment-id", "", "deployment of the chain")
	flags.StringVar(&id.Cell, "cell", "", "cell of the chain")
	flags.StringVar(&id.Environment, "environment", "", "environment of the chain")
	privatePath := flags.String("signing-key", "", "owner-only Ed25519 PKCS#8 private key of a current or new root")
	signedPath := flags.String("signed", "", "partly signed rotation to add this signature to")
	validFor := flags.Duration("valid-for", 24*time.Hour, "time the signature may wait to be applied")
	output := flags.String("out", "", "new signed rotation path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if len(genesisPaths) == 0 || len(newRootPaths) == 0 || *chainPath == "" || *privatePath == "" || *output == "" ||
		flags.NArg() != 0 {
		return errors.New("sign-root-rotation requires --genesis-root, --chain, identity, --new-root, --signing-key and --out")
	}
	if *validFor <= 0 || *validFor > trust.MaxRotationLifetime {
		return fmt.Errorf("--valid-for must be positive and at most %s", trust.MaxRotationLifetime)
	}
	genesisKeys, err := readPublicKeys(genesisPaths)
	if err != nil {
		return err
	}
	genesis, err := trust.ParseKeyring(genesisKeys...)
	if err != nil {
		return err
	}
	chainWire, err := readBoundedRegular(*chainPath, trust.MaxRootChainBytes)
	if err != nil {
		return err
	}
	chain, err := trust.DecodeRootChain(chainWire)
	if err != nil {
		return err
	}
	verified, err := trust.VerifyRootChain(genesis, id, chain)
	if err != nil {
		return fmt.Errorf("current root chain: %w", err)
	}
	newRoots, err := readPublicKeys(newRootPaths)
	if err != nil {
		return err
	}
	rotation, err := trust.NextRotation(verified, newRoots...)
	if err != nil {
		return err
	}
	var signed trust.SignedRotation
	if *signedPath != "" {
		wire, err := readBoundedRegular(*signedPath, trust.MaxRootChainBytes)
		if err != nil {
			return err
		}
		if err := protocol.DecodeStrict(wire, &signed, trust.MaxRootChainBytes); err != nil {
			return fmt.Errorf("partly signed rotation: %w", err)
		}
		existing, err := signed.Payload()
		if err != nil {
			return err
		}
		left, leftErr := trust.EncodePayload(existing)
		right, rightErr := trust.EncodePayload(rotation)
		if leftErr != nil || rightErr != nil || string(left) != string(right) {
			return errors.New("partly signed rotation is a different statement than --chain and --new-root build")
		}
	}
	private, err := readOfflineRootPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(private)
	keyID, err := trust.KeyID(private.Public().(ed25519.PublicKey))
	if err != nil {
		return err
	}
	next, _ := trust.ParseKeyring(newRoots...)
	if verified.Current[keyID] == nil && next[keyID] == nil {
		return errors.New("signing key is neither a current nor a new root")
	}
	for _, envelope := range signed.Signatures {
		if envelope.KeyID == keyID {
			return errors.New("this root already signed the rotation")
		}
	}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	envelope, err := trust.SignRotation(rotation, id, now, now.Add(*validFor), private)
	if err != nil {
		return err
	}
	signed.Signatures = append(signed.Signatures, envelope)
	// The leader applies a statement only while every signature is current.
	if err := trust.RotationCurrent(signed, now); err != nil {
		return fmt.Errorf("a signature in --signed is no longer current; collect them again: %w", err)
	}
	_, completeErr := trust.VerifyRootChain(genesis, id, trust.RootChain{Version: 1, Rotations: append(chain.Rotations, signed)})
	if completeErr != nil && !errors.Is(completeErr, trust.ErrRotationSigners) {
		return completeErr
	}
	wire, err := protocol.EncodeJSON(signed)
	if err != nil {
		return err
	}
	if err := c.writeNew(*output, wire, 0o644); err != nil {
		return err
	}
	sum := sha256.Sum256(wire)
	return c.printJSON(struct {
		Sequence   uint64 `json:"sequence"`
		Signatures int    `json:"signatures"`
		Complete   bool   `json:"complete"`
		SHA256     string `json:"sha256"`
	}{rotation.Sequence, len(signed.Signatures), completeErr == nil, hex.EncodeToString(sum[:])})
}

func readPublicKeys(paths []string) ([]ed25519.PublicKey, error) {
	keys := make([]ed25519.PublicKey, 0, len(paths))
	for _, path := range paths {
		key, err := readRootPublicKey(path)
		if err != nil {
			return nil, err
		}
		keys = append(keys, key)
	}
	return keys, nil
}

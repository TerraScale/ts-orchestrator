package cli

import (
	"bytes"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"reflect"
	"slices"
	"syscall"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
	"github.com/TerraScale/ts-orchestrator/internal/trust"
)

type releaseArchitectures []string

func (architectures *releaseArchitectures) String() string {
	return fmt.Sprint([]string(*architectures))
}

func (architectures *releaseArchitectures) Set(value string) error {
	if value != "amd64" && value != "arm64" {
		return errors.New("architecture must be amd64 or arm64")
	}
	for _, existing := range *architectures {
		if existing == value {
			return errors.New("duplicate architecture")
		}
	}
	*architectures = append(*architectures, value)
	return nil
}

func (c command) signDelegation(args []string) error {
	return c.signDelegationAt(args, time.Now().UTC())
}

func (c command) signDelegationAt(args []string, now time.Time) error {
	if err := c.ctx.Err(); err != nil {
		return err
	}
	flags := flag.NewFlagSet("sign-delegation", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	leafPath := flags.String("subject-public-key", "", "delegated Ed25519 PKIX public key PEM")
	rootPath := flags.String("root-key", "", "offline root Ed25519 PKIX public key PEM")
	privatePath := flags.String("signing-key", "", "owner-only offline root Ed25519 PKCS#8 private key PEM")
	sourceRevision := flags.String("source-revision", "", "exact 40-character source revision")
	var architectures releaseArchitectures
	flags.Var(&architectures, "arch", "exact release architecture: amd64 or arm64; repeatable")
	imageRegion := flags.String("image-cell", "", "catalog cell of the image, e.g. GRU")
	imageOCID := flags.String("image-ocid", "", "exact OCI image OCID imported into the cell's region")
	previousPath := flags.String("previous-delegation", "", "current binary-only delegation to extend for an image")
	environment := flags.String("environment", "canary", "release environment; canary only")
	issuedAtText := flags.String("issued-at", "", "canonical UTC RFC3339 issuance instant")
	expiresAtText := flags.String("expires-at", "", "canonical UTC RFC3339 expiry instant")
	output := flags.String("out", "", "new root-signed delegation envelope")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *leafPath == "" || *rootPath == "" || *privatePath == "" || *output == "" ||
		!release.ValidSourceRevision(*sourceRevision) || len(architectures) == 0 ||
		*environment != "canary" || flags.NArg() != 0 ||
		((*imageRegion == "") != (*imageOCID == "")) ||
		((*imageOCID == "") != (*previousPath == "")) ||
		(*imageRegion != "" && !release.ValidOCIImageIDForRegion(*imageOCID, *imageRegion)) {
		return errors.New("sign-delegation requires exact canary source, architecture, keys, UTC interval, output, and optional catalog-cell image pair")
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
		!expiresAt.After(issuedAt) || expiresAt.Sub(issuedAt) > release.MaxDelegationLifetime {
		return errors.New("delegation must be current and valid for no more than the release lifetime")
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
		return errors.New("delegated leaf must differ from offline root")
	}
	rootPrivate, err := readOfflineRootPrivateKey(*privatePath)
	if err != nil {
		return err
	}
	defer clear(rootPrivate)
	if !bytes.Equal(rootPrivate.Public().(ed25519.PublicKey), rootPublic) {
		return errors.New("offline root signing key does not match root public key")
	}
	rootKeys, err := trust.ParseKeyring(rootPublic)
	if err != nil {
		return err
	}
	leafID, err := trust.KeyID(leafPublic)
	if err != nil {
		return err
	}
	leafEncoded, err := trust.EncodeDelegatedPublicKey(leafPublic)
	if err != nil {
		return err
	}
	binaryCapabilities := make([]trust.Capability, 0, len(architectures))
	for _, architecture := range architectures {
		scope := release.BinaryScope(release.BinaryReceipt{SourceRevision: *sourceRevision, GOARCH: architecture}, "canary")
		binaryCapabilities = append(binaryCapabilities, capabilityForScope(scope))
	}
	capabilities := binaryCapabilities
	if *imageOCID != "" {
		previousEnvelope, err := readEnvelope(*previousPath)
		if err != nil {
			return fmt.Errorf("read previous binary delegation: %w", err)
		}
		previous, err := trust.VerifyDelegationCurrent(previousEnvelope, rootKeys, now,
			trust.Policy{MaxLifetime: release.MaxDelegationLifetime, ClockSkew: time.Minute})
		if err != nil {
			return fmt.Errorf("verify current previous binary delegation: %w", err)
		}
		if previous.SubjectKeyID() != leafID || !previousEnvelope.IssuedAt.Equal(issuedAt) ||
			!previousEnvelope.ExpiresAt.Equal(expiresAt) ||
			!sameCapabilitySet(previous.Capabilities(), binaryCapabilities) {
			return errors.New("image phase differs from previous leaf, source, architecture set, or validity interval")
		}
		capabilities = previous.Capabilities()
		scope := release.ImageScope(release.ImageReceipt{SourceRevision: *sourceRevision,
			OCIRegion: *imageRegion, OCIImageOCID: *imageOCID}, "canary")
		capabilities = append(capabilities, capabilityForScope(scope))
	}
	delegation := trust.Delegation{SchemaVersion: trust.SchemaVersion, SubjectKeyID: leafID,
		SubjectPublicKey: leafEncoded, Capabilities: capabilities}
	if err := c.ctx.Err(); err != nil {
		return err
	}
	envelope, err := trust.SignDelegation(delegation, issuedAt, expiresAt, rootPrivate)
	if err != nil {
		return err
	}
	wire, err := trust.EncodeEnvelope(envelope)
	if err != nil {
		return err
	}
	decoded, err := trust.DecodeEnvelope(wire)
	if err != nil {
		return err
	}
	verified, err := trust.VerifyDelegationCurrent(decoded, rootKeys, now,
		trust.Policy{MaxLifetime: release.MaxDelegationLifetime, ClockSkew: time.Minute})
	if err != nil {
		return fmt.Errorf("verify current release delegation: %w", err)
	}
	if verified.SubjectKeyID() != leafID || !reflect.DeepEqual(verified.Capabilities(), capabilities) {
		return errors.New("signed release delegation differs from exact requested capabilities")
	}
	return c.writeNew(*output, wire, 0o644)
}

func sameCapabilitySet(actual, expected []trust.Capability) bool {
	if len(actual) != len(expected) {
		return false
	}
	for _, capability := range actual {
		if !slices.ContainsFunc(expected, func(other trust.Capability) bool {
			return reflect.DeepEqual(capability, other)
		}) {
			return false
		}
	}
	return true
}

func capabilityForScope(scope trust.Scope) trust.Capability {
	return trust.Capability{Domain: scope.Domain, DeploymentID: scope.DeploymentID,
		Cell: scope.Cell, Environment: scope.Environment, Role: scope.Role,
		Slots: []string{scope.Slot}, Actions: []string{"sign"}}
}

func parseDelegationUTC(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil || parsed.Format(time.RFC3339) != value || parsed.Location() != time.UTC {
		return time.Time{}, errors.New("must be a canonical UTC RFC3339 instant ending in Z")
	}
	return parsed, nil
}

func readLeafPublicKey(path string) (ed25519.PublicKey, error) {
	data, err := readBoundedRegular(path, maxKeyFileBytes)
	if err != nil {
		return nil, err
	}
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("delegated leaf public key must be Ed25519 PKIX PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse delegated leaf public key: %w", err)
	}
	public, ok := parsed.(ed25519.PublicKey)
	if !ok || len(public) != ed25519.PublicKeySize {
		return nil, errors.New("delegated leaf public key must be Ed25519")
	}
	return public, nil
}

func readOfflineRootPrivateKey(path string) (ed25519.PrivateKey, error) {
	file, err := openRegular(path)
	if err != nil {
		return nil, fmt.Errorf("open offline root signing key: %w", err)
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("stat offline root signing key: %w", err)
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 {
		return nil, errors.New("offline root signing key must be a regular owner-only file")
	}
	if stat, ok := info.Sys().(*syscall.Stat_t); ok && stat.Uid != uint32(os.Getuid()) {
		return nil, errors.New("offline root signing key must be owned by this process user")
	}
	if info.Size() <= 0 || info.Size() > maxKeyFileBytes {
		return nil, errors.New("offline root signing key exceeds size limit")
	}
	data, err := io.ReadAll(io.LimitReader(file, maxKeyFileBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read offline root signing key: %w", err)
	}
	defer clear(data)
	block, rest := pem.Decode(data)
	if block == nil || block.Type != "PRIVATE KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("offline root signing key must be PEM PKCS#8 Ed25519")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse offline root signing key: %w", err)
	}
	private, ok := parsed.(ed25519.PrivateKey)
	if !ok || len(private) != ed25519.PrivateKeySize {
		return nil, errors.New("offline root signing key must be Ed25519")
	}
	return private, nil
}

// Package transitiongrant defines the owner's finite first-candidate admission.
// Its signature authorizes preparation only, never control mutations or election.
package transitiongrant

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const Mode = "prepare-control-candidate"
const Arguments = Mode + " --config @config"
const MaximumBytes = 64 << 10
const domain = "TS-CONTROL-CANDIDATE-PREPARATION-V1\x00"

type Config struct {
	Sync               *CandidateSyncConfig `json:"sync,omitempty"`
	Version            int                  `json:"version"`
	Mode               string               `json:"mode"`
	TransitionID       string               `json:"transitionId"`
	NodeID             string               `json:"nodeId"`
	Region             string               `json:"region"`
	ServerName         string               `json:"serverName"`
	StoreDir           string               `json:"storeDir"`
	GrantFile          string               `json:"grantFile"`
	GrantPublicKeyFile string               `json:"grantPublicKeyFile"`
}
type SourceIdentity struct {
	NodeID             string `json:"nodeId"`
	ServerName         string `json:"serverName"`
	InitialGrantSHA256 string `json:"initialGrantSha256"`
	StoreScopeSHA256   string `json:"storeScopeSha256"`
}
type Peer struct {
	Region                 string `json:"region"`
	NodeID                 string `json:"nodeId"`
	ServerName             string `json:"serverName"`
	BootstrapGrantSHA256   string `json:"bootstrapGrantSha256"`
	PreparedManifestSHA256 string `json:"preparedManifestSha256"`
}
type Grant struct {
	Version             int            `json:"version"`
	TransitionID        string         `json:"transitionId"`
	IssuedAt            time.Time      `json:"issuedAt"`
	ExpiresAt           time.Time      `json:"expiresAt"`
	Source              SourceIdentity `json:"source"`
	TargetEpoch         uint64         `json:"targetEpoch"`
	MinimumControlEpoch uint64         `json:"minimumControlEpoch"`
	Peers               []Peer         `json:"peers"`
}
type signedDocument struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}
type VerifiedGrant struct {
	Grant      Grant
	Digest     string
	OwnerKeyID string
}

func token(s string) bool {
	_, e := hostmanifest.RequireToken(s, "identity", "transitiongrant: invalid identity")
	return e == nil
}
func digest(s string) bool {
	b, e := hex.DecodeString(s)
	return e == nil && len(b) == 32 && hex.EncodeToString(b) == s
}
func canonicalDecode(raw []byte, v any) error {
	if len(raw) == 0 || len(raw) > MaximumBytes {
		return errors.New("transitiongrant: document exceeds bound")
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	if d.Decode(v) != nil || d.Decode(&struct{}{}) != io.EOF {
		return errors.New("transitiongrant: malformed document")
	}
	encoded, e := json.Marshal(v)
	if e != nil || !bytes.Equal(raw, encoded) {
		return errors.New("transitiongrant: noncanonical document")
	}
	return nil
}
func (c Config) Validate() error {
	if c.Version != 1 || c.Mode != Mode || !token(c.TransitionID) || (c.Region != "sfo" && c.Region != "fra") || !token(c.NodeID) || !strings.HasPrefix(c.NodeID, c.Region+"-") || !token(c.ServerName) || !hostmanifest.SafeAbsolutePath(c.StoreDir) || !hostmanifest.SafeAbsolutePath(c.GrantFile) || !hostmanifest.SafeAbsolutePath(c.GrantPublicKeyFile) || c.GrantFile == c.GrantPublicKeyFile {
		return errors.New("transitiongrant: invalid candidate configuration")
	}
	// Admission material must remain separate even when no sync worker exists.
	paths := []string{c.StoreDir, c.GrantFile, c.GrantPublicKeyFile}
	for i, path := range paths {
		for _, prior := range paths[:i] {
			if hostmanifest.PathsOverlap(path, prior) {
				return errors.New("transitiongrant: candidate storage and admission paths overlap")
			}
		}
	}
	if c.Sync != nil {
		paths := []string{c.Sync.RequestFile, c.Sync.StagingDir, c.Sync.ReceiptDir, c.Sync.ReceiptPrivateKeyFile, c.StoreDir}
		if c.Sync.Identity.Qualification != nil {
			paths = append(paths, c.Sync.Identity.Qualification.ClientPrivateKeyFile)
		}
		for _, path := range paths {
			if hostmanifest.PathsOverlap(path, c.GrantFile) || hostmanifest.PathsOverlap(path, c.GrantPublicKeyFile) {
				return errors.New("transitiongrant: candidate sync path overlaps preparation admission")
			}
		}
		return c.Sync.Validate(c.StoreDir)
	}
	return nil
}
func ParseConfig(raw []byte) (Config, error) {
	var c Config
	if e := canonicalDecode(raw, &c); e != nil {
		return c, e
	}
	return c, c.Validate()
}
func ComponentConfig(spec hostmanifest.ComponentSpec) (Config, bool, error) {
	fields := strings.Fields(spec.Arguments)
	candidate := len(fields) > 0 && fields[0] == Mode
	if !candidate {
		var marker struct {
			Mode string `json:"mode"`
		}
		_ = json.Unmarshal([]byte(spec.Configuration), &marker)
		candidate = marker.Mode == Mode
	}
	if !candidate {
		return Config{}, false, nil
	}
	if spec.Name != "orchestrator" || spec.User != "terrascale-orchestrator" || spec.Arguments != Arguments {
		return Config{}, true, errors.New("transitiongrant: candidate launch differs")
	}
	c, e := ParseConfig([]byte(spec.Configuration))
	if e != nil {
		return c, true, e
	}
	if !strings.HasPrefix(c.StoreDir, strings.TrimSuffix(spec.DataVolume, "/")+"/") {
		return c, true, errors.New("transitiongrant: candidate store must be within dedicated data volume")
	}
	if !hostmanifest.SafeAbsolutePath(spec.DataVolume) || hostmanifest.PathsOverlap(spec.DataVolume, c.GrantFile) || hostmanifest.PathsOverlap(spec.DataVolume, c.GrantPublicKeyFile) {
		return c, true, errors.New("transitiongrant: preparation admission overlaps writable data volume")
	}
	if c.Sync != nil {
		if err := c.Sync.validateComponent(spec.DataVolume); err != nil {
			return c, true, err
		}
	}
	return c, true, nil
}
func CanonicalGrant(g Grant) ([]byte, error) {
	if g.Version != 1 || !token(g.TransitionID) || g.IssuedAt.IsZero() || !g.ExpiresAt.After(g.IssuedAt) || g.ExpiresAt.Sub(g.IssuedAt) > 24*time.Hour || g.TargetEpoch == 0 || g.MinimumControlEpoch == 0 || !token(g.Source.NodeID) || !strings.HasPrefix(g.Source.NodeID, "gru-") || !token(g.Source.ServerName) || !digest(g.Source.InitialGrantSHA256) || !digest(g.Source.StoreScopeSHA256) || len(g.Peers) != 3 {
		return nil, errors.New("transitiongrant: invalid finite preparation grant")
	}
	seenNode, seenServer := map[string]bool{}, map[string]bool{}
	for i, region := range []string{"gru", "sfo", "fra"} {
		p := g.Peers[i]
		if p.Region != region || !token(p.NodeID) || !strings.HasPrefix(p.NodeID, region+"-") || !token(p.ServerName) || seenNode[p.NodeID] || seenServer[p.ServerName] || !digest(p.BootstrapGrantSHA256) || !digest(p.PreparedManifestSHA256) {
			return nil, errors.New("transitiongrant: invalid exact peer inventory")
		}
		seenNode[p.NodeID] = true
		seenServer[p.ServerName] = true
	}
	raw, e := json.Marshal(g)
	if e != nil || len(raw) > MaximumBytes {
		return nil, errors.New("transitiongrant: grant exceeds bound")
	}
	return raw, nil
}
func SignGrant(s *security.CommandSignatureSigner, g Grant) ([]byte, error) {
	if s == nil {
		return nil, errors.New("transitiongrant: owner signer required")
	}
	raw, e := CanonicalGrant(g)
	if e != nil {
		return nil, e
	}
	sig, e := s.SignCanonicalMaterial(append([]byte(domain), raw...))
	if e != nil {
		return nil, e
	}
	return json.Marshal(signedDocument{raw, sig.Bytes()})
}
func VerifyGrant(public, signed []byte) (VerifiedGrant, error) {
	fail := func() (VerifiedGrant, error) {
		return VerifiedGrant{}, errors.New("transitiongrant: owner signature or grant refused")
	}
	block, rest := pem.Decode(public)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return fail()
	}
	parsed, e := x509.ParsePKIXPublicKey(block.Bytes)
	if e != nil {
		return fail()
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return fail()
	}
	var doc signedDocument
	if canonicalDecode(signed, &doc) != nil {
		return fail()
	}
	var g Grant
	if canonicalDecode(doc.Payload, &g) != nil {
		return fail()
	}
	canonical, e := CanonicalGrant(g)
	if e != nil || !bytes.Equal(canonical, doc.Payload) {
		return fail()
	}
	signature, ok := protocol.OpaqueSignatureTryCopyFrom(doc.Signature)
	if !ok {
		return fail()
	}
	id, _, sig, ok := security.DecodeCommandSignature(signature)
	owner := sha256.Sum256(block.Bytes)
	keyID := hex.EncodeToString(owner[:])
	hash := sha256.Sum256(append([]byte(domain), doc.Payload...))
	if !ok || id != keyID || !ecdsa.VerifyASN1(key, hash[:], sig) {
		return fail()
	}
	sum := sha256.Sum256(signed)
	return VerifiedGrant{g, hex.EncodeToString(sum[:]), keyID}, nil
}
func (v VerifiedGrant) CheckCandidate(now time.Time, c Config, bootstrapDigest, manifestDigest string) error {
	if now.Before(v.Grant.IssuedAt) || !now.Before(v.Grant.ExpiresAt) || c.Validate() != nil || c.TransitionID != v.Grant.TransitionID {
		return errors.New("transitiongrant: candidate grant expired or scope differs")
	}
	for _, p := range v.Grant.Peers {
		if p.NodeID == c.NodeID && p.Region == c.Region && p.ServerName == c.ServerName && p.BootstrapGrantSHA256 == bootstrapDigest && p.PreparedManifestSHA256 == manifestDigest {
			return nil
		}
	}
	return errors.New("transitiongrant: candidate launch not granted")
}

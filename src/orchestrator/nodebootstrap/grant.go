package nodebootstrap

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"regexp"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/natspolicy"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/protocol"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

const bootstrapGrantDomain = "TS-NODE-INITIAL-GRANT-V1\x00"
const bootstrapCommandDomain = "TS-NODE-INITIAL-COMMAND-V1\x00"

// BootstrapGrant admits the complete initial host manifest, including launch
// arguments, configuration, users and storage paths. It has no runtime epoch.
type BootstrapGrant struct {
	Version   int             `json:"version"`
	GrantID   string          `json:"grantId"`
	NodeID    string          `json:"nodeId"`
	Manifest  json.RawMessage `json:"manifest"`
	IssuedAt  time.Time       `json:"issuedAt"`
	ExpiresAt time.Time       `json:"expiresAt"`
}
type bootstrapSignedDocument struct {
	Payload   json.RawMessage `json:"payload"`
	Signature []byte          `json:"signature"`
}
type bootstrapRequest struct {
	GrantSHA256 string          `json:"grantSha256"`
	NodeID      string          `json:"nodeId"`
	Subject     string          `json:"subject"`
	Command     json.RawMessage `json:"command"`
	IssuedAt    time.Time       `json:"issuedAt"`
	ExpiresAt   time.Time       `json:"expiresAt"`
}

// BootstrapAuthority contains only a public key and immutable admitted grant.
// Runtime is the independent real regional lease verifier.
type BootstrapAuthority struct {
	key            *ecdsa.PublicKey
	keyID          string
	grant          BootstrapGrant
	digest         string
	manifestDigest string
	commands       []BootstrapCommand
}

// BootstrapCommand is one exact, idempotent initial activation step.
type BootstrapCommand struct {
	Subject string
	Command json.RawMessage
}

const hostAgentMaximumManifestBytes = 1 << 20

func canonicalBootstrapGrant(grant BootstrapGrant) ([]byte, error) {
	if grant.Version != 1 || !validToken(grant.NodeID) || !validToken(grant.GrantID) || grant.IssuedAt.IsZero() || !grant.ExpiresAt.After(grant.IssuedAt) || grant.ExpiresAt.Sub(grant.IssuedAt) > 24*time.Hour {
		return nil, errors.New("nodebootstrap: invalid grant identity or lifetime")
	}
	if len(grant.Manifest) == 0 || len(grant.Manifest) > hostAgentMaximumManifestBytes || !json.Valid(grant.Manifest) {
		return nil, errors.New("nodebootstrap: invalid manifest bound")
	}
	components, err := grantComponents(grant)
	if err != nil {
		return nil, err
	}
	if len(components) == 0 || len(components) > 8 {
		return nil, errors.New("nodebootstrap: invalid component count")
	}
	seen := map[string]bool{}
	for _, spec := range components {
		if (spec.Name != "orchestrator" && spec.Name != "terrabase" && spec.Name != "grafana-agent") || seen[spec.Name] || spec.Version == "" || len(spec.Version) > 128 {
			return nil, errors.New("nodebootstrap: invalid initial component")
		}
		seen[spec.Name] = true
	}
	return json.Marshal(grant)
}
func validToken(value string) bool {
	return len(value) > 0 && len(value) <= 63 && regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`).MatchString(value)
}

type initialComponent struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

func grantComponents(grant BootstrapGrant) ([]initialComponent, error) {
	var manifest struct {
		Components []initialComponent `json:"components"`
	}
	if err := json.Unmarshal(grant.Manifest, &manifest); err != nil {
		return nil, err
	}
	return manifest.Components, nil
}
func CanonicalGrant(grant BootstrapGrant) ([]byte, error) { return canonicalBootstrapGrant(grant) }
func decodeCommandObjectBounded(data []byte, maximum int, required ...string) (map[string]json.RawMessage, error) {
	if len(data) == 0 || len(data) > maximum {
		return nil, errors.New("nodebootstrap: object exceeds bound")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errors.New("nodebootstrap: expected object")
	}
	allowed := map[string]bool{}
	for _, name := range required {
		allowed[name] = true
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, err
		}
		name, ok := token.(string)
		if !ok || !allowed[name] || fields[name] != nil {
			return nil, errors.New("nodebootstrap: duplicate or unknown field")
		}
		var value json.RawMessage
		if err = decoder.Decode(&value); err != nil || bytes.Equal(value, []byte("null")) {
			return nil, errors.New("nodebootstrap: invalid field")
		}
		fields[name] = value
	}
	if token, err = decoder.Token(); err != nil || token != json.Delim('}') {
		return nil, errors.New("nodebootstrap: incomplete object")
	}
	if _, err = decoder.Token(); err != io.EOF || len(fields) != len(required) {
		return nil, errors.New("nodebootstrap: missing or trailing data")
	}
	return fields, nil
}
func decodeCommandObject(data []byte, required ...string) (map[string]json.RawMessage, error) {
	return decodeCommandObjectBounded(data, 64<<10, required...)
}

// SignBootstrapGrant is called by the owner's provisioning process. The private
// signing key must never be staged on the member host.
func SignBootstrapGrant(signer *security.CommandSignatureSigner, grant BootstrapGrant) ([]byte, error) {
	payload, err := canonicalBootstrapGrant(grant)
	if err != nil {
		return nil, err
	}
	return signBootstrapDocument(signer, bootstrapGrantDomain, payload)
}
func signBootstrapDocument(signer *security.CommandSignatureSigner, domain string, payload []byte) ([]byte, error) {
	signature, err := signer.SignCanonicalMaterial(append([]byte(domain), payload...))
	if err != nil {
		return nil, err
	}
	return json.Marshal(bootstrapSignedDocument{Payload: payload, Signature: signature.Bytes()})
}
func decodeBootstrapDocument(wire []byte) (bootstrapSignedDocument, error) {
	var document bootstrapSignedDocument
	if len(wire) > hostAgentMaximumManifestBytes+16384 {
		return document, errors.New("hostagent: bootstrap document exceeds bound")
	}
	if _, err := decodeCommandObjectBounded(wire, hostAgentMaximumManifestBytes+16384, "payload", "signature"); err != nil {
		return document, err
	}
	if json.Unmarshal(wire, &document) != nil || len(document.Payload) == 0 || len(document.Signature) > 256 {
		return document, errors.New("hostagent: invalid bootstrap signature document")
	}
	return document, nil
}
func verifyBootstrapDocument(wire []byte, domain string, key *ecdsa.PublicKey, keyID string) ([]byte, error) {
	document, err := decodeBootstrapDocument(wire)
	if err != nil {
		return nil, err
	}
	signature, valid := protocol.OpaqueSignatureTryCopyFrom(document.Signature)
	if !valid {
		return nil, errors.New("hostagent: empty bootstrap signature")
	}
	actual, _, raw, ok := security.DecodeCommandSignature(signature)
	digest := sha256.Sum256(append([]byte(domain), document.Payload...))
	if !ok || actual != keyID || !ecdsa.VerifyASN1(key, digest[:], raw) {
		return nil, errors.New("hostagent: bootstrap signature refused")
	}
	return document.Payload, nil
}

// NewBootstrapAuthority verifies a pinned public SPKI key and a signed grant.
// Expiry is checked at admission, so an expired seed can remain configured
// after durable runtime handoff without preventing already admitted service.
func NewBootstrapAuthority(node string, publicPEM, signedGrant []byte) (*BootstrapAuthority, error) {
	return parseBootstrapAuthority(node, publicPEM, signedGrant)
}
func (a *BootstrapAuthority) Grant() BootstrapGrant {
	grant := a.grant
	grant.Manifest = append([]byte(nil), a.grant.Manifest...)
	return grant
}
func (a *BootstrapAuthority) Digest() string { return a.digest }

// VerifyBootstrapGrant verifies the dedicated owner signature and returns its
// host-bound full manifest. Callers must also enforce the grant time window at
// each new operation; an expired grant remains readable for audit/restart.
func VerifyBootstrapGrant(node string, publicPEM, signedGrant []byte) (BootstrapGrant, error) {
	authority, err := parseBootstrapAuthority(node, publicPEM, signedGrant)
	if err != nil {
		return BootstrapGrant{}, err
	}
	return authority.grant, nil
}
func parseBootstrapAuthority(node string, publicPEM, signedGrant []byte) (*BootstrapAuthority, error) {
	block, rest := pem.Decode(publicPEM)
	if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
		return nil, errors.New("hostagent: bootstrap key must be one public SPKI PEM")
	}
	parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, err
	}
	key, ok := parsed.(*ecdsa.PublicKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, errors.New("hostagent: bootstrap key must use P256")
	}
	keyDigest := sha256.Sum256(block.Bytes)
	keyID := hex.EncodeToString(keyDigest[:])
	payload, err := verifyBootstrapDocument(signedGrant, bootstrapGrantDomain, key, keyID)
	if err != nil {
		return nil, err
	}
	if _, err = decodeCommandObjectBounded(payload, hostAgentMaximumManifestBytes+4096, "version", "grantId", "nodeId", "manifest", "issuedAt", "expiresAt"); err != nil {
		return nil, err
	}
	var grant BootstrapGrant
	if json.Unmarshal(payload, &grant) != nil {
		return nil, errors.New("hostagent: invalid bootstrap grant")
	}
	canonical, err := canonicalBootstrapGrant(grant)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(payload, canonical) || grant.NodeID != node {
		return nil, errors.New("hostagent: bootstrap grant is noncanonical or targets another host")
	}
	digest := sha256.Sum256(append([]byte(bootstrapGrantDomain+keyID+"\x00"), payload...))
	manifestHash := sha256.Sum256(grant.Manifest)
	manifestDigest := hex.EncodeToString(manifestHash[:])
	commands, err := BootstrapCommands(grant)
	if err != nil {
		return nil, err
	}
	return &BootstrapAuthority{key: key, keyID: keyID, grant: grant, digest: hex.EncodeToString(digest[:]), manifestDigest: manifestDigest, commands: commands}, nil
}

// BootstrapCommands returns the finite command set covered by the grant. Each
// component has one drain and activation; the host has one final release.
func BootstrapCommands(grant BootstrapGrant) ([]BootstrapCommand, error) {
	payload, err := canonicalBootstrapGrant(grant)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(payload)
	prefix := "boot-" + hex.EncodeToString(digest[:12])
	drainSubject, deploySubject, err := bootstrapSubjects(grant.NodeID)
	if err != nil {
		return nil, err
	}
	var commands []BootstrapCommand
	components, err := grantComponents(grant)
	if err != nil {
		return nil, err
	}
	for index, spec := range components {
		// Ordinals keep IDs within the durable command vocabulary for long names.
		suffix := hex.EncodeToString([]byte{byte(index)})
		drain := drainCommand{prefix + "-drain-" + suffix, true}
		deploy := deployCommand{prefix + "-deploy-" + suffix, spec.Name, spec.Version}
		data, _ := json.Marshal(drain)
		commands = append(commands, BootstrapCommand{drainSubject, data})
		data, _ = json.Marshal(deploy)
		commands = append(commands, BootstrapCommand{deploySubject, data})
	}
	release := drainCommand{prefix + "-release", false}
	data, _ := json.Marshal(release)
	return append(commands, BootstrapCommand{drainSubject, data}), nil
}

// SignBootstrapCommand signs one exact initial step for at most 30 seconds.
func SignBootstrapCommand(signer *security.CommandSignatureSigner, signedGrant []byte, subject string, command any, issued, expires time.Time) ([]byte, error) {
	document, err := decodeBootstrapDocument(signedGrant)
	if err != nil {
		return nil, err
	}
	var grant BootstrapGrant
	if json.Unmarshal(document.Payload, &grant) != nil {
		return nil, errors.New("hostagent: invalid signing grant")
	}
	canonical, err := canonicalBootstrapGrant(grant)
	if err != nil || !bytes.Equal(canonical, document.Payload) {
		return nil, errors.New("hostagent: invalid signing grant")
	}
	digest := sha256.Sum256(append([]byte(bootstrapGrantDomain+signer.PublicKeyID()+"\x00"), canonical...))
	data, err := json.Marshal(command)
	if err != nil {
		return nil, err
	}
	if issued.Before(grant.IssuedAt) || expires.After(grant.ExpiresAt) || !expires.After(issued) || expires.Sub(issued) > 30*time.Second {
		return nil, errors.New("hostagent: bootstrap command lifetime is invalid")
	}
	commands, err := BootstrapCommands(grant)
	if err != nil {
		return nil, err
	}
	found := false
	for _, allowed := range commands {
		found = found || subject == allowed.Subject && bytes.Equal(data, allowed.Command)
	}
	if !found {
		return nil, errors.New("hostagent: command is outside the initial grant")
	}
	payload, err := json.Marshal(bootstrapRequest{GrantSHA256: hex.EncodeToString(digest[:]), NodeID: grant.NodeID, Subject: subject, Command: data, IssuedAt: issued, ExpiresAt: expires})
	if err != nil {
		return nil, err
	}
	return signBootstrapDocument(signer, bootstrapCommandDomain, payload)
}
func (a *BootstrapAuthority) Authorize(ctx context.Context, subject string, wire []byte) (nodeauthority.CommandAuthorization, error) {
	if err := ctx.Err(); err != nil {
		return nodeauthority.CommandAuthorization{}, err
	}
	payload, err := verifyBootstrapDocument(wire, bootstrapCommandDomain, a.key, a.keyID)
	if err != nil {
		return nodeauthority.CommandAuthorization{}, err
	}
	if _, err = decodeCommandObject(payload, "grantSha256", "nodeId", "subject", "command", "issuedAt", "expiresAt"); err != nil {
		return nodeauthority.CommandAuthorization{}, err
	}
	var request bootstrapRequest
	if json.Unmarshal(payload, &request) != nil {
		return nodeauthority.CommandAuthorization{}, errors.New("hostagent: invalid bootstrap command")
	}
	now := time.Now().UTC()
	if request.GrantSHA256 != a.digest || request.NodeID != a.grant.NodeID || request.Subject != subject || now.Before(a.grant.IssuedAt) || !now.Before(a.grant.ExpiresAt) || now.Before(request.IssuedAt) || !now.Before(request.ExpiresAt) || request.IssuedAt.Before(a.grant.IssuedAt) || request.ExpiresAt.After(a.grant.ExpiresAt) || request.ExpiresAt.Sub(request.IssuedAt) > 30*time.Second {
		return nodeauthority.CommandAuthorization{}, errors.New("hostagent: bootstrap command scope or time refused")
	}
	allowed := false
	for _, command := range a.commands {
		allowed = allowed || command.Subject == subject && bytes.Equal(command.Command, request.Command)
	}
	if !allowed {
		return nodeauthority.CommandAuthorization{}, errors.New("hostagent: command is outside the initial grant")
	}
	return nodeauthority.CommandAuthorization{NodeID: a.grant.NodeID, Command: append([]byte(nil), request.Command...), ExpiresAt: request.ExpiresAt, BootstrapGrantSHA256: a.digest, BootstrapManifestSHA256: a.manifestDigest}, nil
}

type drainCommand struct {
	CommandID string `json:"commandId"`
	Drain     bool   `json:"drain"`
}
type deployCommand struct {
	CommandID string `json:"commandId"`
	Component string `json:"component"`
	Version   string `json:"version"`
}

func bootstrapSubjects(node string) (string, string, error) {
	cell := node
	for index, r := range node {
		if r == '-' {
			cell = node[:index]
			break
		}
	}
	drain, err := natspolicy.NatsSubjectTaxonomy.HostAgentCommandSubject(cell, node, "drain")
	if err != nil {
		return "", "", err
	}
	deploy, err := natspolicy.NatsSubjectTaxonomy.HostAgentCommandSubject(cell, node, "deploy")
	return drain, deploy, err
}

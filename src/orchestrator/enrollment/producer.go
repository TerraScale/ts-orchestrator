package enrollment

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json/v2"
	"encoding/pem"
	"maps"
	"slices"
	"strings"
	"time"

	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"
	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/keyrotation"
	"terrascale.tech/orchestrator/src/orchestrator/security"
)

type CredentialPublisher interface {
	PublishEnrollmentCredential(context.Context, keyrotation.EnrollmentCredentialRequest) (hostsecrets.Entry, error)
	Generate(context.Context, security.CapabilityRequest) (security.CapabilityMaterial, error)
}
type Issuer interface {
	Issue(context.Context, security.IdentityRequest) (security.IdentityMaterial, error)
}
type Store interface {
	Reserve(context.Context, Record) (Record, error)
	Publish(context.Context, Record) error
}
type Producer struct {
	Issuer  func(Record) (Issuer, error)
	Vault   CredentialPublisher
	Journal Store
	Signer  *security.CommandSignatureSigner
	Check   func(context.Context) error
}

// Template contains admitted service declarations and public bootstrap inputs.
// Only the explicit identity placeholders below are expanded. Private material
// always flows through Vault, never through Files or the compute metadata.
type Template struct {
	Manifests map[string]hostmanifest.HostManifest `json:"manifests"`
	Files     map[string]string                    `json:"files"`
}
type TLSRole struct{ Name, Certificate, Private, CA string }

var TLSRoles = []TLSRole{
	{"member", "/etc/terrascale/terrabase/server.pem", "/etc/terrascale/terrabase/key.pem", "/etc/terrascale/terrabase/ca.pem"},
	{"observer", "/etc/terrascale/engine-observer/client.pem", "/etc/terrascale/engine-observer/client.key", "/etc/terrascale/engine-observer/ca.pem"},
	{"control", "/etc/terrascale/placement/engine-client.pem", "/etc/terrascale/placement/engine-client.key", "/etc/terrascale/placement/engine-ca.pem"},
	{"placement-nats", "/etc/terrascale/placement/nats-client.pem", "/etc/terrascale/placement/nats-client.key", "/etc/terrascale/placement/nats-ca.pem"},
	{"database-nats", "/etc/terrascale/database/nats-client.pem", "/etc/terrascale/database/nats-client.key", "/etc/terrascale/database/nats-ca.pem"},
	{"node-nats", "/etc/terrascale/ts-node-bootstrap/client.pem", "/etc/terrascale/ts-node-bootstrap/client.key", "/etc/terrascale/ts-node-bootstrap/ca.pem"},
	{"authority-reader", "/etc/terrascale/ts-node-authority/client.pem", "/etc/terrascale/ts-node-authority/client.key", "/etc/terrascale/ts-node-authority/ca.pem"},
	{"regional", "/etc/terrascale/orchestrator/regional/client.pem", "/etc/terrascale/orchestrator/regional/client.key", "/etc/terrascale/orchestrator/regional/ca.pem"},
}

func Identity(r Record, role string) string {
	kind := "orchestrator-" + role
	if role == "member" {
		kind = "terrabase-member"
	}
	return "spiffe://terrascale.tech/" + r.Environment + "/" + kind + "/" + r.Cluster + "/" + r.MemberID
}
func render(template string, r Record, keys map[string]string) string {
	pairs := []string{"${NODE_ID}", r.NodeID, "${MEMBER_ID}", r.MemberID, "${REGION}", r.Region, "${ENVIRONMENT}", r.Environment, "${CLUSTER}", r.Cluster}
	for _, role := range TLSRoles {
		pairs = append(pairs, "${IDENTITY_"+role.Name+"}", Identity(r, role.Name))
	}
	for _, key := range slices.Sorted(maps.Keys(keys)) {
		pairs = append(pairs, "${PUBLIC_KEY_"+key+"}", keys[key])
	}
	return strings.NewReplacer(pairs...).Replace(template)
}
func (p *Producer) Enroll(ctx context.Context, r Record, template Template) (Record, PublicBootstrap, error) {
	if p == nil || p.Issuer == nil || p.Vault == nil || p.Journal == nil || p.Signer == nil || p.Check == nil {
		return Record{}, PublicBootstrap{}, ErrInvalid
	}
	if err := p.Check(ctx); err != nil {
		return Record{}, PublicBootstrap{}, err
	}
	digest, err := Digest(template)
	if err != nil {
		return Record{}, PublicBootstrap{}, err
	}
	r.TemplateDigest = digest
	r, err = p.Journal.Reserve(ctx, r)
	if err != nil {
		return Record{}, PublicBootstrap{}, err
	}
	if r.Public != nil {
		return r, *r.Public, nil
	}
	issuer, err := p.Issuer(r)
	if err != nil {
		return Record{}, PublicBootstrap{}, err
	}
	material, err := issuer.Issue(ctx, security.IdentityRequest{OperationID: r.OperationID, Generation: r.Generation, NotBefore: r.IssuedAt, ExpiresAt: r.ExpiresAt, IdempotencyKey: "enrollment/" + r.OperationID})
	if err != nil {
		return Record{}, PublicBootstrap{}, err
	}
	defer clear(material.WorkloadTLS)
	defer clear(material.ControlTLS)
	defer clear(material.TrustBundle)
	if material.Reference == "" || material.Version != r.Generation || !material.NotBefore.Equal(r.IssuedAt) || !material.ExpiresAt.Equal(r.ExpiresAt) {
		return Record{}, PublicBootstrap{}, ErrInvalid
	}
	tlsMaterial := map[string][]byte{}
	defer func() {
		for _, raw := range tlsMaterial {
			clear(raw)
		}
	}()
	if json.Unmarshal(material.WorkloadTLS, &tlsMaterial) != nil || len(tlsMaterial) != len(TLSRoles) {
		return Record{}, PublicBootstrap{}, ErrInvalid
	}
	public := PublicBootstrap{Files: map[string][]byte{}, PublicKeys: map[string]string{}, Seed: hostsecrets.Seed{Region: r.Region, OperationID: r.OperationID}}
	// Region in reservations is the estate code; Vault seed uses its OCI region.
	public.Seed.Region = OCIRegion(r.Region)
	publish := func(path string, content []byte) error {
		if err := p.Check(ctx); err != nil {
			return err
		}
		entry, e := p.Vault.PublishEnrollmentCredential(ctx, keyrotation.EnrollmentCredentialRequest{OperationID: r.OperationID, Destination: path, Content: content})
		if e != nil {
			return e
		}
		public.Seed.Entries = append(public.Seed.Entries, entry)
		return nil
	}
	for _, role := range TLSRoles {
		raw := tlsMaterial[role.Name]
		var certificate, private []byte
		for len(raw) > 0 {
			block, rest := pem.Decode(raw)
			if block == nil {
				return Record{}, PublicBootstrap{}, ErrInvalid
			}
			raw = rest
			if block.Type == "PRIVATE KEY" {
				private = pem.EncodeToMemory(block)
			} else if block.Type == "CERTIFICATE" {
				certificate = append(certificate, pem.EncodeToMemory(block)...)
			} else {
				return Record{}, PublicBootstrap{}, ErrInvalid
			}
		}
		pair, e := tls.X509KeyPair(certificate, private)
		if e != nil || pair.Leaf == nil || len(pair.Leaf.URIs) != 1 || pair.Leaf.URIs[0].String() != Identity(r, role.Name) {
			clear(private)
			return Record{}, PublicBootstrap{}, ErrInvalid
		}
		e = publish(role.Private, private)
		clear(private)
		if e != nil {
			return Record{}, PublicBootstrap{}, e
		}
		public.Files[role.Certificate] = certificate
		public.Files[role.CA] = bytes.Clone(material.TrustBundle)
	}
	for _, role := range []struct {
		name, path string
		receipt    bool
		pkcs8      bool
	}{
		{"placement", "/etc/terrascale/placement/host.nkey", false, false}, {"database", "/etc/terrascale/database/host.nkey", false, false}, {"lifecycle", "/etc/terrascale/database/lifecycle.nkey", false, false}, {"node", "/etc/terrascale/ts-node-bootstrap/user.seed", false, false}, {"reader", "/etc/terrascale/ts-node-authority/user.seed", false, false}, {"regional", "/etc/terrascale/orchestrator/regional/user.seed", false, false}, {"receipt", "/etc/terrascale/terrabase/transition/receipt-signer.key", true, true}, {"native-recovery-receipt", hostsecrets.NativeRecoveryReceiptKeyPath, true, true},
	} {
		if err := p.Check(ctx); err != nil {
			return Record{}, PublicBootstrap{}, err
		}
		seed, e := p.Vault.Generate(ctx, security.CapabilityRequest{OperationID: r.OperationID, Generation: r.Generation, Bucket: r.IssuedAt.Unix() / int64(security.CapabilityPeriod/time.Second), NotBefore: r.IssuedAt, ExpiresAt: r.ExpiresAt, IdempotencyKey: "enrollment/" + r.OperationID + "/" + role.name})
		if e != nil {
			return Record{}, PublicBootstrap{}, e
		}
		if len(seed.Key) != ed25519.SeedSize || seed.Version != r.Generation || !seed.NotBefore.Equal(r.IssuedAt) || !seed.ExpiresAt.Equal(r.ExpiresAt) {
			clear(seed.Key)
			return Record{}, PublicBootstrap{}, ErrInvalid
		}
		var credential []byte
		if role.receipt {
			credential = ed25519.NewKeyFromSeed(seed.Key)
			public.PublicKeys[role.name] = base64.StdEncoding.EncodeToString(credential[ed25519.SeedSize:])
		} else {
			pair, e := nkeys.FromRawSeed(nkeys.PrefixByteUser, seed.Key)
			if e != nil {
				clear(seed.Key)
				return Record{}, PublicBootstrap{}, e
			}
			credential, e = pair.Seed()
			if e == nil {
				public.PublicKeys[role.name], e = pair.PublicKey()
			}
			pair.Wipe()
			if e != nil {
				clear(seed.Key)
				clear(credential)
				return Record{}, PublicBootstrap{}, e
			}
		}
		clear(seed.Key)
		if role.pkcs8 {
			credential, e = x509.MarshalPKCS8PrivateKey(ed25519.PrivateKey(credential))
			if e != nil {
				clear(credential)
				return Record{}, PublicBootstrap{}, e
			}
		}
		e = publish(role.path, credential)
		clear(credential)
		if e != nil {
			return Record{}, PublicBootstrap{}, e
		}
	}
	for path, content := range template.Files {
		if _, exists := public.Files[path]; exists || hostsecrets.ValidateCredentialDestination(path) == nil {
			return Record{}, PublicBootstrap{}, ErrInvalid
		}
		expanded := render(content, r, public.PublicKeys)
		if strings.Contains(expanded, "${") || strings.Contains(expanded, "PRIVATE KEY") || strings.Contains(expanded, "BEGIN NKEY") {
			return Record{}, PublicBootstrap{}, ErrInvalid
		}
		public.Files[path] = []byte(expanded)
	}
	public.ArchitectureFiles = map[string]map[string][]byte{}
	for _, arch := range []string{"arm64", "amd64"} {
		input, ok := template.Manifests[arch]
		if !ok {
			return Record{}, PublicBootstrap{}, ErrInvalid
		}
		encoded, e := json.Marshal(input)
		if e != nil {
			return Record{}, PublicBootstrap{}, e
		}
		expanded := render(string(encoded), r, public.PublicKeys)
		manifest, e := hostmanifest.ParseHostManifest([]byte(expanded))
		if e != nil {
			return Record{}, PublicBootstrap{}, e
		}
		signed, e := SignPublicBootstrap(p.Signer, r, manifest, r.IssuedAt)
		if e != nil {
			return Record{}, PublicBootstrap{}, e
		}
		files := maps.Clone(public.Files)
		files["/var/lib/terrascale/ts-node/manifest.json"] = signed.Manifest
		files["/etc/terrascale/ts-node-bootstrap/grant.json"] = signed.Grant
		public.ArchitectureFiles[arch] = files
		if arch == "arm64" {
			public.Manifest, public.Grant = signed.Manifest, signed.Grant
		}
	}
	seedJSON, e := json.Marshal(public.Seed)
	if e != nil {
		return Record{}, PublicBootstrap{}, e
	}
	public.Files[hostsecrets.SeedPath] = seedJSON
	for _, files := range public.ArchitectureFiles {
		files[hostsecrets.SeedPath] = bytes.Clone(seedJSON)
	}
	r.IdentityReference = material.Reference
	r.Public = &public
	if e := p.Journal.Publish(ctx, r); e != nil {
		return Record{}, PublicBootstrap{}, e
	}
	return r, public, nil
}
func OCIRegion(region string) string {
	switch region {
	case "gru":
		return "sa-saopaulo-1"
	case "sfo":
		return "us-sanjose-1"
	case "fra":
		return "eu-frankfurt-1"
	default:
		return ""
	}
}

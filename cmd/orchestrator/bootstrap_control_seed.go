package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"github.com/nats-io/nkeys"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/hostmanifest"

	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
	"terrascale.tech/orchestrator/src/orchestrator/nodeauthority"
	"terrascale.tech/orchestrator/src/orchestrator/ocireconcile"
)

type bootstrapHostTrustReference struct {
	CandidateID   string `json:"candidateId"`
	PublicKeyFile string `json:"publicKeyFile"`
}
type bootstrapHostFileReference struct {
	SourceFile    string `json:"sourceFile"`
	Path          string `json:"path"`
	Private       bool   `json:"private"`
	SecretID      string `json:"secretId,omitempty"`
	VersionNumber int64  `json:"versionNumber,omitempty"`
}
type bootstrapControlHostSeed struct {
	AuthorityReader    nodeauthority.ReaderConfig     `json:"authorityReader"`
	HostID             string                         `json:"hostId"`
	PrivateKeySecretID string                         `json:"privateKeySecretId"`
	PrivateKeyVersion  int64                          `json:"privateKeyVersion"`
	NKeySecretID       string                         `json:"nkeySecretId"`
	NKeyVersion        int64                          `json:"nkeyVersion"`
	NATS               bootstrapcredentials.Reference `json:"nats"`
	CommandTrust       []bootstrapHostTrustReference  `json:"commandTrust"`
	Files              []bootstrapHostFileReference   `json:"files"`
}

func prepareBootstrapControlSeeds(lookup envLookup, loaded *loadedBootstrapControl) error {
	if len(loaded.declaration.Seeds) == 0 {
		return errors.New("control: per-slot initial host seeds are required")
	}
	version, err := addRegionRequiredEnv(lookup, ocireconcile.TSNodeVersionEnvironment)
	if err != nil {
		return err
	}
	digest, err := addRegionRequiredEnv(lookup, ocireconcile.TSNodeSHA256Environment)
	if err != nil {
		return err
	}
	artifact, err := addRegionRequiredEnv(lookup, ocireconcile.TSNodeURLEnvironment)
	if err != nil {
		return err
	}
	release, err := addRegionRequiredEnv(lookup, bootstrapReleaseKeyEnvironment)
	if err != nil {
		return err
	}
	public, err := hex.DecodeString(release)
	if err != nil || len(public) != ed25519.PublicKeySize {
		public, err = base64.StdEncoding.Strict().DecodeString(release)
	}
	if err != nil || len(public) != ed25519.PublicKeySize {
		return errors.New("control: canonical Ed25519 release pin required")
	}
	release = hex.EncodeToString(public)
	loaded.seeds = map[string]map[int]string{}
	seen := map[string]bool{}
	for _, seed := range loaded.declaration.Seeds {
		if seen[seed.HostID] {
			return errors.New("control: duplicate host seed")
		}
		seen[seed.HostID] = true
		var member bootstrapControlMember
		for _, candidate := range loaded.declaration.Members {
			if candidate.HostID == seed.HostID {
				member = candidate
			}
		}
		activation, ok := loaded.activations[seed.HostID]
		if member.HostID == "" || !ok {
			return errors.New("control: seed requires declared host and signed owner grant")
		}
		credentialCheck, err := bootstrapcredentials.Load(seed.NATS)
		if err != nil {
			return err
		}
		if err = credentialCheck.Close(); err != nil {
			return err
		}
		if err := validateBootstrapAuthorityReader(seed, activation); err != nil {
			return err
		}
		var files []ocireconcile.BootstrapHostFile
		var secrets []map[string]any
		add := func(source, path string, private bool, secretID string, version int64) error {
			content, err := bootstrapcredentials.ReadFile(source, private, 32<<10)
			if err != nil {
				return err
			}
			if private {
				defer clear(content)
			}
			if err := validateBootstrapSeedContent(content, private, loaded.activations); err != nil {
				return err
			}
			if private {
				if !strings.HasPrefix(secretID, "ocid1.vaultsecret.") || version <= 0 {
					return errors.New("control: private host credential requires exact Vault secret version")
				}
				digest := sha256.Sum256(content)
				secrets = append(secrets, map[string]any{"secretId": secretID, "versionNumber": version, "sha256": hex.EncodeToString(digest[:]), "destination": path})
				for i := range content {
					content[i] = 0
				}
				return nil
			}
			files = append(files, ocireconcile.BootstrapHostFile{Path: path, Content: content, Private: private})
			return nil
		}
		const root = "/etc/terrascale/ts-node-bootstrap/"
		for _, file := range []struct {
			source, path string
			private      bool
			secretID     string
			version      int64
		}{
			{seed.NATS.CAFile, root + "ca.pem", false, "", 0}, {seed.NATS.CertificateFile, root + "client.pem", false, "", 0},
			{seed.NATS.PrivateKeyFile, root + "client.key", true, seed.PrivateKeySecretID, seed.PrivateKeyVersion}, {seed.NATS.NKeySeedFile, root + "user.seed", true, seed.NKeySecretID, seed.NKeyVersion},
		} {
			if err := add(file.source, file.path, file.private, file.secretID, file.version); err != nil {
				return err
			}
		}

		manifest, err := hostmanifest.CanonicalHostManifestJSON(activation.grant.Manifest)
		if err != nil {
			return err
		}
		files = append(files, ocireconcile.BootstrapHostFile{Path: "/var/lib/terrascale/ts-node/manifest.json", Content: manifest, Private: true}, ocireconcile.BootstrapHostFile{Path: root + "grant.json", Content: activation.signed, Private: true})
		for _, input := range loaded.declaration.Activations {
			if input.HostID == seed.HostID {
				if err := add(input.OwnerPublicKeyFile, root+"authority.pem", false, "", 0); err != nil {
					return err
				}
			}
		}
		var trust []map[string]string
		seenCandidates := map[string]bool{}
		for index, key := range seed.CommandTrust {
			if key.CandidateID == "" || strings.ContainsAny(key.CandidateID, " \r\n\x00") || seenCandidates[key.CandidateID] {
				return errors.New("control: invalid host command trust")
			}
			content, err := bootstrapcredentials.ReadFile(key.PublicKeyFile, false, 32<<10)
			if err != nil {
				return err
			}
			if err := validateBootstrapSeedContent(content, false, loaded.activations); err != nil {
				return err
			}
			block, rest := pem.Decode(content)
			if block == nil || block.Type != "PUBLIC KEY" || len(bytes.TrimSpace(rest)) != 0 {
				return errors.New("control: runtime command trust requires one public P-256 key")
			}
			parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
			public, ok := parsed.(*ecdsa.PublicKey)
			if err != nil || !ok || public.Curve != elliptic.P256() {
				return errors.New("control: runtime command trust requires public P-256 key")
			}
			digest := sha256.Sum256(block.Bytes)
			keyID := hex.EncodeToString(digest[:])
			for _, activation := range loaded.activations {
				if keyID == activation.ownerKeyID {
					return errors.New("control: bootstrap owner cannot be runtime command authority")
				}
			}
			admitted := false
			for _, region := range loaded.declaration.Regions {
				signer := loaded.signers[region.Code]
				if region.Code == member.Region && key.CandidateID == region.CommandCandidateID && signer != nil && signer.PublicKeyID() == keyID {
					admitted = true
				}
			}
			if !admitted {
				return errors.New("control: runtime command trust differs from admitted regional signer")
			}
			seenCandidates[key.CandidateID] = true
			path := fmt.Sprintf("%strust-%d.pem", root, index)
			files = append(files, ocireconcile.BootstrapHostFile{Path: path, Content: content})
			trust = append(trust, map[string]string{"candidateId": key.CandidateID, "publicKeyFile": path})
		}
		if len(trust) == 0 {
			return errors.New("control: runtime command trust is required before initial host launch")
		}
		for _, file := range seed.Files {
			for _, input := range loaded.declaration.Activations {
				if file.SourceFile == input.OwnerSigningKeyFile && input.OwnerSigningKeyFile != "" {
					return errors.New("control: owner bootstrap private signer cannot be seeded")
				}
			}
			if err := add(file.SourceFile, file.Path, file.Private, file.SecretID, file.VersionNumber); err != nil {
				return err
			}
		}
		config := map[string]any{"authorityReader": seed.AuthorityReader, "nodeId": seed.HostID, "natsUrl": seed.NATS.URL, "natsNkeyFile": root + "user.seed", "natsTlsCaFile": root + "ca.pem", "natsTlsCertFile": root + "client.pem", "natsTlsKeyFile": root + "client.key", "authorityBucket": "ORCH_LEADERS", "commandTrustKeys": trust, "bootstrapBeforeNats": true, "bootstrapGrantFile": root + "grant.json", "bootstrapPublicKeyFile": root + "authority.pem", "releasePublicKey": release, "manifestPath": "/var/lib/terrascale/ts-node/manifest.json", "installRoot": "/opt/terrascale", "unitDir": "/etc/systemd/system", "dataVolumeRoot": "/var/lib/terrascale", "chronycBinary": "/usr/bin/chronyc", "systemctlBinary": "/usr/bin/systemctl", "useraddBinary": "/usr/sbin/useradd", "heartbeatIntervalMilliseconds": 1000, "reconcileIntervalMilliseconds": 1000}
		wire, err := json.Marshal(config)
		if err != nil {
			return err
		}
		files = append(files, ocireconcile.BootstrapHostFile{Path: "/etc/terrascale/ts-node.json", Content: wire, Private: true})
		var ociRegion string
		for _, region := range loaded.declaration.Regions {
			if region.Code == member.Region {
				ociRegion = region.OCIRegion
			}
		}
		secretWire, err := json.Marshal(map[string]any{"region": ociRegion, "operationId": fmt.Sprintf("control-%d-%s", loaded.declaration.Generation, seed.HostID), "entries": secrets})
		if err != nil {
			return err
		}
		var secretDeclaration hostsecrets.Seed
		if json.Unmarshal(secretWire, &secretDeclaration) != nil {
			return errors.New("control: invalid host secret declaration")
		}
		if err := hostsecrets.ValidateSeed(secretDeclaration); err != nil {
			return err
		}
		files = append(files, ocireconcile.BootstrapHostFile{Path: "/etc/terrascale/host-secrets.json", Content: secretWire, Private: true})
		cloudInit, err := ocireconcile.TSNodeCloudInit(version, digest, artifact, artifact+".sig", release, files)
		if err != nil {
			return err
		}
		if loaded.seeds[member.Region] == nil {
			loaded.seeds[member.Region] = map[int]string{}
		}
		loaded.seeds[member.Region][member.Index] = cloudInit
	}
	for _, region := range loaded.declaration.Regions {
		if len(loaded.seeds[region.Code]) != region.MemberCount {
			return errors.New("control: every OCI member slot requires an admitted seed")
		}
	}
	return nil
}

// Examine every block: certificate parsers may ignore trailing private keys.
func validateBootstrapSeedContent(content []byte, private bool, activations map[string]loadedControlActivation) error {
	remaining := bytes.TrimSpace(content)
	for len(remaining) != 0 && bytes.Contains(remaining, []byte("-----BEGIN")) {
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN")) {
			return errors.New("control: unexpected text before PEM block")
		}
		block, rest := pem.Decode(remaining)
		if block == nil {
			return errors.New("control: malformed seed PEM")
		}
		if strings.Contains(block.Type, "PRIVATE KEY") {
			if !private {
				return errors.New("control: private key cannot enter public seed")
			}
			key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
			if err != nil {
				key, err = x509.ParseECPrivateKey(block.Bytes)
			}
			if err != nil {
				key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
			}
			if err != nil {
				return errors.New("control: unrecognized private seed key")
			}
			if signer, ok := key.(*ecdsa.PrivateKey); ok {
				der, err := x509.MarshalPKIXPublicKey(&signer.PublicKey)
				if err != nil {
					return err
				}
				digest := sha256.Sum256(der)
				for _, activation := range activations {
					if activation.ownerKeyID == hex.EncodeToString(digest[:]) {
						return errors.New("control: owner grant signer cannot be provisioned to a host")
					}
				}
			}
		} else if !private {
			switch block.Type {
			case "CERTIFICATE":
				if _, err := x509.ParseCertificate(block.Bytes); err != nil {
					return errors.New("control: malformed public certificate")
				}
			case "PUBLIC KEY":
				if _, err := x509.ParsePKIXPublicKey(block.Bytes); err != nil {
					return errors.New("control: malformed public key")
				}
			default:
				return errors.New("control: unsupported public PEM block")
			}
		}
		remaining = bytes.TrimSpace(rest)
		if len(remaining) != 0 && !bytes.HasPrefix(remaining, []byte("-----BEGIN")) {
			return errors.New("control: unexpected trailing PEM content")
		}
	}
	if !private {
		if bytes.Contains(content, []byte("PRIVATE KEY")) || bytes.Contains(content, []byte("NKEY SEED")) {
			return errors.New("control: credentials cannot enter public seed")
		}
		for _, token := range bytes.FieldsFunc(content, func(r rune) bool { return !(r >= 'A' && r <= 'Z' || r >= '2' && r <= '7') }) {
			if pair, err := nkeys.FromSeed(token); err == nil {
				pair.Wipe()
				return errors.New("control: NKey seed cannot enter public user-data")
			}
		}
	}
	return nil
}

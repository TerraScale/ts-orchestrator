package vmimage

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"regexp"
)

// TSNodeCommandTrust pins a command signing key to its regional candidate.
// It enrolls trust only; the receiver separately requires a live regional lease.
type TSNodeCommandTrust struct {
	CandidateID  string
	PublicKeyPEM []byte
}

type tsNodeCommandTrustFile struct {
	CandidateID   string `json:"candidateId"`
	PublicKeyFile string `json:"publicKeyFile"`
}

var commandCandidatePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,255}$`)

var commandBucketPattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,128}$`)

func commandTrustPath(index int) string {
	return fmt.Sprintf("/etc/terrascale/ts-node-command/key-%d.pem", index)
}

func canonicalCommandTrust(config TSNodeConfig) ([]tsNodeCommandTrustFile, []NoCloudRootFile, error) {
	if !commandBucketPattern.MatchString(config.AuthorityBucket) || len(config.CommandTrustKeys) < 1 || len(config.CommandTrustKeys) > 4 {
		return nil, nil, errors.New("vmimage: command authority bucket and bounded trust are required")
	}
	refs := make([]tsNodeCommandTrustFile, 0, len(config.CommandTrustKeys))
	files := make([]NoCloudRootFile, 0, len(config.CommandTrustKeys))
	candidates, keys := map[string]bool{}, map[string]bool{}
	for index, trust := range config.CommandTrustKeys {
		if !commandCandidatePattern.MatchString(trust.CandidateID) || candidates[trust.CandidateID] || len(trust.PublicKeyPEM) > 1024 {
			return nil, nil, errors.New("vmimage: invalid or repeated command candidate")
		}
		block, rest := pem.Decode(trust.PublicKeyPEM)
		if block == nil || block.Type != "PUBLIC KEY" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, nil, errors.New("vmimage: command trust requires one public SPKI PEM")
		}
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		public, ok := parsed.(*ecdsa.PublicKey)
		if err != nil || !ok || public.Curve != elliptic.P256() || !public.Curve.IsOnCurve(public.X, public.Y) || keys[string(block.Bytes)] {
			return nil, nil, errors.New("vmimage: command trust requires distinct P256 public keys")
		}
		candidates[trust.CandidateID], keys[string(block.Bytes)] = true, true
		refs = append(refs, tsNodeCommandTrustFile{trust.CandidateID, commandTrustPath(index)})
		files = append(files, NoCloudRootFile{Path: commandTrustPath(index), Mode: 0444, Content: pem.EncodeToMemory(block)})
	}
	return refs, files, nil
}

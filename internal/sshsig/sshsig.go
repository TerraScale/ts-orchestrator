package sshsig

import (
	"bytes"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"errors"
	"fmt"
	"hash"
	"strings"

	"golang.org/x/crypto/ssh"
)

const armorStart = "-----BEGIN SSH SIGNATURE-----"
const armorEnd = "-----END SSH SIGNATURE-----"

type sigBlob struct {
	PublicKey     []byte
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Signature     []byte
}

type wireSignature struct {
	Format string
	Blob   []byte
	Rest   []byte `ssh:"rest"`
}

type signedMessage struct {
	Namespace     string
	Reserved      string
	HashAlgorithm string
	Hash          []byte
}

func newHash(algorithm string) (hash.Hash, error) {
	switch algorithm {
	case "sha512":
		return sha512.New(), nil
	case "sha256":
		return sha256.New(), nil
	}
	return nil, fmt.Errorf("sshsig: unsupported hash algorithm %q", algorithm)
}

func decode(armored []byte) ([]byte, error) {
	text := strings.TrimSpace(string(armored))
	if !strings.HasPrefix(text, armorStart) || !strings.HasSuffix(text, armorEnd) {
		return nil, errors.New("sshsig: signature is not armored")
	}
	body := text[len(armorStart) : len(text)-len(armorEnd)]
	return base64.StdEncoding.DecodeString(strings.Join(strings.Fields(body), ""))
}

func Verify(message, armored []byte, namespace string, allowed []ssh.PublicKey) (ssh.PublicKey, error) {
	blob, err := decode(armored)
	if err != nil {
		return nil, err
	}
	if len(blob) < 10 || !bytes.HasPrefix(blob, []byte("SSHSIG")) {
		return nil, errors.New("sshsig: blob is not an SSHSIG")
	}
	if version := uint32(blob[6])<<24 | uint32(blob[7])<<16 | uint32(blob[8])<<8 | uint32(blob[9]); version != 1 {
		return nil, fmt.Errorf("sshsig: unsupported version %d", version)
	}
	var parsed sigBlob
	if err := ssh.Unmarshal(blob[10:], &parsed); err != nil {
		return nil, fmt.Errorf("sshsig: malformed blob: %w", err)
	}
	if parsed.Namespace != namespace {
		return nil, fmt.Errorf("sshsig: namespace %q is not %q", parsed.Namespace, namespace)
	}
	h, err := newHash(parsed.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	pub, err := ssh.ParsePublicKey(parsed.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("sshsig: malformed signer key: %w", err)
	}
	var signer ssh.PublicKey
	for _, k := range allowed {
		if bytes.Equal(pub.Marshal(), k.Marshal()) {
			signer = k
			break
		}
	}
	if signer == nil {
		return nil, errors.New("sshsig: signer is not an allowed key")
	}
	var wire wireSignature
	if err := ssh.Unmarshal(parsed.Signature, &wire); err != nil {
		return nil, fmt.Errorf("sshsig: malformed signature: %w", err)
	}
	sig := &ssh.Signature{Format: wire.Format, Blob: wire.Blob, Rest: wire.Rest}
	h.Write(message)
	signed := append([]byte("SSHSIG"), ssh.Marshal(signedMessage{Namespace: namespace, Reserved: "", HashAlgorithm: parsed.HashAlgorithm, Hash: h.Sum(nil)})...)
	if err := pub.Verify(signed, sig); err != nil {
		return nil, fmt.Errorf("sshsig: signature check failed: %w", err)
	}
	return pub, nil
}

func ParseAllowed(lines []string) ([]ssh.PublicKey, error) {
	keys := make([]ssh.PublicKey, 0, len(lines))
	for i, line := range lines {
		key, _, _, rest, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("sshsig: allowed key line %d: %w", i+1, err)
		}
		if len(bytes.TrimSpace(rest)) != 0 {
			return nil, fmt.Errorf("sshsig: allowed key line %d contains multiple keys", i+1)
		}
		keys = append(keys, key)
	}
	return keys, nil
}

package globalclient

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"

	"github.com/nats-io/nkeys"
)

type identitySnapshot struct {
	pair nkeys.KeyPair
	tls  *tls.Config
}

func (p *Plan) identity(ctx context.Context) (identitySnapshot, error) {
	seed, err := readIdentityFile(ctx, p.seed, 4096, true)
	if err != nil {
		return identitySnapshot{}, err
	}
	defer clear(seed)
	var line []byte
	for _, candidate := range bytes.Split(seed, []byte{'\n'}) {
		if candidate = bytes.TrimSpace(candidate); len(candidate) > 0 {
			line = candidate
			break
		}
	}
	pair, err := nkeys.FromSeed(line)
	if err != nil {
		return identitySnapshot{}, errIdentityFiles
	}
	success := false
	defer func() {
		if !success {
			pair.Wipe()
		}
	}()
	public, err := pair.PublicKey()
	if err != nil || public != p.public {
		return identitySnapshot{}, errors.New("global worker identity changed after static admission")
	}
	ca, err := readIdentityFile(ctx, p.ca, 65536, false)
	if err != nil {
		return identitySnapshot{}, err
	}
	certificate, err := readIdentityFile(ctx, p.certificate, 65536, false)
	if err != nil {
		return identitySnapshot{}, err
	}
	key, err := readIdentityFile(ctx, p.key, 65536, true)
	if err != nil {
		return identitySnapshot{}, err
	}
	defer clear(key)
	client, err := tls.X509KeyPair(certificate, key)
	if err != nil {
		return identitySnapshot{}, errIdentityFiles
	}
	block, _ := pem.Decode(ca)
	if block == nil {
		return identitySnapshot{}, errIdentityFiles
	}
	authority, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !authority.IsCA {
		return identitySnapshot{}, errIdentityFiles
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(ca) {
		return identitySnapshot{}, errIdentityFiles
	}
	success = true
	return identitySnapshot{pair: pair, tls: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{client}}}, nil
}

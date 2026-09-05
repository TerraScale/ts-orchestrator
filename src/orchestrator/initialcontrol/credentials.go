package initialcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"net"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
	"terrascale.tech/orchestrator/src/orchestrator/initialgrant"
	"terrascale.tech/orchestrator/src/orchestrator/natsconnect"
)

func readCredential(path, digest string, private bool) ([]byte, error) {
	invalid := errors.New("initial control: credential does not match its admitted reference")
	data, err := initialgrant.ReadMaterialFile(path, 64<<10, private)
	if err != nil {
		return nil, invalid
	}
	if digest != "" {
		sum := sha256.Sum256(data)
		if hex.EncodeToString(sum[:]) != digest {
			clear(data)
			return nil, invalid
		}
	}
	return data, nil
}

func loadTLS(ref initialgrant.TLSFiles) (*tls.Config, error) {
	ca, err := readCredential(ref.CAFile, ref.CASHA256, false)
	if err != nil {
		return nil, err
	}
	cert, err := readCredential(ref.CertificateFile, ref.CertificateSHA256, false)
	if err != nil {
		return nil, err
	}
	key, err := readCredential(ref.KeyFile, "", true)
	if err != nil {
		return nil, err
	}
	defer clear(key)
	pair, err := tls.X509KeyPair(cert, key)
	if err != nil {
		return nil, errors.New("initial control: TLS private identity does not match admitted certificate")
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(ca) {
		return nil, errors.New("initial control: invalid admitted TLS roots")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{pair}, RootCAs: pool, ClientCAs: pool}, nil
}

func connect(ctx context.Context, broker initialgrant.Broker, identity initialgrant.Connection) (*nats.Conn, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	material, err := readCredential(identity.NKeySeedFile, "", true)
	if err != nil {
		return nil, err
	}
	defer clear(material)
	pair, err := nkeys.FromSeed(bytes.TrimSpace(material))
	if err != nil {
		return nil, errors.New("initial control: invalid NKey identity")
	}
	defer pair.Wipe()
	public, err := pair.PublicKey()
	if err != nil || public != identity.PublicNKey {
		return nil, errors.New("initial control: NKey identity differs from admitted public key")
	}
	tlsConfig, err := loadTLS(identity.TLS)
	if err != nil {
		return nil, err
	}
	// No reconnect retains the provisioner's signer or reopens its connection.
	nc, err := natsconnect.Connect(ctx, natsconnect.Config{URL: broker.Endpoint, TLS: tlsConfig, PublicNKey: public, Sign: pair.Sign, Timeout: 5 * time.Second}, net.Dialer{Timeout: 5 * time.Second})
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, errors.New("initial control: authenticated NATS connection failed")
	}
	if err = ctx.Err(); err != nil {
		nc.Close()
		return nil, err
	}
	if nc.ConnectedServerName() != broker.ServerName {
		nc.Close()
		return nil, errors.New("initial control: connected broker identity differs from signed scope")
	}
	return nc, nil
}

package releaseclient

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"io"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

const Port = 4222

type Auth struct {
	verifier *Verifier
	local    string
}

func NewAuth(verifier *Verifier) (*Auth, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, err
	}
	return &Auth{verifier: verifier, local: hex.EncodeToString(secret)}, nil
}

func (a *Auth) Check(c server.ClientAuthentication) bool {
	if c.Kind() != server.CLIENT {
		return false
	}
	opts := c.GetOpts()
	token := opts.Token
	if token == "" {
		token = opts.Password
	}
	if addr := c.RemoteAddress(); addr != nil && addr.Network() == "pipe" &&
		subtle.ConstantTimeCompare([]byte(token), []byte(a.local)) == 1 {
		c.RegisterUser(&server.User{Username: "ts-orch"})
		return true
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	claims, err := a.verifier.Verify(ctx, token)
	publish := protocol.ReleaseWildcard
	if err != nil {
		if claims, err = a.verifier.VerifyMesh(ctx, token); err != nil {
			return false
		}
		publish = protocol.ReleaseMeshWildcard
	}
	c.RegisterUser(&server.User{
		Username: "ci:" + claims.Repository + ":" + claims.RunID,
		Permissions: &server.Permissions{
			Publish:   &server.SubjectPermission{Allow: []string{publish}},
			Subscribe: &server.SubjectPermission{Allow: []string{Inbox(claims.RunID) + ".>"}},
		},
		ConnectionDeadline: time.Unix(claims.Expires, 0).Add(clockSkew),
	})
	return true
}

func Options(state string, auth *Auth) (*server.Options, error) {
	certificate, err := listenerCertificate(filepath.Join(state, "nats"))
	if err != nil {
		return nil, err
	}
	return &server.Options{
		ServerName:                 "ts-orch-release",
		Host:                       "127.0.0.1",
		Port:                       Port,
		TLS:                        true,
		TLSConfig:                  &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS12},
		TLSTimeout:                 5,
		MaxPayload:                 64 << 10,
		MaxConn:                    256,
		MaxSubs:                    64,
		AuthTimeout:                5,
		MaxControlLine:             32 << 10,
		NoLog:                      true,
		NoSigs:                     true,
		CustomClientAuthentication: auth,
	}, nil
}

func Start(state string) (*server.Server, *nats.Conn, error) {
	auth, err := NewAuth(NewVerifier())
	if err != nil {
		return nil, nil, err
	}
	options, err := Options(state, auth)
	if err != nil {
		return nil, nil, err
	}
	srv, err := server.NewServer(options)
	if err != nil {
		return nil, nil, err
	}
	srv.Start()
	if !srv.ReadyForConnections(10 * time.Second) {
		srv.Shutdown()
		return nil, nil, errors.New("release NATS server did not start")
	}
	conn, err := auth.Connect(srv)
	if err != nil {
		srv.Shutdown()
		return nil, nil, err
	}
	return srv, conn, nil
}

func Inbox(runID string) string { return "_INBOX." + runID }

func (a *Auth) Connect(srv *server.Server) (*nats.Conn, error) {
	return nats.Connect("", nats.InProcessServer(srv), nats.Token(a.local), nats.Name("ts-orch"))
}

func listenerCertificate(dir string) (tls.Certificate, error) {
	certFile, keyFile := filepath.Join(dir, "tls.crt"), filepath.Join(dir, "tls.key")
	_, certErr := os.Stat(certFile)
	_, keyErr := os.Stat(keyFile)
	if !errors.Is(certErr, os.ErrNotExist) || !errors.Is(keyErr, os.ErrNotExist) {
		return tls.LoadX509KeyPair(certFile, keyFile)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return tls.Certificate{}, err
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "ts-orch-release"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(100, 0, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	if err := writeNew(keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return tls.Certificate{}, err
	}
	if err := writeNew(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return tls.Certificate{}, err
	}
	return tls.LoadX509KeyPair(certFile, keyFile)
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if err != nil {
		return err
	}
	_, err = file.Write(data)
	return errors.Join(err, file.Sync(), file.Close())
}

func SPKIPin(der []byte) (string, error) {
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(certificate.RawSubjectPublicKeyInfo)
	return hex.EncodeToString(sum[:]), nil
}

func Pin(args []string, output io.Writer) error {
	flags := flag.NewFlagSet("release pin", flag.ContinueOnError)
	flags.SetOutput(output)
	state := flags.String("state", "/var/lib/ts-orch", "node state directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || !filepath.IsAbs(*state) {
		return errors.New("usage: ts-orch release pin --state <absolute state directory>")
	}
	certificate, err := listenerCertificate(filepath.Join(*state, "nats"))
	if err != nil {
		return err
	}
	pin, err := SPKIPin(certificate.Certificate[0])
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(output, "%s\n", pin)
	return err
}

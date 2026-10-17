package natscell

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"sync"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// ConnectMemory authenticates without opening credential files. The caller
// retains authority over the connection through ctx, including reconnects.
func ConnectMemory(ctx context.Context, cell, endpoint string, credentials []byte, config *tls.Config) (*nats.Conn, error) {
	if ctx == nil || ctx.Err() != nil || !cellName.MatchString(cell) || endpoint == "" || len(credentials) == 0 || len(credentials) > 64<<10 ||
		config == nil || config.InsecureSkipVerify || config.RootCAs == nil || len(config.Certificates) != 1 || len(config.Certificates[0].Certificate) == 0 {
		return nil, errors.New("in-memory NATS credentials are unavailable")
	}
	claim, public, err := credentialUserBytes(credentials)
	if err != nil {
		return nil, err
	}
	raw, err := nkeys.ParseDecoratedJWT(credentials)
	if err != nil {
		return nil, err
	}
	leaf, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err != nil || verifyTLSLeaf(leaf, config.Certificates[0].Certificate[1:], config.RootCAs, "client") != nil {
		return nil, errors.New("in-memory NATS client certificate is invalid")
	}
	deadline := leaf.NotAfter
	if claim.Expires > 0 && time.Unix(claim.Expires, 0).Before(deadline) {
		deadline = time.Unix(claim.Expires, 0)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	pair, err := nkeys.ParseDecoratedUserNKey(credentials)
	if err != nil {
		cancel()
		return nil, err
	}
	var mu sync.Mutex
	cleanup := sync.OnceFunc(func() {
		cancel()
		mu.Lock()
		defer mu.Unlock()
		pair.Wipe()
	})
	valid := func() error {
		result := jwt.CreateValidationResults()
		claim.Validate(result)
		if ctx.Err() != nil || !time.Now().Before(deadline) || result.IsBlocking(true) {
			return errors.New("in-memory NATS authority expired")
		}
		return nil
	}
	if err := valid(); err != nil {
		cleanup()
		return nil, err
	}
	timeout := 12 * time.Second
	if original, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(original))
	}
	conn, err := nats.Connect(bridgeClientURLs(endpoint), nats.Name("terrascale-"+cell+"-root-reader"),
		nats.Timeout(timeout), nats.ErrorHandler(ErrorHandler), nats.CustomInboxPrefix(inboxPrefix(cell, public)),
		nats.SetCustomDialer(&tlsFirstDialer{config: config.Clone(), timeout: timeout}),
		nats.UserJWT(func() (string, error) {
			if err := valid(); err != nil {
				return "", err
			}
			return raw, nil
		}, func(nonce []byte) ([]byte, error) {
			mu.Lock()
			defer mu.Unlock()
			if err := valid(); err != nil {
				return nil, err
			}
			return pair.Sign(nonce)
		}), nats.ClosedHandler(func(*nats.Conn) { cleanup() }))
	if err != nil {
		cleanup()
		return nil, err
	}
	stop := context.AfterFunc(ctx, conn.Close)
	if conn.IsClosed() || valid() != nil {
		stop()
		conn.Close()
		cleanup()
		return nil, errors.New("in-memory NATS authority expired during connection")
	}
	return conn, nil
}

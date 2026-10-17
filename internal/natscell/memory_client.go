package natscell

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nkeys"
)

// ErrMemorySessionLost ends an original session or authentication attempt.
// A signed nonce may have reached the broker even when Connect returns an error.
var ErrMemorySessionLost = errors.New("original authenticated in-memory NATS session was lost")

// ConnectMemory authenticates without opening credential files. The caller
// retains authority over the connection through ctx, including reconnects.
func ConnectMemory(ctx context.Context, cell, endpoint string, credentials []byte, config *tls.Config) (*nats.Conn, error) {
	conn, _, err := ConnectMemoryLease(ctx, cell, endpoint, credentials, config)
	return conn, err
}

// ConnectMemoryLease also returns the original authenticated connection lifetime.
// Its deadline includes the verified certificate chain and JWT expiry.
func ConnectMemoryLease(ctx context.Context, cell, endpoint string, credentials []byte, config *tls.Config) (*nats.Conn, context.Context, error) {
	if ctx == nil || ctx.Err() != nil || len(credentials) == 0 || len(credentials) > 64<<10 {
		return nil, nil, errors.New("in-memory NATS credentials are unavailable")
	}
	claim, public, err := credentialUserBytes(credentials)
	if err != nil {
		return nil, nil, err
	}
	return connectMemoryLease(ctx, ctx, cell, endpoint, credentials, config, claim, public, false)
}

// ConnectMemorySingleLease opens the fixed dedicated-manager read role. Its
// first disconnect ends the original session permanently.
func ConnectMemorySingleLease(ctx context.Context, cell, endpoint string, credentials []byte, config *tls.Config) (*nats.Conn, context.Context, error) {
	return ConnectMemorySingleLeaseForOperation(ctx, ctx, cell, endpoint, credentials, config)
}

// ConnectMemorySingleLeaseForOperation bounds the initial connection separately
// from the original lifecycle retained by the authenticated session.
func ConnectMemorySingleLeaseForOperation(ctx, originalCtx context.Context, cell, endpoint string, credentials []byte, config *tls.Config) (*nats.Conn, context.Context, error) {
	if ctx == nil || originalCtx == nil || ctx.Err() != nil || originalCtx.Err() != nil || strings.Contains(endpoint, ",") || len(credentials) == 0 || len(credentials) > 64<<10 {
		return nil, nil, errors.New("in-memory NATS credentials are unavailable")
	}
	if err := ValidateNetBirdReaderCredentialBytes(credentials, cell); err != nil {
		return nil, nil, err
	}
	raw, err := jwt.ParseDecoratedJWT(credentials)
	if err != nil {
		return nil, nil, err
	}
	claim, err := jwt.DecodeUserClaims(raw)
	if err != nil {
		return nil, nil, err
	}
	conn, lease, err := connectMemoryLease(originalCtx, ctx, cell, endpoint, credentials, config, claim, claim.Subject, true, nats.NoReconnect(), nats.IgnoreDiscoveredServers())
	if err != nil {
		return nil, nil, err
	}
	state, err := conn.TLSConnectionState()
	if err != nil || len(state.VerifiedChains) == 0 {
		conn.Close()
		return nil, nil, ErrMemorySessionLost
	}
	deadline, _ := lease.Deadline()
	for _, chain := range state.VerifiedChains {
		for _, cert := range chain {
			if cert.NotAfter.Before(deadline) {
				deadline = cert.NotAfter
			}
		}
	}
	single, cancel := context.WithDeadline(lease, deadline)
	context.AfterFunc(single, func() { conn.Close(); cancel() })
	if single.Err() != nil || !conn.IsConnected() {
		cancel()
		conn.Close()
		return nil, nil, ErrMemorySessionLost
	}
	return conn, single, nil
}

func connectMemoryLease(ctx, operationCtx context.Context, cell, endpoint string, credentials []byte, config *tls.Config, claim *jwt.UserClaims, public string, terminalAuth bool, options ...nats.Option) (*nats.Conn, context.Context, error) {
	if ctx == nil || operationCtx == nil || ctx.Err() != nil || operationCtx.Err() != nil || !cellName.MatchString(cell) || endpoint == "" || len(credentials) == 0 || len(credentials) > 64<<10 ||
		config == nil || config.InsecureSkipVerify || config.RootCAs == nil || len(config.Certificates) != 1 || len(config.Certificates[0].Certificate) == 0 {
		return nil, nil, errors.New("in-memory NATS credentials are unavailable")
	}
	raw, err := nkeys.ParseDecoratedJWT(credentials)
	if err != nil {
		return nil, nil, err
	}
	leaf, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
	if err != nil || verifyTLSLeaf(leaf, config.Certificates[0].Certificate[1:], config.RootCAs, "client") != nil {
		return nil, nil, errors.New("in-memory NATS client certificate is invalid")
	}
	deadline := leaf.NotAfter
	intermediates := x509.NewCertPool()
	for _, der := range config.Certificates[0].Certificate[1:] {
		certificate, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, nil, err
		}
		intermediates.AddCert(certificate)
	}
	chains, err := leaf.Verify(x509.VerifyOptions{Roots: config.RootCAs, Intermediates: intermediates, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}})
	if err != nil {
		return nil, nil, err
	}
	for _, certificate := range chains[0] {
		if certificate.NotAfter.Before(deadline) {
			deadline = certificate.NotAfter
		}
	}
	if claim.Expires > 0 && time.Unix(claim.Expires, 0).Before(deadline) {
		deadline = time.Unix(claim.Expires, 0)
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	operationDone := make(chan struct{})
	stopOperation := context.AfterFunc(operationCtx, func() {
		cancel()
		close(operationDone)
	})
	detachOperation := sync.OnceFunc(func() {
		if !stopOperation() {
			<-operationDone
		}
	})
	defer detachOperation()
	pair, err := nkeys.ParseDecoratedUserNKey(credentials)
	if err != nil {
		cancel()
		return nil, nil, err
	}
	var mu sync.Mutex
	var authAttempt atomic.Bool
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
		return nil, nil, err
	}
	timeout := 12 * time.Second
	if original, ok := ctx.Deadline(); ok {
		timeout = min(timeout, time.Until(original))
	}
	if until, ok := operationCtx.Deadline(); ok {
		timeout = min(timeout, time.Until(until))
	}
	options = append(options, nats.Name("terrascale-"+cell+"-root-reader"),
		nats.Timeout(timeout), nats.ErrorHandler(ErrorHandler), nats.CustomInboxPrefix(inboxPrefix(cell, public)),
		nats.SetCustomDialer(&tlsFirstDialer{config: config.Clone(), timeout: timeout, ctx: ctx}),
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
			authAttempt.Store(true)
			return pair.Sign(nonce)
		}), nats.DisconnectErrHandler(func(conn *nats.Conn, _ error) {
			if !conn.Opts.AllowReconnect {
				cleanup()
			}
		}), nats.ClosedHandler(func(*nats.Conn) { cleanup() }))
	conn, err := nats.Connect(bridgeClientURLs(endpoint), options...)
	if err != nil {
		cleanup()
		if terminalAuth && authAttempt.Load() {
			return nil, nil, errors.Join(ErrMemorySessionLost, err)
		}
		return nil, nil, err
	}
	detachOperation()
	stop := context.AfterFunc(ctx, conn.Close)
	if conn.IsClosed() || valid() != nil || operationCtx.Err() != nil {
		stop()
		conn.Close()
		cleanup()
		return nil, nil, ErrMemorySessionLost
	}
	return conn, ctx, nil
}

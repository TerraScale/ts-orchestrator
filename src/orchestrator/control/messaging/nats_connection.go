package messaging

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
)

// NatsConnectionConfiguration is the shared authenticated connection
// composition used by production control roles. Authentication and TLS are
// references to already-resolved files; this type never retains credential
// bytes.
type NatsConnectionConfiguration struct {
	URL            string
	Authentication *NatsAuthenticationFiles
	TLS            *NatsTlsFiles
	Timeout        time.Duration
	MaxReconnects  int
}

// NatsConnect opens one explicitly authenticated NATS connection. Keeping the
// option composition here prevents a role from accidentally falling back to
// an unauthenticated or plaintext connection. Initial connection establishment
// is cancellation-aware and bounded; reconnect policy applies only after the
// authenticated connection has been established.
func NatsConnect(ctx context.Context, configuration NatsConnectionConfiguration) (*nats.Conn, error) {
	if ctx == nil {
		return nil, errors.New("NATS connection context is required")
	}
	if strings.TrimSpace(configuration.URL) == "" || configuration.Authentication == nil || configuration.TLS == nil {
		return nil, errors.New("NATS connection requires URL, authentication, and mTLS credentials")
	}
	parsed, err := url.Parse(configuration.URL)
	if err != nil || !parsed.IsAbs() || parsed.Host == "" || parsed.Scheme != "tls" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return nil, errors.New("NATS connection URL is invalid")
	}
	if configuration.Timeout <= 0 {
		configuration.Timeout = 15 * time.Second
	}
	options := []nats.Option{
		nats.Timeout(configuration.Timeout),
		nats.MaxReconnects(configuration.MaxReconnects),
		nats.RetryOnFailedConnect(false),
		nats.ReconnectWait(2 * time.Second),
		func(options *nats.Options) error {
			options.NoRandomize = true
			return nil
		},
	}
	options = append(options, configuration.Authentication.Options()...)
	options = append(options, configuration.TLS.Options()...)
	result := make(chan struct {
		client *nats.Conn
		err    error
	}, 1)
	go func() {
		client, connectErr := nats.Connect(configuration.URL, options...)
		result <- struct {
			client *nats.Conn
			err    error
		}{client, connectErr}
	}()
	select {
	case response := <-result:
		return response.client, response.err
	case <-ctx.Done():
		go func() {
			response := <-result
			if response.client != nil {
				response.client.Close()
			}
		}()
		return nil, ctx.Err()
	}
}

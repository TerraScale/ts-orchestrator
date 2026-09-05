// Package globalclient admits and opens the dedicated GRU worker connection.
package globalclient

import (
	"context"
	"errors"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/control/directory"
	"terrascale.tech/orchestrator/src/orchestrator/natsconnect"
)

// Plan owns resolved immutable file references, never credential bytes.
type Plan struct{ url, seed, public, ca, certificate, key string }

// Admit validates operational session inputs without opening a listener or client.
func Admit(config *directory.GlobalAuthorityNatsConfiguration) (*Plan, error) {
	if config == nil || config.Cell != "gru" || config.Replicas != 3 || config.Authentication == nil || config.Tls == nil {
		return nil, errors.New("global worker connection requires complete GRU R3 identity configuration")
	}
	auth := config.Authentication
	if auth.CredentialsFile != nil {
		return nil, errors.New("global operational sessions require an NKey seed file; JWT credential-file mode is unsupported by their journals")
	}
	if auth.NKeyFile == nil {
		return nil, errors.New("global operational sessions require an NKey seed file")
	}
	endpoint, err := url.Parse(config.Url)
	if err != nil || endpoint.Scheme != "tls" || endpoint.Hostname() == "" || endpoint.User != nil || endpoint.Path != "" || endpoint.Opaque != "" || endpoint.RawQuery != "" || endpoint.ForceQuery || endpoint.Fragment != "" || endpoint.RawFragment != "" || strings.Contains(config.Url, "#") {
		return nil, errors.New("global worker connection requires an absolute tls URL without embedded credentials or request components")
	}
	plan := &Plan{url: endpoint.String(), public: auth.PublicKey}
	for _, binding := range []struct {
		source string
		target *string
	}{{*auth.NKeyFile, &plan.seed}, {config.Tls.CaFile, &plan.ca}, {config.Tls.CertificateFile, &plan.certificate}, {config.Tls.KeyFile, &plan.key}} {
		if binding.source == "" {
			return nil, errIdentityFiles
		}
		absolute, err := filepath.Abs(binding.source)
		if err != nil {
			return nil, errIdentityFiles
		}
		*binding.target = absolute
	}
	identity, err := plan.identity(context.Background())
	if err != nil {
		return nil, err
	}
	identity.pair.Wipe()
	return plan, nil
}

// Matches prevents later configuration mutation from changing the admitted client.
func (p *Plan) Matches(config *directory.GlobalAuthorityNatsConfiguration) bool {
	if p == nil || config == nil || config.Authentication == nil || config.Authentication.NKeyFile == nil || config.Authentication.CredentialsFile != nil || config.Tls == nil || config.Cell != "gru" || config.Replicas != 3 {
		return false
	}
	absolute := func(path string) string {
		result, err := filepath.Abs(path)
		if err != nil {
			return ""
		}
		return result
	}
	return config.Url == p.url && config.Authentication.PublicKey == p.public && absolute(*config.Authentication.NKeyFile) == p.seed && absolute(config.Tls.CaFile) == p.ca && absolute(config.Tls.CertificateFile) == p.certificate && absolute(config.Tls.KeyFile) == p.key
}

// Connect opens one authenticated, unbuffered session. The caller owns Close.
func (p *Plan) Connect(ctx context.Context) (*nats.Conn, error) {
	return p.connect(ctx, net.Dialer{Timeout: 2 * time.Second})
}
func (p *Plan) connect(ctx context.Context, network net.Dialer) (*nats.Conn, error) {
	if p == nil || ctx == nil {
		return nil, errors.New("global worker connection plan and context are required")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	bounded, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	identity, err := p.identity(bounded)
	if err != nil {
		return nil, err
	}
	defer identity.pair.Wipe()
	return natsconnect.Connect(bounded, natsconnect.Config{URL: p.url, TLS: identity.tls, PublicNKey: p.public, Sign: identity.pair.Sign, Timeout: 2 * time.Second}, network)
}

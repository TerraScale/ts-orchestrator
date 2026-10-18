package foundation

import (
	"errors"
	"fmt"
	"unicode/utf8"

	spec "github.com/opencontainers/runtime-spec/specs-go"
)

type componentConfiguration struct {
	Args, Env []string
	Mounts    []spec.Mount
	Memory    uint64
}

func renderConfiguration(keys [3][]byte) ([]byte, error) {
	for _, key := range keys {
		if len(key) < 32 || len(key) > 256 || !utf8.Valid(key) {
			return nil, errors.New("NetBird configuration requires its original Vault keys")
		}
	}
	return fmt.Appendf(nil, `server:
  listenAddress: "127.0.0.1:18081"
  exposedAddress: "https://netbird.terrascale.tech:443"
  stunPorts:
    - 3478
  metricsPort: 9090
  healthcheckAddress: "127.0.0.1:19000"
  logLevel: "info"
  logFile: "console"
  authSecret: %q
  dataDir: "/var/lib/netbird"
  auth:
    issuer: "https://netbird.terrascale.tech/oauth2"
    signKeyRefreshEnabled: true
    sessionCookieEncryptionKey: %q
    dashboardRedirectURIs:
      - "https://netbird.terrascale.tech/nb-auth"
      - "https://netbird.terrascale.tech/nb-silent-auth"
    cliRedirectURIs:
      - "http://localhost:53000/"
  reverseProxy:
    trustedHTTPProxies:
      - "127.0.0.1/32"
    trustedPeers:
      - "127.0.0.1/32"
  store:
    engine: "sqlite"
    encryptionKey: %q
`, keys[0], keys[1], keys[2]), nil
}

const ingressConfiguration = `{
	admin off
}
netbird.terrascale.tech {
	@grpc header Content-Type application/grpc*
	reverse_proxy @grpc h2c://127.0.0.1:18081
	@backend path /relay* /ws-proxy/* /api/* /oauth2/*
	reverse_proxy @backend 127.0.0.1:18081
	reverse_proxy 127.0.0.1:18080
}
`

func configureComponents(root string) [3]componentConfiguration {
	bind := func(source, destination string, readOnly bool) spec.Mount {
		options := []string{"rbind", "nosuid", "nodev"}
		if readOnly {
			options = append(options, "ro")
		}
		return spec.Mount{Source: source, Destination: destination, Type: "bind", Options: options}
	}
	return [3]componentConfiguration{
		{
			Args: []string{"/go/bin/netbird-server", "--config", "/etc/netbird/config.yaml"},
			Mounts: []spec.Mount{
				bind(root+"/store/data", "/var/lib/netbird", false),
				bind(root+"/store/config.yaml", "/etc/netbird/config.yaml", true),
			},
			Memory: 512 << 20,
		},
		{
			Args: []string{"/bin/bash", "-ec", `sed -i 's/listen 80 default_server;/listen 127.0.0.1:18080 default_server;/; /listen \[::\]:80 default_server;/d' /etc/nginx/http.d/default.conf; exec /usr/local/init_react_envs.sh /usr/sbin/nginx`},
			// Upstream requires USE_AUTH0=false to use the fixed embedded IdP.
			Env: []string{
				"NETBIRD_MGMT_API_ENDPOINT=https://netbird.terrascale.tech",
				"NETBIRD_MGMT_GRPC_API_ENDPOINT=https://netbird.terrascale.tech",
				"AUTH_AUDIENCE=netbird-dashboard", "AUTH_CLIENT_ID=netbird-dashboard", "AUTH_CLIENT_SECRET=",
				"AUTH_AUTHORITY=https://netbird.terrascale.tech/oauth2", "USE_AUTH0=false",
				"AUTH_SUPPORTED_SCOPES=openid profile email groups", "AUTH_REDIRECT_URI=/nb-auth",
				"AUTH_SILENT_REDIRECT_URI=/nb-silent-auth", "NGINX_SSL_PORT=443", "LETSENCRYPT_DOMAIN=none",
			},
			Memory: 192 << 20,
		},
		{
			Args: []string{"/usr/bin/caddy", "run", "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"},
			Env:  []string{"XDG_DATA_HOME=/data", "XDG_CONFIG_HOME=/config"},
			Mounts: []spec.Mount{
				bind(root+"/ingress.Caddyfile", "/etc/caddy/Caddyfile", true),
				bind(root+"/store/data/foundation-tls", "/data", false),
				bind(root+"/store/data/foundation-caddy-config", "/config", false),
			},
			Memory: 192 << 20,
		},
	}
}

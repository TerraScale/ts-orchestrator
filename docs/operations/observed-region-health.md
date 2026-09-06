# Observed region health

The reconciliation command writes Worker health from fresh authenticated host status replies. Configured IP addresses and listening ports never count as engine readiness.

Set `TS_ORCH_HEALTH_CONFIG_FILE` to a private regular JSON file containing every estate region. Each region declares explicit coordinates, an authenticated regional NATS connection, and admitted hosts. Addresses must exactly match the configured Cloudflare load balancer pool. The file is reread each tick, and TLS/NKey material is validated at startup.

```json
{
  "regions": [{
    "code": "gru",
    "latitude": -23.43,
    "longitude": -46.47,
    "connection": {
      "url": "tls://regional-broker.example:4222",
      "caFile": "/etc/terrascale/health/ca.pem",
      "certificateFile": "/etc/terrascale/health/client.pem",
      "privateKeyFile": "/etc/terrascale/health/client.key",
      "nkeySeedFile": "/etc/terrascale/health/user.seed"
    },
    "members": [{"id": "gru-1", "address": "198.51.100.1", "architecture": 0}]
  }]
}
```

Architecture `0` means arm64; `1` means amd64. The example address is illustrative. Use the actual admitted hosts and pinned credentials. Regional NATS subject permissions must bind host responders to their node IDs. The observer needs read-only status request/reply permissions and no command signing key.

The host's `ts-node.json` supplies the actual engine observation endpoint and identity:

```json
{
  "engineObservation": {
    "endpoint": "127.0.0.1:7443",
    "serverIdentity": "spiffe://example/engine/gru-1",
    "certificateFile": "/etc/terrascale/engine-observer/client.pem",
    "privateKeyFile": "/etc/terrascale/engine-observer/client.key",
    "trustBundleFile": "/etc/terrascale/engine-observer/ca.pem",
    "tenant": "admitted-tenant",
    "project": "admitted-project",
    "database": "admitted-database"
  }
}
```

Merge this field into the complete node configuration. The client identity must be separately admitted for the database scope; do not reuse the engine's server key. TBEP requires a literal loopback endpoint, TLS 1.3, trusted certificates and an exact sole server SPIFFE URI. The node samples supervision, topology and admin status, then includes measured serving/draining state and its timestamp in its heartbeat and nonce-bound status reply. Failed observations clear the sample.

Each health tick has an eight-second budget. Regions are sampled concurrently with at most eight host requests per region. Transport failures produce unavailable health, and samples older than 30 seconds or more than one second in the future are rejected. A region is eligible only when all members of its configured load balancer pool have fresh serving engine reports, measured healthy clocks, no drain state, and no observed disk exhaustion. Cancellation of the reconciler stops the tick.

Current limits: TBEP does not report replication lag, so `lag_ms` is omitted unless every eligible member has a measured lag. Disk exhaustion is the available observed overload condition; this does not claim engine queue or CPU load measurement. Coordinates describe the admitted region configuration. A pending control-only listener may report measured starting or draining state with unknown engine topology; this cannot establish serving health.

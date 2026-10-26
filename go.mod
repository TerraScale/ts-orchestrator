module github.com/TerraScale/ts-orchestrator

go 1.27.3

// The read-only applied snapshot/watch contract is maintained with upstream provenance.
replace github.com/moby/swarmkit/v2 => ./third_party/swarmkit

// Pinned OCI runtime snapshot carries caller cancellation through instance-principal acquisition and signing.
replace github.com/oracle/oci-go-sdk/v65 => ./third_party/oci-go-sdk

require (
	github.com/VictoriaMetrics/metrics v1.44.1
	github.com/a-h/templ v0.3.1020
	github.com/containerd/containerd/api v1.12.0
	github.com/containerd/containerd/v2 v2.4.2
	github.com/containerd/errdefs v1.0.0
	github.com/containerd/platforms v1.0.0-rc.5
	github.com/distribution/reference v0.6.0
	github.com/gofrs/flock v0.10.0
	github.com/gogo/protobuf v1.3.2
	github.com/letsencrypt/pebble/v2 v2.10.1
	github.com/mattn/go-isatty v0.0.20
	github.com/miekg/dns v1.1.62
	github.com/moby/swarmkit/v2 v2.1.2
	github.com/nats-io/jwt/v2 v2.8.2
	github.com/nats-io/nats-server/v2 v2.15.0
	github.com/nats-io/nats.go v1.54.0
	github.com/nats-io/nkeys v0.4.16
	github.com/oklog/ulid/v2 v2.1.2
	github.com/opencontainers/go-digest v1.0.0
	github.com/opencontainers/image-spec v1.1.1
	github.com/opencontainers/runtime-spec v1.3.0
	github.com/oracle/oci-go-sdk/v65 v65.126.0
	github.com/pkg/errors v0.9.1
	github.com/prometheus/common v0.70.1
	github.com/starfederation/datastar-go v1.2.2
	github.com/tetratelabs/wazero v1.12.0
	golang.org/x/crypto v0.58.0
	golang.org/x/net v0.61.0
	golang.org/x/sync v0.24.0
	golang.org/x/sys v0.49.0
	golang.org/x/time v0.16.0
	google.golang.org/grpc v1.83.2
	google.golang.org/protobuf v1.36.12
	terrascale.tech/sdk v0.0.0-20261009173424-f8f51d8a46c6
)

require (
	code.cloudfoundry.org/clock v1.1.0 // indirect
	github.com/CAFxX/httpcompression v0.0.9 // indirect
	github.com/a-h/parse v0.0.0-20250122154542-74294addb73e // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/antithesishq/antithesis-sdk-go v0.8.0-default-no-op // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bits-and-blooms/bitset v1.13.0 // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cenkalti/backoff/v5 v5.0.3 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cilium/ebpf v0.22.0 // indirect
	github.com/cli/browser v1.3.0 // indirect
	github.com/cloudflare/cfssl v1.6.4 // indirect
	github.com/container-storage-interface/spec v1.2.0 // indirect
	github.com/containerd/continuity v0.5.0 // indirect
	github.com/containerd/errdefs/pkg v0.3.0 // indirect
	github.com/containerd/fifo v1.1.0 // indirect
	github.com/containerd/log v0.2.0 // indirect
	github.com/containerd/log/otel v0.1.0 // indirect
	github.com/containerd/plugin v1.1.0 // indirect
	github.com/containerd/ttrpc v1.2.9 // indirect
	github.com/containerd/typeurl/v2 v2.3.0 // indirect
	github.com/coreos/go-semver v0.3.1 // indirect
	github.com/coreos/go-systemd/v22 v22.7.0 // indirect
	github.com/docker/go-events v0.1.0 // indirect
	github.com/docker/go-metrics v0.1.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/felixge/httpsnoop v1.1.0 // indirect
	github.com/fernet/fernet-go v0.0.0-20211208181803-9f70042a33ee // indirect
	github.com/fsnotify/fsnotify v1.10.1 // indirect
	github.com/go-jose/go-jose/v4 v4.1.5 // indirect
	github.com/go-logr/logr v1.4.4 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/golang/groupcache v0.0.0-20210331224755-41bb18bfe9da // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/certificate-transparency-go v1.1.4 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.4-0.20250319132907-e064f32e3674 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware v1.3.0 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/providers/prometheus v1.1.0 // indirect
	github.com/grpc-ecosystem/go-grpc-middleware/v2 v2.1.0 // indirect
	github.com/grpc-ecosystem/go-grpc-prometheus v1.2.0 // indirect
	github.com/grpc-ecosystem/grpc-gateway/v2 v2.30.0 // indirect
	github.com/hashicorp/go-immutable-radix v1.3.1 // indirect
	github.com/hashicorp/go-memdb v1.3.2 // indirect
	github.com/hashicorp/golang-lru v0.5.4 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.9.2 // indirect
	github.com/jmoiron/sqlx v1.3.3 // indirect
	github.com/jonboulle/clockwork v0.5.0 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/letsencrypt/challtestsrv v1.4.2 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/minio/highwayhash v1.0.4 // indirect
	github.com/moby/locker v1.0.1 // indirect
	github.com/moby/sys/mountinfo v0.7.2 // indirect
	github.com/moby/sys/signal v0.7.1 // indirect
	github.com/moby/sys/user v0.4.1 // indirect
	github.com/moby/sys/userns v0.2.1 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/natefinch/atomic v1.0.1 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/prometheus/client_golang v1.24.1 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/procfs v0.21.1 // indirect
	github.com/sirupsen/logrus v1.10.2 // indirect
	github.com/soheilhy/cmux v0.1.5 // indirect
	github.com/sony/gobreaker/v2 v2.4.0 // indirect
	github.com/spf13/cobra v1.10.2 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/tmc/grpc-websocket-proxy v0.0.0-20201229170055-e5319fda7802 // indirect
	github.com/ulikunitz/xz v0.5.17 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fastrand v1.1.0 // indirect
	github.com/valyala/histogram v1.2.0 // indirect
	github.com/weppos/publicsuffix-go v0.15.1-0.20210511084619-b1f36a2d6c0b // indirect
	github.com/xiang90/probing v0.0.0-20190116061207-43a291ad63a2 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	github.com/yuin/goldmark v1.8.6 // indirect
	github.com/zmap/zcrypto v0.0.0-20210511125630-18f1e0152cfc // indirect
	github.com/zmap/zlint/v3 v3.1.0 // indirect
	go.etcd.io/bbolt v1.5.0 // indirect
	go.etcd.io/etcd/api/v3 v3.6.14 // indirect
	go.etcd.io/etcd/client/pkg/v3 v3.6.14 // indirect
	go.etcd.io/etcd/client/v3 v3.6.14 // indirect
	go.etcd.io/etcd/pkg/v3 v3.6.14 // indirect
	go.etcd.io/etcd/server/v3 v3.6.14 // indirect
	go.etcd.io/raft/v3 v3.6.0 // indirect
	go.opentelemetry.io/auto/sdk v1.2.1 // indirect
	go.opentelemetry.io/contrib/instrumentation/google.golang.org/grpc/otelgrpc v0.71.0 // indirect
	go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp v0.71.0 // indirect
	go.opentelemetry.io/otel v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace v1.46.0 // indirect
	go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc v1.46.0 // indirect
	go.opentelemetry.io/otel/metric v1.46.0 // indirect
	go.opentelemetry.io/otel/sdk v1.46.0 // indirect
	go.opentelemetry.io/otel/trace v1.46.0 // indirect
	go.opentelemetry.io/proto/otlp v1.11.0 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap v1.27.0 // indirect
	go.yaml.in/yaml/v2 v2.4.4 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/tools v0.51.0 // indirect
	google.golang.org/genproto v0.0.0-20260825221802-da73d73af1c5 // indirect
	google.golang.org/genproto/googleapis/api v0.0.0-20260825221802-da73d73af1c5 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20260825221802-da73d73af1c5 // indirect
	gopkg.in/natefinch/lumberjack.v2 v2.2.1 // indirect
	k8s.io/klog/v2 v2.140.0 // indirect
	sigs.k8s.io/json v0.0.0-20250730193827-2d320260d730 // indirect
	sigs.k8s.io/yaml v1.6.0 // indirect
)

replace github.com/nats-io/nats-server/v2 => ./third_party/nats-server

tool github.com/a-h/templ/cmd/templ

replace terrascale.tech/sdk => github.com/TerraScale/ts-go v0.0.0-20261009173424-f8f51d8a46c6

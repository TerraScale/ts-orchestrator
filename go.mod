module git.terrascale.tech/TerraScale/ts-orchestrator

go 1.27.0

require (
	github.com/VictoriaMetrics/metrics v1.44.1
	github.com/a-h/templ v0.3.1020
	github.com/nats-io/jwt/v2 v2.8.2
	github.com/nats-io/nats-server/v2 v2.15.0
	github.com/nats-io/nats.go v1.54.0
	github.com/nats-io/nkeys v0.4.16
	github.com/oklog/ulid/v2 v2.1.2
	github.com/oracle/oci-go-sdk/v65 v65.126.0
	github.com/starfederation/datastar-go v1.2.2
	golang.org/x/net v0.58.0
	golang.org/x/sync v0.23.0
	golang.org/x/sys v0.48.0
	golang.org/x/time v0.16.0
	terrascale.tech/sdk v0.0.0-20261008171617-49fb07f5b866
)

require (
	github.com/CAFxX/httpcompression v0.0.9 // indirect
	github.com/a-h/parse v0.0.0-20250122154542-74294addb73e // indirect
	github.com/andybalholm/brotli v1.2.0 // indirect
	github.com/antithesishq/antithesis-sdk-go v0.8.0-default-no-op // indirect
	github.com/cenkalti/backoff/v4 v4.3.0 // indirect
	github.com/cli/browser v1.3.0 // indirect
	github.com/fatih/color v1.16.0 // indirect
	github.com/fsnotify/fsnotify v1.7.0 // indirect
	github.com/gofrs/flock v0.10.0 // indirect
	github.com/google/go-tpm v0.9.8 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/pgx/v5 v5.9.2 // indirect
	github.com/klauspost/compress v1.20.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/minio/highwayhash v1.0.4 // indirect
	github.com/natefinch/atomic v1.0.1 // indirect
	github.com/nats-io/nuid v1.0.1 // indirect
	github.com/sony/gobreaker/v2 v2.4.0 // indirect
	github.com/valyala/bytebufferpool v1.0.0 // indirect
	github.com/valyala/fastrand v1.1.0 // indirect
	github.com/valyala/histogram v1.2.0 // indirect
	github.com/youmark/pkcs8 v0.0.0-20240726163527-a2c0da244d78 // indirect
	golang.org/x/crypto v0.57.0 // indirect
	golang.org/x/mod v0.41.0 // indirect
	golang.org/x/text v0.42.0 // indirect
	golang.org/x/tools v0.49.0 // indirect
)

replace github.com/nats-io/nats-server/v2 => ./third_party/nats-server

tool github.com/a-h/templ/cmd/templ

replace terrascale.tech/sdk => git.terrascale.tech/TerraScale/ts-go v0.0.0-20261008171617-49fb07f5b866

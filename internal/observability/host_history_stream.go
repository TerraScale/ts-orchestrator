package observability

import (
	"time"
)

const (
	HostMetricBatchVersion          = 1
	HostMetricStreamName            = "TS_HOST_METRIC_HISTORY"
	HostMetricStreamBytes     int64 = 1536 << 20
	HostMetricBatchBytes            = 64 << 10
	hostMetricHeaderBytes           = 128 // NATS framing and the uint64 expected-last-sequence header.
	HostMetricInterval              = time.Minute
	hostMetricDecodedBytes          = 1 << 20
	hostMetricPublishAttempts       = 8
	hostMetricReplayWait            = time.Second
	hostMetricReplayChunk           = 64
	hostMetricMaxFilesystems        = 37 // Five host roots and at most 32 managed roles.
)

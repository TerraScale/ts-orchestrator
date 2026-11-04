package mesh

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

const ClockReportSubject = "terrabase.clock.report"
const ClockReportBucket = "tb-clock-skew"

type clockReport struct {
	Node               string    `json:"node"`
	Region             string    `json:"region"`
	SkewMilliseconds   *float64  `json:"skewMilliseconds"`
	LocalWritesAllowed bool      `json:"localWritesAllowed"`
	SampledAt          time.Time `json:"sampledAt"`
}

func (n *Node) serveClockReports() error {
	if n.fabric == nil {
		return nil
	}
	js, err := jetstream.New(n.fabric)
	if err != nil {
		return err
	}
	var bucket jetstream.KeyValue
	sub, err := n.fabric.QueueSubscribe(ClockReportSubject, "clock-reports", func(message *nats.Msg) {
		var report clockReport
		if len(message.Data) > 4096 || json.Unmarshal(message.Data, &report) != nil || !serviceName.MatchString(report.Node) ||
			!serviceName.MatchString(report.Region) || report.SampledAt.IsZero() ||
			(report.SkewMilliseconds != nil && (math.IsNaN(*report.SkewMilliseconds) || math.IsInf(*report.SkewMilliseconds, 0) || *report.SkewMilliseconds < 0)) ||
			(report.LocalWritesAllowed && (report.SkewMilliseconds == nil || *report.SkewMilliseconds > 50)) {
			_ = message.Respond([]byte(`{"stored":false}`))
			return
		}
		ctx, cancel := context.WithTimeout(n.ctx, 2*time.Second)
		defer cancel()
		var storeErr error
		if bucket == nil {
			bucket, storeErr = js.CreateOrUpdateKeyValue(ctx, jetstream.KeyValueConfig{
				Bucket: ClockReportBucket, History: 1, TTL: 15 * time.Second, Replicas: 3, MaxBytes: 1 << 20, MaxValueSize: 4096,
			})
		}
		if storeErr == nil {
			_, storeErr = bucket.Put(ctx, report.Node, message.Data)
		}
		if storeErr != nil {
			bucket = nil
			_ = message.Respond([]byte(`{"stored":false}`))
			return
		}
		_ = message.Respond([]byte(`{"stored":true}`))
	})
	if err != nil {
		return err
	}
	if err := sub.SetPendingLimits(64, 256<<10); err != nil {
		return errors.Join(err, sub.Unsubscribe())
	}
	return n.fabric.Flush()
}

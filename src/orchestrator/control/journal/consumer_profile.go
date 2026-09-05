package journal

import (
	"time"

	"github.com/nats-io/nats.go/jetstream"
)

// NatsConsumerProfileMatches is the closed consumer profile comparison.
func NatsConsumerProfileMatches(
	observed *jetstream.ConsumerInfo,
	expected jetstream.ConsumerConfig,
	expectedStream string,
) bool {
	if observed == nil {
		return false
	}

	if expected.Name == "" || expected.FilterSubject == "" {
		return false
	}

	actual := observed.Config
	return observed.Stream == expectedStream &&
		observed.Name == expected.Name &&
		!observed.Paused &&
		!observed.PushBound &&
		actual.Name == expected.Name &&
		actual.Durable == expected.Durable &&
		actual.Description == expected.Description &&
		actual.DeliverPolicy == expected.DeliverPolicy &&
		actual.OptStartSeq == expected.OptStartSeq &&
		timeEqualOptional(actual.OptStartTime, expected.OptStartTime) &&
		actual.DeliverSubject == "" &&
		actual.DeliverGroup == "" &&
		actual.AckPolicy == expected.AckPolicy &&
		actual.AckWait == expected.AckWait &&
		actual.MaxDeliver == expected.MaxDeliver &&
		actual.FilterSubject == expected.FilterSubject &&
		len(actual.FilterSubjects) == 0 &&
		actual.ReplayPolicy == expected.ReplayPolicy &&
		actual.SampleFrequency == "" &&
		actual.RateLimit == expected.RateLimit &&
		actual.MaxAckPending == expected.MaxAckPending &&
		actual.IdleHeartbeat == expected.IdleHeartbeat &&
		actual.FlowControl == expected.FlowControl &&
		actual.MaxWaiting == expected.MaxWaiting &&
		actual.HeadersOnly == expected.HeadersOnly &&
		actual.MaxRequestBatch == expected.MaxRequestBatch &&
		actual.MaxRequestExpires == expected.MaxRequestExpires &&
		actual.MaxRequestMaxBytes == expected.MaxRequestMaxBytes &&
		actual.InactiveThreshold == expected.InactiveThreshold &&
		durationSlicesEqual(actual.BackOff, expected.BackOff) &&
		actual.Replicas == expected.Replicas &&
		actual.PauseUntil == nil &&
		actual.MemoryStorage == expected.MemoryStorage &&
		len(actual.PriorityGroups) == 0 &&
		actual.PriorityPolicy == jetstream.PriorityPolicyNone &&
		actual.PinnedTTL == 0
}

func timeEqualOptional(first, second *time.Time) bool {
	if first == nil || second == nil {
		return first == second
	}

	return first.Equal(*second)
}

func durationSlicesEqual(actual, expected []time.Duration) bool {
	if len(actual) != len(expected) {
		return false
	}

	for index := range actual {
		if actual[index] != expected[index] {
			return false
		}
	}

	return true
}

package journal

import (
	"context"
	"errors"
	"time"

	"github.com/nats-io/nats.go/jetstream"
	"terrascale.tech/orchestrator/src/orchestrator/control/messaging"
)

// CiRunnerConsumerRegistration identifies one reconciled CI runner consumer.
type CiRunnerConsumerRegistration struct {
	Zone     string
	Consumer string
	Subject  string
}

func NewCiRunnerConsumerRegistration(zone, consumer, subject string) CiRunnerConsumerRegistration {
	return CiRunnerConsumerRegistration{Zone: zone, Consumer: consumer, Subject: subject}
}

// CiRunnerConsumerReconciler reconciles controller-owned runner consumers
// before any runner identity can be issued.
type CiRunnerConsumerReconciler struct {
	jetStream jetstream.JetStream
	topology  *messaging.GlobalNatsTopology
}

func NewCiRunnerConsumerReconciler(js jetstream.JetStream, topology *messaging.GlobalNatsTopology) (*CiRunnerConsumerReconciler, error) {
	if js == nil {
		return nil, errors.New("(Parameter 'jetStream')")
	}

	if topology == nil {
		return nil, errors.New("(Parameter 'topology')")
	}

	return &CiRunnerConsumerReconciler{jetStream: js, topology: topology}, nil
}

func (r *CiRunnerConsumerReconciler) ReconcileAsync(
	ctx context.Context,
	zone string,
	runner string,
) (CiRunnerConsumerRegistration, error) {
	expected, err := r.topology.CiJobConsumer(zone, runner)
	if err != nil {
		return CiRunnerConsumerRegistration{}, err
	}

	if expected.Name == "" {
		return CiRunnerConsumerRegistration{}, errors.New(
			"NATS returned a CI runner consumer without a name.")
	}

	if expected.FilterSubject == "" {
		return CiRunnerConsumerRegistration{}, errors.New(
			"NATS returned a CI runner consumer without a filter subject.")
	}

	stream, err := r.jetStream.Stream(ctx, messaging.GlobalNatsTopologyCiStream)
	if err != nil {
		return CiRunnerConsumerRegistration{}, err
	}

	consumer, err := stream.CreateOrUpdateConsumer(ctx, expected)
	if err != nil {
		return CiRunnerConsumerRegistration{}, err
	}

	info, err := consumer.Info(ctx)
	if err != nil {
		return CiRunnerConsumerRegistration{}, err
	}

	if !CiRunnerConsumerReconcilerMatches(info, expected, messaging.GlobalNatsTopologyCiStream) {
		return CiRunnerConsumerRegistration{}, errors.New(
			"NATS returned an unsafe CI runner consumer configuration for " + expected.Name + ".")
	}

	return NewCiRunnerConsumerRegistration(zone, expected.Name, expected.FilterSubject), nil
}

// CiRunnerConsumerReconcilerMatches is the closed consumer profile comparison.
func CiRunnerConsumerReconcilerMatches(
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

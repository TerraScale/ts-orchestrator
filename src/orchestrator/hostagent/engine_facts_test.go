package hostagent

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"
)

func TestHostFactsCarriesEngineSampleAndClearsFailedObservation(t *testing.T) {
	source := newTestFactsSource(t, fakeClock{}, newFakeSystemd())
	sample := EngineFacts{Measured: true, Serving: true, ObservedAtUnixMS: time.Now().UnixMilli()}
	source.engine = func(context.Context) (EngineFacts, error) { return sample, nil }
	facts, err := source.Sample(t.Context(), NodeStateServing, nil)
	if err != nil || !reflect.DeepEqual(facts.Engine, sample) {
		t.Fatalf("engine sample lost: %+v %v", facts.Engine, err)
	}
	source.engine = func(context.Context) (EngineFacts, error) { return sample, errors.New("authentication failed") }
	facts, err = source.Sample(t.Context(), NodeStateServing, nil)
	if err != nil || facts.Engine.Measured || facts.Engine.Serving {
		t.Fatalf("failed engine observation reused: %+v %v", facts.Engine, err)
	}
}

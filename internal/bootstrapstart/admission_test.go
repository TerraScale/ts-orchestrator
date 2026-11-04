package bootstrapstart

import (
	"context"
)

type fakeInstanceObserver struct{ observation InstanceObservation }

func (fake fakeInstanceObserver) ObserveInstance(context.Context, string) (InstanceObservation, error) {
	return fake.observation, nil
}

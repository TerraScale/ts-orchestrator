package app

import (
	"github.com/TerraScale/ts-orchestrator/internal/brokerauth"
)

// Overridden only by tests whose local kernel clock is deliberately not an NTP
// qualification source. Production startup and broker authority share a probe.
var controllerBrokerClockProbe = func() brokerauth.ClockProbe { return brokerauth.KernelClockProbe{} }

func controllerClockCheck(probe brokerauth.ClockProbe) func() error {
	return func() error {
		_, err := brokerauth.MeasureHealthyClock(probe)
		return err
	}
}

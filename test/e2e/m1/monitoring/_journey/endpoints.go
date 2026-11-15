package alertdelivery

import "os"

var (
	listenAddress     = os.Getenv("JOURNEY_RELAY_ADDRESS") + ":9094"
	stateDirectory    = os.Getenv("JOURNEY_RELAY_STATE")
	fleetLayout       = os.Getenv("JOURNEY_RELAY_LAYOUT")
	budgetServer      = "nats://" + os.Getenv("JOURNEY_RELAY_ADDRESS") + ":4223"
	meshAlertsToken   = os.Getenv("JOURNEY_RELAY_STATE") + "/alerts.token"
	emailEndpoint     = "http://127.0.0.9:8025/accounts/"
	pushEndpoint      = "http://127.0.0.9:8025/push/"
	admissionEndpoint = "http://127.0.0.9:8025/admission"
)

package alertdelivery

import "time"

const (
	listenAddress     = "127.0.0.1:9094"
	stateDirectory    = "/var/lib/ts-alerts"
	fleetLayout       = "/etc/ts-monitoring/production/alertmanager.env"
	budgetServer      = "nats://127.0.0.1:4223"
	meshAlertsToken   = "/var/lib/ts-orch/mesh/alerts.token"
	emailEndpoint     = "https://api.cloudflare.com/client/v4/accounts/"
	pushEndpoint      = "https://ntfy.sh/"
	admissionEndpoint = "https://auth.terrascale.tech/v1/terrascale/email/admission"
)

var notificationDeadline = 10 * time.Second

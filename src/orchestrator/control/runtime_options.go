package control

import (
	"fmt"
	"net/url"
)

// String provides a bounded, credential-free diagnostic projection. In
// particular, it does not delegate to fmt's struct formatting, which would
// expose configured paths and make adding a secret field unsafe by default.
func (o *OrchestratorOptions) String() string {
	if o == nil {
		return "<nil>"
	}
	return fmt.Sprintf("OrchestratorOptions{command=%s, cell=%q, nats_url=%q, replicas=%d, instance=%q, command_identity=%t}",
		o.Command.String(), o.Cell, redactedNatsURL(o.NatsURL), o.Replicas, o.Instance,
		o.CommandIdentity != nil)
}

func redactedNatsURL(raw string) string {
	parsed, err := url.Parse(raw)
	if err == nil && parsed.User != nil {
		parsed.User = url.User(parsed.User.Username())
		return parsed.String()
	}
	return raw
}

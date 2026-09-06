package hostcontrol

import (
	"context"
	"errors"
	"github.com/nats-io/nats.go"
	"strings"
	"terrascale.tech/orchestrator/src/orchestrator/hostagent"
	"time"
)

// Observer exposes only authenticated fresh status requests, without requiring
// a mutation signing key. Admission is reread for every request.
type Observer struct{ client *Client }

func NewObserver(region string, connection *nats.Conn, resolve func(context.Context, string) (Host, error), timeout time.Duration) (*Observer, error) {
	if region == "" || region != strings.ToUpper(region) || connection == nil || resolve == nil || timeout <= 0 || timeout > time.Minute {
		return nil, errors.New("hostcontrol: observer requires admitted region, connection, resolver and bounded timeout")
	}
	client := &Client{config: Config{Region: region, Connection: connection, ResolveHost: resolve, Timeout: timeout}}
	if err := client.checkConnection(); err != nil {
		return nil, err
	}
	return &Observer{client: client}, nil
}
func (o *Observer) Status(ctx context.Context, host string) (hostagent.NodeStatusReport, error) {
	return o.client.Status(ctx, host)
}

package natscell

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
)

// Only a failure to reach the brokers matches ErrUnavailable: a CD driver
// retries it, while configuration errors must stop the run at once.
func TestStartMarksOnlyUnreachableBrokersUnavailable(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	defer cancel()
	port := freeClientPort(t)
	_, err := Start(ctx, Config{Cell: "lab", Instance: "client", Replicas: 1, Lab: true,
		URL: fmt.Sprintf("nats://127.0.0.1:%d", port)})
	if err == nil || !errors.Is(err, ErrUnavailable) || !strings.HasPrefix(err.Error(), "connect regional NATS: ") {
		t.Fatalf("unreachable broker = %v, want ErrUnavailable with the connect cause", err)
	}
	for name, config := range map[string]Config{
		"invalid cell":     {Cell: "Lab", Instance: "client", Replicas: 1, Lab: true, URL: "nats://127.0.0.1:4222"},
		"invalid replicas": {Cell: "lab", Instance: "client", Replicas: 2, Lab: true, URL: "nats://127.0.0.1:4222"},
		"missing credentials": {Cell: "gru", Instance: "operator", Replicas: 3, ClientRole: "operator",
			URL:             "tls://10.251.0.11:4222,tls://10.251.0.12:4222,tls://10.251.0.13:4222",
			CredentialsFile: "missing.creds", TLS: TLSFiles{CAFile: "ca", CertFile: "cert", KeyFile: "key"},
			OperatorForward: map[string]string{"10.251.0.12:4222": "127.0.0.1:14222"}},
	} {
		if _, err := Start(ctx, config); err == nil || errors.Is(err, ErrUnavailable) {
			t.Errorf("%s = %v, want an error that is not ErrUnavailable", name, err)
		}
	}
}

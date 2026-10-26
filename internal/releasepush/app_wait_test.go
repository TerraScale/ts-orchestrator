package releasepush

import (
	"context"
	"encoding/json"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nats-io/nats.go"
)

func TestAppWaitRenewsShortCredentialAndResumesDroppedConnection(t *testing.T) {
	i := newIssuer(t)
	v := i.verifier(time.Now())
	v.Now = time.Now
	srv, auth, url, pin := startServerIn(t, v, t.TempDir())
	local, err := auth.Connect(srv)
	if err != nil {
		t.Fatal(err)
	}
	defer local.Close()
	started := make(chan struct{})
	var applications, mints, connections atomic.Int32
	h := &Handler{Verifier: v, App: func(ctx context.Context, _, _ string, _ Claims) (json.RawMessage, error) {
		applications.Add(1)
		close(started)
		select {
		case <-time.After(3 * time.Second): // Longer than each credential's admitted lifetime.
			return json.RawMessage(`[{"region":"gru","bake":"passed"}]`), nil
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}}
	if err := h.Serve(local); err != nil {
		t.Fatal(err)
	}
	mint := func(context.Context) (string, error) {
		mints.Add(1)
		claims := goodClaims(time.Now())
		claims["repository"] = owner + "/ts-dashboard"
		claims["job_workflow_ref"] = owner + "/ts-dashboard/.github/workflows/images-ghcr.yml@" + mainRef
		// Auth admits until exp+clockSkew, keeping the real expiry test short.
		claims["exp"] = time.Now().Add(-clockSkew + 2*time.Second).Unix()
		return i.sign(t, claims), nil
	}
	dial := func(token string) (*nats.Conn, error) {
		conn, err := Dial(Region{NATS: url, SPKISHA256: pin}, token, nats.MaxReconnects(0))
		if err == nil && connections.Add(1) == 1 {
			go func() { <-started; conn.Close() }() // Lose the acceptance reply or first polling connection.
		}
		return conn, err
	}
	token, _ := mint(t.Context())
	initialClaims, _ := appTokenClaims(token)
	conn, err := dial(token)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	reply, err := awaitApp(ctx, AppRelease{Service: "ts-dashboard", Image: "ghcr.io/terrascale/ts-dashboard@sha256:" + strings.Repeat("a", 64), Token: token}, conn, mint, dial, 100*time.Millisecond)
	if err != nil || reply.State != "done" || !strings.Contains(string(reply.Result), "passed") {
		t.Fatalf("release lost across credential expiry/disconnect: %+v %v", reply, err)
	}
	if applications.Load() != 1 || mints.Load() < 2 || connections.Load() < 2 || time.Now().Before(time.Unix(initialClaims.Expires, 0).Add(clockSkew)) {
		t.Fatalf("release did not outlive its credential idempotently: apps=%d mints=%d connections=%d", applications.Load(), mints.Load(), connections.Load())
	}
}

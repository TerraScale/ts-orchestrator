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
	for _, subject := range []string{SubjectApp, SubjectApply} {
		t.Run(subject, func(t *testing.T) { testOperationWait(t, subject) })
	}
}

func TestOperationRenewalRefusesChangedAttempt(t *testing.T) {
	i := newIssuer(t)
	claims := goodClaims(time.Now())
	claims["exp"] = time.Now().Unix() // Force renewal before dialing.
	token := i.sign(t, claims)
	claims["run_attempt"] = "2"
	_, err := awaitOperation(t.Context(), token, nil, func(context.Context) (string, error) {
		return i.sign(t, claims), nil
	}, func(string) (*nats.Conn, error) {
		t.Fatal("dialed with a different signed attempt")
		return nil, nil
	}, time.Millisecond, SubjectApp, nil)
	if err == nil || err.Error() != "renewed release credential changed workflow identity" {
		t.Fatalf("changed attempt: %v", err)
	}
}

func testOperationWait(t *testing.T, subject string) {
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
	h.Mesh = func(ctx context.Context, _ string, _ json.RawMessage) (json.RawMessage, error) {
		return h.App(ctx, "", "", Claims{})
	}
	if err := h.Serve(local); err != nil {
		t.Fatal(err)
	}
	mint := func(context.Context) (string, error) {
		mints.Add(1)
		claims := goodClaims(time.Now())
		claims["repository"] = owner + "/terrascale"
		claims["job_workflow_ref"] = owner + "/terrascale/.github/workflows/images-ghcr.yml@" + mainRef
		if subject == SubjectApply {
			claims = meshClaims(time.Now())
		}
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
	reply, err := awaitOperation(ctx, token, conn, mint, dial, 100*time.Millisecond, subject, func(token string) ([]byte, error) {
		if subject == SubjectApply {
			return json.Marshal(MeshRequest{Token: token, Spec: json.RawMessage(`{"name":"whoami"}`)})
		}
		return json.Marshal(AppRelease{Service: "ts-dashboard", Image: "ghcr.io/terrascale/ts-dashboard@sha256:" + strings.Repeat("a", 64), Token: token})
	})
	if err != nil || reply.State != "done" || !strings.Contains(string(reply.Result), "passed") {
		t.Fatalf("release lost across credential expiry/disconnect: %+v %v", reply, err)
	}
	if applications.Load() != 1 || mints.Load() < 2 || connections.Load() < 2 || time.Now().Before(time.Unix(initialClaims.Expires, 0).Add(clockSkew)) {
		t.Fatalf("release did not outlive its credential idempotently: apps=%d mints=%d connections=%d", applications.Load(), mints.Load(), connections.Load())
	}
}

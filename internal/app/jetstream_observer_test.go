package app

import (
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/natscell"
	"github.com/nats-io/jwt/v2"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
	"github.com/nats-io/nkeys"
)

type jetStreamObserverDialer struct{ *tls.Dialer }

func (*jetStreamObserverDialer) SkipTLSHandshake() bool { return true }

func jetStreamObserverSubjects(bucket string) (leader, direct []string) {
	for _, prefix := range []string{"$JS.API", "$JS.gru.API"} {
		leader = append(leader, prefix+".STREAM.MSG.GET.KV_"+bucket)
		direct = append(direct, prefix+".DIRECT.GET.KV_"+bucket, prefix+".DIRECT.GET.KV_"+bucket+".>")
	}
	return leader, direct
}

func testRolloutJetStreamWithObserver(t *testing.T, bucket string) (jetstream.JetStream, *nats.Conn) {
	t.Helper()
	auth := newAuthenticatedNATS(t, "gru")
	runtime, err := auth.start(t, t.Context(), natscell.Config{Cell: "gru", Embedded: &natscell.Embedded{}})
	if err != nil {
		t.Fatal(err)
	}
	user, err := nkeys.CreateUser()
	if err != nil {
		t.Fatal(err)
	}
	defer user.Wipe()
	public, err := user.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	leader, direct := jetStreamObserverSubjects(bucket)
	claim := jwt.NewUserClaims(public)
	claim.IssuerAccount = auth.cellID
	claim.Expires = time.Now().Add(5 * time.Minute).Unix()
	claim.Pub.Deny = jwt.StringList{">"}
	claim.Sub.Allow = append(jwt.StringList(leader), direct...)
	credentials := testBrokerJWTUserWithKey(t, auth.root, "jetstream-observer.creds", auth.account, user, claim)
	dialer := &jetStreamObserverDialer{Dialer: &tls.Dialer{NetDialer: &net.Dialer{Timeout: 5 * time.Second}, Config: runtime.BrokerTLS().PeerConfig()}}
	observer, err := nats.Connect(runtime.URL(), nats.UserCredentials(credentials), nats.SetCustomDialer(dialer), nats.NoReconnect(), nats.Timeout(5*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(observer.Close)
	return runtime.JetStream(), observer
}

// watchJetStreamLeaderReads counts leader and follower reads of bucket. The
// server can answer a read before it copies the request to the observer, so
// finish waits for want leader reads before checking that no more arrived.
func watchJetStreamLeaderReads(t *testing.T, observer *nats.Conn, bucket string) func(want int) int {
	t.Helper()
	leader, direct := jetStreamObserverSubjects(bucket)
	subscribe := func(subjects []string, messages chan *nats.Msg) []*nats.Subscription {
		var subscriptions []*nats.Subscription
		for _, subject := range subjects {
			subscription, err := observer.ChanSubscribe(subject, messages)
			if err != nil {
				t.Fatal(err)
			}
			subscriptions = append(subscriptions, subscription)
		}
		return subscriptions
	}
	leaderReads, directReads := make(chan *nats.Msg, 1024), make(chan *nats.Msg, 1024)
	subscriptions := append(subscribe(leader, leaderReads), subscribe(direct, directReads)...)
	if err := observer.Flush(); err != nil {
		t.Fatal(err)
	}
	return func(want int) int {
		t.Helper()
		reads := 0
		deadline := time.After(10 * time.Second)
	wait:
		for reads < want {
			select {
			case <-leaderReads:
				reads++
			case <-deadline:
				break wait
			}
		}
		if err := observer.Flush(); err != nil {
			t.Fatal(err)
		}
		for _, subscription := range subscriptions {
			_ = subscription.Unsubscribe()
		}
		if err := observer.LastError(); err != nil {
			t.Fatalf("JetStream observer authorization failed: %v", err)
		}
		reads += len(leaderReads)
		if count := len(directReads); count != 0 {
			t.Fatalf("authorization used follower reads=%d", count)
		}
		return reads
	}
}

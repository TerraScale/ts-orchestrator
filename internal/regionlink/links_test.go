package regionlink

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server"
	"github.com/nats-io/nats.go"
)

func TestLinksRegionsAndRequests(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	if _, err := conn.Subscribe("ts.orch.v1.gru.obs.ping", func(message *nats.Msg) {
		_ = message.Respond(append([]byte("pong:"), message.Data...))
	}); err != nil {
		t.Fatal(err)
	}
	links, err := New("GRU", conn, []string{"sjc", "FRA", "global", "bad region"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if got := links.Regions(); !slices.Equal(got, []string{"gru", "fra", "sjc"}) {
		t.Fatalf("regions = %v", got)
	}
	reply, err := links.Request(t.Context(), "GRU", "ping", []byte("x"))
	if err != nil || string(reply) != "pong:x" {
		t.Fatalf("reply = %q err=%v", reply, err)
	}
	if _, err := links.Request(t.Context(), "sjc", "ping", nil); !errors.Is(err, ErrNotLinked) {
		t.Fatalf("unlinked err = %v", err)
	}
	if _, err := links.Request(t.Context(), "mia", "ping", nil); !errors.Is(err, ErrUnknownRegion) {
		t.Fatalf("unknown err = %v", err)
	}
	if err := links.Link("mia", conn); err != nil || !links.Linked("mia") {
		t.Fatalf("link err = %v", err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 200*time.Millisecond)
	defer cancel()
	if _, err := links.Request(ctx, "mia", "ping", nil); err == nil {
		t.Fatal("a region with no responder must fail")
	}
	if err := links.Link("mia", nil); err != nil || links.Linked("mia") {
		t.Fatal("unlink failed")
	}
	if err := links.Link("global", conn); err == nil {
		t.Fatal("the global scope is not a region")
	}
}

// A caller deadline later than the link timeout does not stretch it.
func TestLinkTimeoutAppliesUnderALaterCallerDeadline(t *testing.T) {
	srv, err := server.NewServer(&server.Options{Host: "127.0.0.1", Port: -1, NoLog: true, NoSigs: true})
	if err != nil {
		t.Fatal(err)
	}
	go srv.Start()
	if !srv.ReadyForConnections(5 * time.Second) {
		t.Fatal("NATS did not start")
	}
	t.Cleanup(func() { srv.Shutdown(); srv.WaitForShutdown() })
	conn, err := nats.Connect(srv.ClientURL())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(conn.Close)
	if _, err := conn.Subscribe("ts.orch.v1.gru.obs.slow", func(message *nats.Msg) {
		time.Sleep(2 * time.Second)
		_ = message.Respond(nil)
	}); err != nil {
		t.Fatal(err)
	}
	links, err := New("gru", conn, nil, 150*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	started := time.Now()
	if _, err := links.Request(ctx, "gru", "slow", nil); err == nil {
		t.Fatal("a slow region answered")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("the request took %s under a 150ms link timeout", elapsed)
	}

	t.Run("unlink drops only peer routes", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
		defer cancel()
		responder, err := nats.Connect(srv.ClientURL(), nats.Timeout(time.Second))
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(responder.Close)
		const subject = "ts.orch.v1.sjc.obs.ping"
		type observation struct {
			subject string
			payload string
			err     error
		}
		observed := make(chan observation, 4)
		sub, err := responder.Subscribe(subject, func(message *nats.Msg) {
			err := message.Respond(append([]byte("pong:"), message.Data...))
			select {
			case observed <- observation{message.Subject, string(message.Data), err}:
			case <-ctx.Done():
			}
		})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = sub.Unsubscribe() })
		if err := responder.FlushTimeout(time.Second); err != nil {
			t.Fatal(err)
		}
		links, err := New("gru", nil, []string{"sjc", "fra"}, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		state := func(want []string, linked bool) {
			t.Helper()
			if got := links.Regions(); !slices.Equal(got, want) || links.Linked("sjc") != linked || links.Linked("gru") {
				t.Fatalf("regions = %v, linked sjc=%v gru=%v; want %v, sjc=%v gru=false", got, links.Linked("sjc"), links.Linked("gru"), want, linked)
			}
		}
		observe := func(payload string) {
			t.Helper()
			waitCtx, stop := context.WithTimeout(ctx, time.Second)
			defer stop()
			select {
			case got := <-observed:
				if got.subject != subject || got.payload != payload || got.err != nil {
					t.Fatalf("responder = %+v, want %s %q and nil response error", got, subject, payload)
				}
			case <-waitCtx.Done():
				t.Fatalf("responder observation %q: %v", payload, waitCtx.Err())
			}
		}
		ping := func(payload string) {
			t.Helper()
			reply, err := links.Request(ctx, "SJC", "ping", []byte(payload))
			if err != nil || string(reply) != "pong:"+payload {
				t.Fatalf("peer request %q = %q, %v", payload, reply, err)
			}
			observe(payload)
		}
		links.Unlink("GRU")
		state([]string{"gru", "fra", "sjc"}, false)
		links.Unlink("mia")
		state([]string{"gru", "fra", "sjc"}, false)
		if err := links.Link("sjc", conn); err != nil || !links.Linked("sjc") {
			t.Fatalf("link sjc: %v", err)
		}
		state([]string{"gru", "fra", "sjc"}, true)
		ping("linked")
		links.Unlink("GRU")
		state([]string{"gru", "fra", "sjc"}, true)
		ping("local-kept")
		links.Unlink("mia")
		state([]string{"gru", "fra", "sjc"}, true)
		ping("unknown-kept")
		links.Unlink("SJC")
		state([]string{"gru", "fra"}, false)
		if reply, err := links.Request(ctx, "sjc", "ping", []byte("removed")); !errors.Is(err, ErrUnknownRegion) || reply != nil {
			t.Fatalf("removed peer request = %q, %v; want nil, ErrUnknownRegion", reply, err)
		}
		// The same-connection probe orders earlier sends before the final observation.
		if err := conn.FlushTimeout(time.Second); err != nil {
			t.Fatal(err)
		}
		probeCtx, stopProbe := context.WithTimeout(ctx, time.Second)
		defer stopProbe()
		reply, err := conn.RequestWithContext(probeCtx, subject, []byte("responder-alive"))
		if err != nil || string(reply.Data) != "pong:responder-alive" {
			t.Fatalf("direct responder probe = %+v, %v", reply, err)
		}
		observe("responder-alive")
		select {
		case extra := <-observed:
			t.Fatalf("unexpected responder observation: %+v", extra)
		default:
		}
	})
}

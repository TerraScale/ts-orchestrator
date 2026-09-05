//go:build unix

package globalclient

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"strconv"
	"sync"
	"testing"
	"time"

	"golang.org/x/net/dns/dnsmessage"
)

func TestCancellationAfterAcceptClosesINFOAndTLSWait(t *testing.T) {
	for _, stage := range []string{"INFO", "TLS"} {
		t.Run(stage, func(t *testing.T) {
			config, _ := clientFixture(t, tls.VersionTLS13)
			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			config.Url = "tls://" + listener.Addr().String()
			plan, err := Admit(config)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan error, 1)
			go func() {
				connection, err := plan.Connect(ctx)
				if connection != nil {
					connection.Close()
				}
				result <- err
			}()
			peer, err := listener.Accept()
			if err != nil {
				t.Fatal(err)
			}
			defer peer.Close()
			if err := peer.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if stage == "TLS" {
				if _, err := io.WriteString(peer, "INFO {\"server_id\":\"test\",\"version\":\"2.14.6\",\"proto\":1,\"tls_required\":true,\"auth_required\":true,\"nonce\":\"test\",\"max_payload\":1048576}\r\n"); err != nil {
					t.Fatal(err)
				}
				header := make([]byte, 5)
				if _, err := io.ReadFull(peer, header); err != nil {
					t.Fatal(err)
				}
				if header[0] != 22 {
					t.Fatal("client did not enter TLS handshake")
				}
			}
			cancel()
			select {
			case err := <-result:
				if !errors.Is(err, context.Canceled) {
					t.Fatalf("canceled setup error=%v", err)
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("setup ignored cancellation after TCP accept")
			}
			if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := io.Copy(io.Discard, peer); err != nil {
				t.Fatalf("canceled socket was not closed: %v", err)
			}
		})
	}
}

func TestDNSDelayAndHandshakeShareAbsoluteBudget(t *testing.T) {
	config, _ := clientFixture(t, tls.VersionTLS13)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	accepted := make(chan net.Conn, 1)
	go func() {
		peer, err := listener.Accept()
		if err == nil {
			accepted <- peer
		}
	}()
	config.Url = "tls://worker.test:" + strconv.Itoa(listener.Addr().(*net.TCPAddr).Port)
	plan, err := Admit(config)
	if err != nil {
		t.Fatal(err)
	}
	dns, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer dns.Close()
	go func() {
		buffer := make([]byte, 4096)
		for {
			n, peer, err := dns.ReadFrom(buffer)
			if err != nil {
				return
			}
			var query dnsmessage.Message
			if query.Unpack(buffer[:n]) != nil {
				continue
			}
			response := dnsmessage.Message{Header: dnsmessage.Header{ID: query.ID, Response: true, RecursionAvailable: true}, Questions: query.Questions}
			for _, question := range query.Questions {
				if question.Type == dnsmessage.TypeA {
					response.Answers = append(response.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: question.Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET, TTL: 1}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, 1}}})
				}
			}
			data, err := response.Pack()
			if err == nil {
				dns.WriteTo(data, peer)
			}
		}
	}()
	var queried sync.Once
	observed := make(chan struct{})
	resolver := &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
		queried.Do(func() { close(observed) })
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(400 * time.Millisecond):
		}
		return (&net.Dialer{}).DialContext(ctx, "udp", dns.LocalAddr().String())
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	before := time.Now()
	connection, err := plan.connect(ctx, net.Dialer{Resolver: resolver})
	if connection != nil {
		connection.Close()
		t.Fatal("stalled server connected")
	}
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(before) > 850*time.Millisecond {
		t.Fatalf("dial and handshake restarted the deadline: %v after %v", err, time.Since(before))
	}
	select {
	case <-observed:
	default:
		t.Fatal("DNS bypassed context resolver")
	}
	select {
	case peer := <-accepted:
		defer peer.Close()
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := io.Copy(io.Discard, peer); err != nil {
			t.Fatalf("deadline socket not closed: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("DNS delay consumed test without reaching handshake")
	}
}

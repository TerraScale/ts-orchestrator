package natscell

import (
	"crypto/tls"
	"net"
	"strconv"
	"testing"
	"time"
)

func TestTLSFirstDialerReturnsNilConnectionOnFailedReconnect(t *testing.T) {
	closedPort := freeClientPort(t)
	dialer := &tlsFirstDialer{config: &tls.Config{MinVersion: tls.VersionTLS13}, timeout: 100 * time.Millisecond}
	conn, err := dialer.Dial("tcp", net.JoinHostPort("127.0.0.1", strconv.Itoa(closedPort)))
	if err == nil || conn != nil {
		if conn != nil {
			_ = conn.Close()
		}
		t.Fatalf("failed TLS reconnect returned connection %v and error %v", conn, err)
	}
}

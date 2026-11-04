package natscell

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/jwt/v2"
)

type rawLeaf struct {
	conn   net.Conn
	reader *bufio.Reader
}

func dialRawLeaf(ctx context.Context, t *testing.T, addr string, files TLSFiles, credsPath string) *rawLeaf {
	t.Helper()
	data, err := os.ReadFile(credsPath)
	if err != nil {
		t.Fatal(err)
	}
	userJWT, err := jwt.ParseDecoratedJWT(data)
	if err != nil {
		t.Fatal(err)
	}
	user, err := jwt.ParseDecoratedNKey(data)
	if err != nil {
		t.Fatal(err)
	}
	dialer := net.Dialer{Timeout: 5 * time.Second}
	plain, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	_ = plain.SetDeadline(time.Now().Add(10 * time.Second))
	line, err := bufio.NewReader(plain).ReadString('\n')
	if err != nil || !strings.HasPrefix(line, "INFO ") {
		t.Fatalf("leaf INFO = %q, %v", line, err)
	}
	var info struct {
		Nonce string `json:"nonce"`
	}
	if err := json.Unmarshal([]byte(strings.TrimPrefix(strings.TrimSpace(line), "INFO ")), &info); err != nil || info.Nonce == "" {
		t.Fatalf("leaf INFO nonce: %v", err)
	}
	config, err := loadTLS(files, false)
	if err != nil {
		t.Fatal(err)
	}
	config.ServerName = "127.0.0.1"
	secure := tls.Client(plain, config)
	if err := secure.HandshakeContext(ctx); err != nil {
		t.Fatal(err)
	}
	signature, err := user.Sign([]byte(info.Nonce))
	if err != nil {
		t.Fatal(err)
	}
	connect, err := json.Marshal(map[string]any{
		"version": "2.15.0", "jwt": userJWT, "sig": base64.RawURLEncoding.EncodeToString(signature),
		"name": "raw-leaf", "headers": true, "compress_mode": "off", "protocol": 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	leaf := &rawLeaf{conn: secure, reader: bufio.NewReader(secure)}
	if _, err := fmt.Fprintf(secure, "CONNECT %s\r\nPING\r\n", connect); err != nil {
		t.Fatal(err)
	}
	for {
		line, err := leaf.reader.ReadString('\n')
		if err != nil {
			t.Fatalf("raw leaf handshake: %v", err)
		}
		switch {
		case strings.HasPrefix(line, "PONG"):
			_ = secure.SetDeadline(time.Time{})
			return leaf
		case strings.HasPrefix(line, "-ERR"):
			t.Fatalf("hub refused the raw leaf credential: %s", line)
		case strings.HasPrefix(line, "PING"):
			_, _ = io.WriteString(secure, "PONG\r\n")
		}
	}
}

func (l *rawLeaf) publish(t *testing.T, subject, reply string, payload []byte) {
	t.Helper()
	header := "LMSG " + subject
	if reply != "" {
		header += " " + reply
	}
	if _, err := fmt.Fprintf(l.conn, "%s %d\r\n%s\r\nPING\r\n", header, len(payload), payload); err != nil &&
		!errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
}

// awaitClose reads until the hub closes the link and returns its last -ERR.
func (l *rawLeaf) awaitClose(t *testing.T) string {
	t.Helper()
	defer l.close()
	_ = l.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	reason := ""
	for {
		line, err := l.reader.ReadString('\n')
		if strings.HasPrefix(line, "-ERR") {
			reason = strings.TrimSpace(line)
		}
		if strings.HasPrefix(line, "PING") {
			_, _ = io.WriteString(l.conn, "PONG\r\n")
		}
		if err != nil {
			var timeout net.Error
			if errors.As(err, &timeout) && timeout.Timeout() {
				return "link stayed open; last error " + reason
			}
			return reason
		}
	}
}

func (l *rawLeaf) close() { _ = l.conn.Close() }

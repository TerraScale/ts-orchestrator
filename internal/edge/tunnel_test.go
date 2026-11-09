package edge

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestTerraBaseLoopbackRelaysExtendedConnectWebSocketsBesideREST(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	upstream := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			_, _ = io.WriteString(w, "rest "+r.Host+r.URL.RequestURI())
			return
		}
		if r.Header.Get(":protocol") != "websocket" || r.Host != terrabaseLoopback || r.URL.RequestURI() != "/v1/sql/socket?db=main" ||
			r.Header.Get("Sec-WebSocket-Protocol") != "terrabase.sql" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		w.Header().Set("Sec-WebSocket-Protocol", "terrabase.sql")
		w.WriteHeader(http.StatusOK)
		flusher := http.NewResponseController(w)
		_ = flusher.Flush()
		frames := bufio.NewReader(r.Body)
		for {
			message, err := readWebSocketFrame(frames)
			if errors.Is(err, io.EOF) {
				_ = writeWebSocketFrame(w, "closed", false)
				return
			}
			if err != nil || writeWebSocketFrame(w, "echo "+message, false) != nil || flusher.Flush() != nil {
				return
			}
		}
	}))
	upstream.Config.Protocols = new(http.Protocols)
	upstream.Config.Protocols.SetUnencryptedHTTP2(true)
	upstream.Start()
	defer upstream.Close()
	e := New(t.TempDir())
	e.terrabase = func() (string, error) { return upstream.Listener.Addr().String(), nil }
	ln := listen(t)
	go func() { _ = e.serveRegionalInternal(ln) }()
	dial := func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, ln.Addr().String())
	}

	protocols := new(http.Protocols)
	protocols.SetUnencryptedHTTP2(true)
	rest := &http.Client{Transport: &http.Transport{Protocols: protocols, DialContext: dial}}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, "http://"+terrabaseLoopback+"/v1/databases?limit=1", nil)
	response, err := rest.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK || string(body) != "rest "+terrabaseLoopback+"/v1/databases?limit=1" {
		t.Fatalf("REST = %d %q", response.StatusCode, body)
	}

	upload, send := io.Pipe()
	request, _ = http.NewRequestWithContext(ctx, http.MethodConnect, "http://"+terrabaseLoopback+"/v1/sql/socket?db=main", upload)
	request.Header.Set(":protocol", "websocket")
	request.Header.Set("Sec-WebSocket-Version", "13")
	request.Header.Set("Sec-WebSocket-Protocol", "terrabase.sql")
	response, err = tunnelTransport{dial: dial}.RoundTrip(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.Header.Get("Sec-WebSocket-Protocol") != "terrabase.sql" {
		t.Fatalf("extended CONNECT = %d %v", response.StatusCode, response.Header)
	}
	frames := bufio.NewReader(response.Body)
	for _, message := range []string{"select 1", "select 2"} {
		if err := writeWebSocketFrame(send, message, true); err != nil {
			t.Fatal(err)
		}
		if reply, err := readWebSocketFrame(frames); err != nil || reply != "echo "+message {
			t.Fatalf("reply = %q, %v", reply, err)
		}
	}
	send.Close()
	if reply, err := readWebSocketFrame(frames); err != nil || reply != "closed" {
		t.Fatalf("after half-close = %q, %v", reply, err)
	}
	if _, err := frames.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("stream end = %v", err)
	}
}

func writeWebSocketFrame(w io.Writer, message string, masked bool) error {
	payload := []byte(message)
	frame := []byte{0x81, byte(len(payload))}
	if masked {
		mask := [4]byte{7, 1, 3, 9}
		frame[1] |= 0x80
		frame = append(frame, mask[:]...)
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
	}
	_, err := w.Write(append(frame, payload...))
	return err
}

func readWebSocketFrame(r *bufio.Reader) (string, error) {
	head := make([]byte, 2)
	if _, err := io.ReadFull(r, head); err != nil {
		return "", err
	}
	var mask []byte
	if head[1]&0x80 != 0 {
		mask = make([]byte, 4)
		if _, err := io.ReadFull(r, mask); err != nil {
			return "", err
		}
	}
	payload := make([]byte, head[1]&0x7f)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", err
	}
	for i := range payload {
		if mask != nil {
			payload[i] ^= mask[i%4]
		}
	}
	return string(payload), nil
}

package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/edge"
	"github.com/TerraScale/ts-orchestrator/internal/observability"
)

const failAfter = 10 * time.Second

var started = time.Now()

func step(name string, err error) {
	if err != nil {
		fmt.Printf("FAIL %s after %s: %v\n", name, time.Since(started).Round(time.Millisecond), err)
		os.Exit(1)
	}
	fmt.Printf("ok %s at %s\n", name, time.Since(started).Round(time.Millisecond))
}

func main() {
	if len(os.Args) == 5 {
		limitsMain()
		return
	}
	state, caPath, host := os.Args[1], os.Args[2], os.Args[3]
	pem, err := os.ReadFile(caPath)
	roots := x509.NewCertPool()
	if err == nil && !roots.AppendCertsFromPEM(pem) {
		err = fmt.Errorf("no certificate in %s", caPath)
	}
	step("ca", err)
	backend, err := net.Listen("tcp", "127.0.0.1:0")
	step("backend", err)
	go serveBackend(backend)
	port := backend.Addr().(*net.TCPAddr).Port
	public := edge.New(state)
	public.SetServiceRoutes(map[string]int{}, map[string]int{host: port}, map[string]string{}, nil)
	errCh := make(chan error, 1)
	go func() { errCh <- public.Run(context.Background()) }()
	step("edge postgres listener", waitListening(errCh))
	attacker := net.ParseIP("198.18.1.1")
	victim := net.ParseIP("198.18.2.1")
	sessionIP := net.ParseIP("198.18.3.1")
	otherV6 := net.ParseIP("2001:db8:121::1")
	session, err := connect(sessionIP, host, roots)
	step("authenticated session", err)
	step("first query", query(session))
	step("idle", runPhase("idle", attacker, 32, nil, 0, session, victim, otherV6, host, roots))
	step("tls stall", runPhase("tls stall", attacker, 32, stallTLS, 0, session, victim, otherV6, host, roots))
	step("startup silence", runPhase("startup silence", attacker, 32, func(c net.Conn) error {
		_, err := negotiateTLS(c, host, roots)
		return err
	}, 0, session, victim, otherV6, host, roots))
	step("200 from one address", runPhase("200 ipv4", attacker, 200, nil, 168, session, victim, otherV6, host, roots))
	v6 := make([]net.IP, 200)
	for i := range v6 {
		v6[i] = net.ParseIP(fmt.Sprintf("2001:db8:120::%x", i+1))
	}
	step("200 from one ipv6 prefix", runMany(v6, 168, session, victim, otherV6, host, roots))
	step("session after the flood", query(session))
	step("close session", session.Close())
}

func waitListening(errCh <-chan error) error {
	deadline := time.Now().Add(failAfter)
	want := observability.Series("ts_orch_edge_listener_ready", "protocol", "postgres") + " 1\n"
	for time.Now().Before(deadline) {
		select {
		case err := <-errCh:
			if err == nil {
				err = errors.New("edge stopped")
			}
			return err
		default:
		}
		var metrics strings.Builder
		observability.WriteEdgeListenerMetrics(&metrics)
		if strings.Contains(metrics.String(), want) {
			return nil
		}
		runtime.Gosched()
	}
	return errors.New("postgres listener not ready")
}

func runPhase(name string, ip net.IP, n int, setup func(net.Conn) error, refused int, session *tls.Conn, victim, otherV6 net.IP, host string, roots *x509.CertPool) error {
	beforeSource, beforeGlobal, err := counters()
	if err != nil {
		return err
	}
	conns, err := hold(n, func() (net.Conn, error) { return dial(ip) }, setup)
	if err != nil {
		return err
	}
	err = assertCap(name, ip, n-refused, refused, beforeSource, beforeGlobal, session, victim, otherV6, host, roots)
	closeAll(conns)
	if err != nil {
		return err
	}
	return waitSample(inFlightSeries(), 0)
}

func runMany(ips []net.IP, refused int, session *tls.Conn, victim, otherV6 net.IP, host string, roots *x509.CertPool) error {
	beforeSource, beforeGlobal, err := counters()
	if err != nil {
		return err
	}
	next := 0
	conns, err := hold(len(ips), func() (net.Conn, error) {
		conn, dialErr := dial(ips[next])
		next++
		return conn, dialErr
	}, nil)
	if err != nil {
		closeAll(conns)
		return err
	}
	err = assertCap("ipv6 prefix", ips[0], len(ips)-refused, refused, beforeSource, beforeGlobal, session, victim, otherV6, host, roots)
	closeAll(conns)
	if err != nil {
		return err
	}
	return waitSample(inFlightSeries(), 0)
}

func counters() (int, int, error) {
	source, err := sample(sourceSeries())
	if err != nil {
		return 0, 0, err
	}
	global, err := sample(globalSeries())
	return source, global, err
}

func assertCap(name string, probe net.IP, held, refused, beforeSource, beforeGlobal int, session *tls.Conn, victim, otherV6 net.IP, host string, roots *x509.CertPool) error {
	if err := waitSample(inFlightSeries(), held); err != nil {
		return fmt.Errorf("%s hold: %w", name, err)
	}
	if err := waitSample(sourceSeries(), beforeSource+refused); err != nil {
		return fmt.Errorf("%s refusals: %w", name, err)
	}
	if err := waitSample(inFlightSeries(), held); err != nil {
		return fmt.Errorf("%s held: %w", name, err)
	}
	if err := refusedState(probe); err != nil {
		return fmt.Errorf("%s extra: %w", name, err)
	}
	if err := waitSample(sourceSeries(), beforeSource+refused+1); err != nil {
		return fmt.Errorf("%s probe: %w", name, err)
	}
	afterGlobal, err := sample(globalSeries())
	if err != nil {
		return err
	}
	if afterGlobal != beforeGlobal {
		return fmt.Errorf("%s global refusals %d to %d", name, beforeGlobal, afterGlobal)
	}
	if err := query(session); err != nil {
		return fmt.Errorf("%s session: %w", name, err)
	}
	if err := freshQuery(victim, host, roots); err != nil {
		return fmt.Errorf("%s victim: %w", name, err)
	}
	if err := freshQuery(otherV6, host, roots); err != nil {
		return fmt.Errorf("%s other prefix: %w", name, err)
	}
	return nil
}

func hold(n int, open func() (net.Conn, error), setup func(net.Conn) error) ([]net.Conn, error) {
	conns := make([]net.Conn, 0, n)
	for range n {
		conn, err := open()
		if err != nil {
			closeAll(conns)
			return nil, err
		}
		if setup != nil {
			if err := setup(conn); err != nil {
				conn.Close()
				closeAll(conns)
				return nil, err
			}
		}
		conns = append(conns, conn)
	}
	return conns, nil
}

func closeAll(conns []net.Conn) {
	for _, conn := range conns {
		conn.Close()
	}
}

func stallTLS(conn net.Conn) error {
	_, err := conn.Write([]byte{0x16})
	return err
}

func refusedState(ip net.IP) error {
	conn, err := dial(ip)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(failAfter))
	state, err := readSQLState(conn)
	if err != nil {
		return err
	}
	if state != "53300" {
		return fmt.Errorf("sqlstate %s", state)
	}
	return nil
}

func freshQuery(ip net.IP, host string, roots *x509.CertPool) error {
	conn, err := connect(ip, host, roots)
	if err != nil {
		return err
	}
	defer conn.Close()
	return query(conn)
}

func connect(ip net.IP, host string, roots *x509.CertPool) (*tls.Conn, error) {
	raw, err := dial(ip)
	if err != nil {
		return nil, err
	}
	conn, err := negotiateTLS(raw, host, roots)
	if err != nil {
		raw.Close()
		return nil, err
	}
	if _, err := conn.Write(startup()); err != nil {
		conn.Close()
		return nil, err
	}
	if _, err := readUntilReady(conn); err != nil {
		conn.Close()
		return nil, err
	}
	_ = conn.SetDeadline(time.Time{})
	return conn, nil
}

func negotiateTLS(conn net.Conn, host string, roots *x509.CertPool) (*tls.Conn, error) {
	_ = conn.SetDeadline(time.Now().Add(failAfter))
	var req [8]byte
	binary.BigEndian.PutUint32(req[:4], 8)
	binary.BigEndian.PutUint32(req[4:], 80877103)
	if _, err := conn.Write(req[:]); err != nil {
		return nil, err
	}
	var ans [1]byte
	if _, err := io.ReadFull(conn, ans[:]); err != nil {
		return nil, err
	}
	if ans[0] != 'S' {
		return nil, fmt.Errorf("ssl answer %q", ans[0])
	}
	tlsConn := tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		return nil, err
	}
	return tlsConn, nil
}

func startup() []byte {
	params := "user\x00preauth\x00database\x00preauth\x00\x00"
	body := make([]byte, 4+len(params))
	binary.BigEndian.PutUint32(body[:4], 196608)
	copy(body[4:], params)
	msg := binary.BigEndian.AppendUint32(nil, uint32(4+len(body)))
	return append(msg, body...)
}

func query(conn net.Conn) error {
	sql := "SELECT 1\x00"
	msg := append([]byte{'Q'}, binary.BigEndian.AppendUint32(nil, uint32(4+len(sql)))...)
	msg = append(msg, sql...)
	if _, err := conn.Write(msg); err != nil {
		return err
	}
	body, err := readUntilReady(conn)
	if err != nil {
		return err
	}
	if !bytes.Contains(body, []byte("preauth-ok")) {
		return fmt.Errorf("result %q", body)
	}
	return nil
}

func readUntilReady(r io.Reader) ([]byte, error) {
	var all []byte
	for {
		var head [5]byte
		if _, err := io.ReadFull(r, head[:]); err != nil {
			return all, err
		}
		n := binary.BigEndian.Uint32(head[1:])
		if n < 4 || n > 1<<20 {
			return all, fmt.Errorf("message %d", n)
		}
		body := make([]byte, n-4)
		if _, err := io.ReadFull(r, body); err != nil {
			return all, err
		}
		all = append(all, head[:]...)
		all = append(all, body...)
		switch head[0] {
		case 'Z':
			return all, nil
		case 'E':
			return all, errors.New(sqlState(body))
		}
	}
}

func readSQLState(r io.Reader) (string, error) {
	var head [5]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return "", err
	}
	if head[0] != 'E' {
		return "", fmt.Errorf("byte %q", head[0])
	}
	n := binary.BigEndian.Uint32(head[1:])
	if n < 4 || n > 1<<16 {
		return "", fmt.Errorf("error length %d", n)
	}
	body := make([]byte, n-4)
	if _, err := io.ReadFull(r, body); err != nil {
		return "", err
	}
	state := sqlState(body)
	if state == "" {
		return "", errors.New("no sqlstate")
	}
	return state, nil
}

func sqlState(body []byte) string {
	for len(body) > 0 && body[0] != 0 {
		kind := body[0]
		body = body[1:]
		end := bytes.IndexByte(body, 0)
		if end < 0 {
			return ""
		}
		if kind == 'C' {
			return string(body[:end])
		}
		body = body[end+1:]
	}
	return ""
}

func dial(ip net.IP) (net.Conn, error) {
	if v4 := ip.To4(); v4 != nil {
		return (&net.Dialer{LocalAddr: &net.TCPAddr{IP: v4}}).Dial("tcp4", "127.0.0.1:5432")
	}
	return (&net.Dialer{LocalAddr: &net.TCPAddr{IP: ip}}).Dial("tcp6", "[::1]:5432")
}

func inFlightSeries() string { return "ts_orch_edge_postgres_preauth_handshakes" }

func sourceSeries() string {
	return observability.Series("ts_orch_edge_postgres_preauth_refusals_total", "reason", "source")
}

func globalSeries() string {
	return observability.Series("ts_orch_edge_postgres_preauth_refusals_total", "reason", "global")
}

func sample(series string) (int, error) {
	var body strings.Builder
	edge.WritePostgresPreauthMetrics(&body)
	prefix := series + " "
	for _, line := range strings.Split(body.String(), "\n") {
		if strings.HasPrefix(line, prefix) {
			return strconv.Atoi(strings.TrimPrefix(line, prefix))
		}
	}
	return 0, fmt.Errorf("missing %s", series)
}

func waitSample(series string, want int) error {
	deadline := time.Now().Add(failAfter)
	var got int
	var err error
	for time.Now().Before(deadline) {
		got, err = sample(series)
		if err == nil && got == want {
			return nil
		}
		runtime.Gosched()
	}
	if err != nil {
		return err
	}
	return fmt.Errorf("%s = %d, want %d", series, got, want)
}

func serveBackend(ln net.Listener) {
	for {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		go handleBackend(conn)
	}
}

func handleBackend(conn net.Conn) {
	defer conn.Close()
	if err := discardProxy(conn); err != nil {
		return
	}
	if err := discardStartup(conn); err != nil {
		return
	}
	if _, err := conn.Write(authOK()); err != nil {
		return
	}
	for {
		var head [5]byte
		if _, err := io.ReadFull(conn, head[:]); err != nil {
			return
		}
		n := binary.BigEndian.Uint32(head[1:])
		if n < 4 {
			return
		}
		payload := make([]byte, n-4)
		if _, err := io.ReadFull(conn, payload); err != nil {
			return
		}
		if head[0] != 'Q' {
			return
		}
		if string(payload) == "SELECT edge_slow\x00" {
			<-time.NewTimer(10*time.Minute + time.Second).C
		}
		if string(payload) == "COPY edge_stream\x00" {
			if err := copyBackend(conn); err != nil {
				return
			}
			continue
		}
		if _, err := conn.Write(queryResponse()); err != nil {
			return
		}
	}
}

func discardProxy(r io.Reader) error {
	var head [16]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint16(head[14:16])
	_, err := io.CopyN(io.Discard, r, int64(n))
	return err
}

func discardStartup(r io.Reader) error {
	var head [4]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return err
	}
	n := binary.BigEndian.Uint32(head[:])
	if n < 4 {
		return errors.New("short startup")
	}
	_, err := io.CopyN(io.Discard, r, int64(n-4))
	return err
}

func authOK() []byte {
	var b []byte
	b = append(b, 'R')
	b = binary.BigEndian.AppendUint32(b, 8)
	b = binary.BigEndian.AppendUint32(b, 0)
	b = append(b, 'K')
	b = binary.BigEndian.AppendUint32(b, 12)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = binary.BigEndian.AppendUint32(b, 1)
	b = append(b, 'Z')
	b = binary.BigEndian.AppendUint32(b, 5)
	b = append(b, 'I')
	return b
}

func queryResponse() []byte {
	field := append([]byte("result"), 0)
	field = binary.BigEndian.AppendUint32(field, 0)
	field = binary.BigEndian.AppendUint16(field, 0)
	field = binary.BigEndian.AppendUint32(field, 25)
	field = binary.BigEndian.AppendUint16(field, 0xffff)
	field = binary.BigEndian.AppendUint32(field, 0xffffffff)
	field = binary.BigEndian.AppendUint16(field, 0)
	rdBody := binary.BigEndian.AppendUint16(nil, 1)
	rdBody = append(rdBody, field...)
	rd := append([]byte{'T'}, binary.BigEndian.AppendUint32(nil, uint32(4+len(rdBody)))...)
	rd = append(rd, rdBody...)
	value := []byte("preauth-ok")
	drBody := binary.BigEndian.AppendUint16(nil, 1)
	drBody = binary.BigEndian.AppendUint32(drBody, uint32(len(value)))
	drBody = append(drBody, value...)
	dr := append([]byte{'D'}, binary.BigEndian.AppendUint32(nil, uint32(4+len(drBody)))...)
	dr = append(dr, drBody...)
	tag := "SELECT 1\x00"
	cc := append([]byte{'C'}, binary.BigEndian.AppendUint32(nil, uint32(4+len(tag)))...)
	cc = append(cc, tag...)
	ready := []byte{'Z', 0, 0, 0, 5, 'I'}
	return append(append(append(rd, dr...), cc...), ready...)
}

func copyBackend(conn net.Conn) error {
	frame := func(kind byte, body []byte) error {
		header := append([]byte{kind}, binary.BigEndian.AppendUint32(nil, uint32(4+len(body)))...)
		if _, err := conn.Write(header); err != nil {
			return err
		}
		_, err := conn.Write(body)
		return err
	}
	if err := frame('H', []byte{0, 0, 0}); err != nil {
		return err
	}
	if err := frame('d', make([]byte, (1<<20)+1)); err != nil {
		return err
	}
	tick := time.NewTicker(2 * time.Second)
	defer tick.Stop()
	finish := time.NewTimer(10*time.Minute + time.Second)
	defer finish.Stop()
	for {
		select {
		case <-tick.C:
			if err := frame('d', []byte("copy")); err != nil {
				return err
			}
		case <-finish.C:
			if err := frame('c', nil); err != nil {
				return err
			}
			if err := frame('C', []byte("COPY 1\x00")); err != nil {
				return err
			}
			return frame('Z', []byte{'I'})
		}
	}
}

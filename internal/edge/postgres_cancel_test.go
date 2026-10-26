package edge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net"
	"net/http"
	"testing"
	"time"
)

func TestPostgresCancellationFindsUniqueOwnerOverMeshAndRejectsStaleGeneration(t *testing.T) {
	t.Parallel()
	regions := startRegions(t, terraBase, "ams")
	port, got, headers := echoBackend(t)
	key := [8]byte{0, 0, 0, 42, 0, 0, 0, 7}
	owner, ingress := regions["ams"].edge, regions["fra"].edge
	release, err := owner.pgKeys.add(key, port)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	request := append(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 16}, cancelRequest), key[:]...)
	var packet []byte
	for _, ip := range []net.IP{net.IPv4(203, 0, 113, 7), net.ParseIP("2001:db8::7")} {
		address := &net.TCPAddr{IP: ip, Port: 54321}
		header := proxyHeader(address, address)
		packet = append(header, request...)
		ingress.forwardCancel(packet)
		select {
		case body := <-got:
			if !bytes.Equal(body, request) || !bytes.Equal(<-headers, header) {
				t.Fatal("wrong backend cancellation or client address")
			}
		case <-time.After(10 * time.Second):
			t.Fatal("remote owner did not receive cancellation")
		}
	}
	id, count := owner.pgKeys.find(sha256.Sum256(key[:]))
	if count != 1 {
		t.Fatal("live owner missing")
	}
	release()
	replacement, err := owner.pgKeys.add(key, port)
	if err != nil {
		t.Fatal(err)
	}
	defer replacement()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	status, _ := ingress.postgresCancelCall(ctx, "ams", "dispatch", append(id[:], packet...))
	if status != http.StatusNotFound {
		t.Fatal("stale connection generation accepted")
	}
	// A digest can locate an owner but cannot authorize dispatch without its full key.
	status, _ = ingress.postgresCancelCall(ctx, "ams", "dispatch", sha256Digest(key))
	if status != http.StatusBadRequest {
		t.Fatal("digest authorized cancellation")
	}
	id, _ = owner.pgKeys.find(sha256.Sum256(key[:]))
	wrong := bytes.Clone(packet)
	wrong[len(wrong)-1] ^= 1
	status, _ = ingress.postgresCancelCall(ctx, "ams", "dispatch", append(id[:], wrong...))
	if status != http.StatusNotFound || len(got) != 0 || len(headers) != 0 {
		t.Fatal("incorrect full key authorized backend delivery")
	}
	public, err := http.Post(regions["ams"].public.URL+postgresCancelPath+"lookup", "application/octet-stream", bytes.NewReader(sha256Digest(key)))
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, public.Body)
	public.Body.Close()
	if public.StatusCode != http.StatusNotFound {
		t.Fatal("public control endpoint exposed")
	}
}

func sha256Digest(key [8]byte) []byte { sum := sha256.Sum256(key[:]); return sum[:] }

func TestPostgresCancellationRejectsAmbiguousOwnersAndIncompleteDiscovery(t *testing.T) {
	t.Parallel()
	regions := startRegions(t, terraBase, "ams")
	key := [8]byte{1}
	port, _, _ := echoBackend(t)
	one, _ := regions["gru"].edge.pgKeys.add(key, port)
	two, _ := regions["ams"].edge.pgKeys.add(key, port)
	defer one()
	defer two()
	packet := append(binary.BigEndian.AppendUint32([]byte{0, 0, 0, 16}, cancelRequest), key[:]...)
	packet = append(proxyHeader(nil, nil), packet...)
	if regions["fra"].edge.relayPostgresCancel(packet, key) {
		t.Fatal("ambiguous ownership dispatched cancellation")
	}
	two()
	regions["ams"].stop()
	if regions["fra"].edge.relayPostgresCancel(packet, key) {
		t.Fatal("incomplete ownership discovery dispatched cancellation")
	}
}

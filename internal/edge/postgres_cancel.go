package edge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"io"
	"net/http"
	"slices"
	"time"
)

const postgresCancelPath = "/__ts_orch/postgres/cancel/"

// The lookup carries only a digest. The cancellation secret goes only to the
// unique live owner, over mesh mTLS, with a generation that cannot survive reconnect.
func (e *Edge) relayPostgresCancel(packet []byte, key [8]byte) bool {
	select {
	case e.pgRelays <- struct{}{}:
		defer func() { <-e.pgRelays }()
	default:
		return false
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	m := e.meshNode()
	regions := m.AdmittedRegions()
	if len(regions) > 32 {
		return false
	}
	digest := sha256.Sum256(key[:])
	id, matches := e.pgKeys.find(digest)
	owner := m.Region()
	type answer struct {
		region   string
		id       [16]byte
		matches  int
		complete bool
	}
	answers := make(chan answer, len(regions))
	pending := 0
	for _, region := range regions {
		if region == m.Region() {
			continue
		}
		pending++
		go func() {
			status, body := e.postgresCancelCall(ctx, region, "lookup", digest[:])
			a := answer{region: region, complete: status == http.StatusNotFound || status == http.StatusOK && len(body) == 16}
			if status == http.StatusOK && len(body) == 16 {
				a.id = [16]byte(body)
				a.matches = 1
			}
			answers <- a
		}()
	}
	for range pending {
		a := <-answers
		if !a.complete {
			return false
		}
		matches += a.matches
		if a.matches == 1 {
			owner, id = a.region, a.id
		}
	}
	if matches != 1 || !slices.Equal(regions, m.AdmittedRegions()) {
		return false
	}
	if owner == m.Region() {
		if port, ok := e.pgKeys.resolve(key, id); ok {
			return e.sendPostgresCancel(port, packet)
		}
		return false
	}
	status, _ := e.postgresCancelCall(ctx, owner, "dispatch", append(id[:], packet...))
	return status == http.StatusOK
}

func (e *Edge) postgresCancelCall(ctx context.Context, region, action string, body []byte) (int, []byte) {
	r, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+e.peerAddr(region)+postgresCancelPath+action, bytes.NewReader(body))
	if err != nil {
		return 0, nil
	}
	resp, err := e.peers.RoundTrip(r)
	if err != nil {
		return 0, nil
	}
	defer resp.Body.Close()
	answer, err := io.ReadAll(io.LimitReader(resp.Body, 17))
	if err != nil || len(answer) > 16 {
		return 0, nil
	}
	return resp.StatusCode, answer
}

func (e *Edge) servePostgresCancel(w http.ResponseWriter, r *http.Request) {
	if !fromPeer(r) || r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}
	select {
	case e.pgControl <- struct{}{}:
		defer func() { <-e.pgControl }()
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	control := http.NewResponseController(w)
	control.SetReadDeadline(time.Now().Add(3 * time.Second))
	control.SetWriteDeadline(time.Now().Add(3 * time.Second))
	defer control.SetReadDeadline(time.Time{})
	defer control.SetWriteDeadline(time.Time{})
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 84))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	switch r.URL.Path {
	case postgresCancelPath + "lookup":
		if len(body) != 32 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		id, count := e.pgKeys.find([32]byte(body))
		if count != 1 {
			if count == 0 {
				w.WriteHeader(http.StatusNotFound)
			} else {
				w.WriteHeader(http.StatusConflict)
			}
			return
		}
		w.Write(id[:])
	case postgresCancelPath + "dispatch":
		if len(body) < 48 {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		packet := body[16:]
		header := 16 + int(binary.BigEndian.Uint16(packet[14:16]))
		if header+16 != len(packet) || !bytes.Equal(packet[:12], []byte("\r\n\r\n\x00\r\nQUIT\n")) ||
			binary.BigEndian.Uint32(packet[header:]) != 16 || binary.BigEndian.Uint32(packet[header+4:]) != cancelRequest {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		port, ok := e.pgKeys.resolve([8]byte(packet[len(packet)-8:]), [16]byte(body[:16]))
		if !ok {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		if !e.sendPostgresCancel(port, packet) {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	default:
		http.NotFound(w, r)
	}
}

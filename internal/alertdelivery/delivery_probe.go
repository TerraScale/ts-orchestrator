package alertdelivery

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofrs/flock"
)

type deliveryProbe struct {
	path    string
	pending chan struct{}
}

type deliveryProbeState struct {
	Next      time.Time `json:"next"`
	Completed time.Time `json:"completed"`
}

func probeTopic(secret string) string {
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write([]byte("terrascale-alert-delivery-probe-v1"))
	return "ts-probe-" + hex.EncodeToString(mac.Sum(nil))
}

func (p *deliveryProbe) start(ctx context.Context, r relay) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	if err := p.complete(ctx, r); err != nil {
		slog.WarnContext(ctx, "Alert delivery probe incomplete")
	}
}

func (p *deliveryProbe) complete(ctx context.Context, r relay) error {
	lock := flock.New(p.path + ".lock")
	locked, err := lock.TryLock()
	if err != nil {
		return err
	}
	if !locked {
		return nil
	}
	defer lock.Unlock()
	state, err := p.load()
	if err != nil {
		return err
	}
	if time.Now().Before(state.Next) {
		return nil
	}
	state.Next = time.Now().Add(5 * time.Minute)
	if err := p.save(state); err != nil {
		return err
	}
	secret, err := r.readTopic(ctx)
	if err != nil || !validPushTopic(secret) {
		return errors.New("probe credentials unavailable")
	}
	topic := probeTopic(secret)
	if topic == secret {
		return errors.New("probe topic conflicts")
	}
	nonce := make([]byte, 16)
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	message := hex.EncodeToString(nonce)
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, r.pushEndpoint+topic, strings.NewReader(message))
	if err != nil {
		return err
	}
	response, err := r.client.Do(request)
	if err != nil {
		return errors.New("probe publish failed")
	}
	data, readErr := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	response.Body.Close()
	var published struct {
		ID      string `json:"id"`
		Event   string `json:"event"`
		Topic   string `json:"topic"`
		Message string `json:"message"`
	}
	if response.StatusCode != http.StatusOK || readErr != nil || len(data) > 64<<10 || json.Unmarshal(data, &published) != nil || published.ID == "" || published.Event != "message" || published.Topic != topic || published.Message != message {
		return errors.New("probe publish rejected")
	}
	request, err = http.NewRequestWithContext(ctx, http.MethodGet, r.pushEndpoint+topic+"/json?poll=1&since=5m&message="+message, nil)
	if err != nil {
		return err
	}
	response, err = r.client.Do(request)
	if err != nil {
		return errors.New("probe read failed")
	}
	defer response.Body.Close()
	data, err = io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if response.StatusCode != http.StatusOK || err != nil || len(data) > 64<<10 {
		return errors.New("probe read rejected")
	}
	for _, line := range strings.Split(string(data), "\n") {
		var received struct {
			ID      string `json:"id"`
			Event   string `json:"event"`
			Topic   string `json:"topic"`
			Message string `json:"message"`
		}
		if json.Unmarshal([]byte(line), &received) == nil && received.ID == published.ID && received.Event == "message" && received.Topic == topic && received.Message == message {
			state.Completed = time.Now()
			return p.save(state)
		}
	}
	return errors.New("probe message not received")
}

func (p *deliveryProbe) load() (deliveryProbeState, error) {
	data, err := os.ReadFile(p.path)
	if errors.Is(err, os.ErrNotExist) {
		return deliveryProbeState{}, nil
	}
	if err != nil {
		return deliveryProbeState{}, err
	}
	var state deliveryProbeState
	err = json.Unmarshal(data, &state)
	return state, err
}

func (p *deliveryProbe) save(state deliveryProbeState) error {
	return saveObservation(p.path, state)
}

func (p *deliveryProbe) write(w io.Writer) {
	state, err := p.load()
	completed := int64(0)
	if err == nil && !state.Completed.IsZero() && !state.Completed.After(time.Now()) {
		completed = state.Completed.Unix()
	}
	fmt.Fprintf(w, "terrascale_alert_delivery_probe_completed_timestamp_seconds %d\n", completed)
}

func (p *deliveryProbe) signal() {
	select {
	case p.pending <- struct{}{}:
	default:
	}
}

func (p *deliveryProbe) run(ctx context.Context, r relay) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-p.pending:
			p.start(ctx, r)
		}
	}
}

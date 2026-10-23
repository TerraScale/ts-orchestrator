package alertdelivery

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/vaultsecret"
	"github.com/mattn/go-isatty"
)

// Reject short topics and characters that could escape a URL path or terminal line.
var pushTopicRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43,128}$`)

func validPushTopic(topic string) bool { return pushTopicRE.MatchString(topic) }

func readPushTopic(ctx context.Context) (string, error) {
	values, err := vaultsecret.ReadInstanceSecrets(ctx, "ts-alerts", map[string]vaultsecret.Ref{
		"TS_ALERTS_NTFY_TOPIC_FILE": {Vault: vaultsecret.SharedVault, Name: "gru-1-ts-alerts-ntfy-topic"},
	})
	topic := values["TS_ALERTS_NTFY_TOPIC_FILE"]
	if err != nil || !validPushTopic(topic) {
		return "", errors.New("push Vault topic unavailable or invalid")
	}
	return topic, nil
}

func (r relay) subscribe(ctx context.Context) error {
	// Refuse redirected use before reading any secret, even with a controlling TTY.
	if !isatty.IsTerminal(os.Stdin.Fd()) || !isatty.IsTerminal(os.Stdout.Fd()) {
		return errors.New("subscribe requires an interactive terminal; use ssh -t")
	}
	terminal, err := os.OpenFile("/dev/tty", os.O_RDWR, 0)
	if err != nil {
		return errors.New("subscribe requires a controlling terminal")
	}
	defer terminal.Close()
	readCtx, cancel := context.WithTimeout(ctx, 20*time.Second)
	topic, err := r.readTopic(readCtx)
	cancel()
	if err != nil || !validPushTopic(topic) {
		return errors.New("push Vault topic unavailable or invalid")
	}
	client := &http.Client{Timeout: 55 * time.Second, Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	return confirmSubscription(ctx, terminal, topic, client)
}

func confirmSubscription(ctx context.Context, terminal io.ReadWriter, topic string, client *http.Client) error {
	if !validPushTopic(topic) {
		return errors.New("push Vault topic invalid")
	}
	if _, err := fmt.Fprintf(terminal, "Private topic: %s\nSubscribe: https://ntfy.sh/%s\nKeep this link private. Subscribe in ntfy, then press Enter to send one test alert: ", topic, topic); err != nil {
		return errors.New("subscription terminal unavailable")
	}
	if _, err := bufio.NewReader(terminal).ReadString('\n'); err != nil {
		return errors.New("subscription confirmation canceled; no test sent")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://127.0.0.1:9094/alerts", strings.NewReader(`{"status":"firing","alerts":[{"status":"firing","labels":{"alertname":"SubscriptionTest","service":"ts-alerts","region":"gru","severity":"info"}}]}`))
	if err != nil {
		return errors.New("subscription test request failed")
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return errors.New("subscription test relay unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		return errors.New("subscription test not accepted by both providers; inspect relay health and retry")
	}
	_, err = io.WriteString(terminal, "Test accepted by email and push providers. Check your ntfy client and email for receipt.\n")
	if err != nil {
		return errors.New("subscription terminal unavailable")
	}
	return nil
}

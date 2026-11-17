package releasepush

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/protocol"
	"github.com/nats-io/nats.go"
)

type Region struct {
	Region string `json:"region"`
}

func LoadRegions(path string) ([]Region, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var regions []Region
	if err := protocol.DecodeStrict(data, &regions, 64<<10); err != nil || len(regions) == 0 {
		return nil, fmt.Errorf("%s: %w", path, errors.Join(err, errors.New("needs at least one region")))
	}
	return regions, nil
}

func fileSHA256(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

func MintToken(ctx context.Context) (string, error) {
	endpoint, bearer := os.Getenv("ACTIONS_ID_TOKEN_REQUEST_URL"), os.Getenv("ACTIONS_ID_TOKEN_REQUEST_TOKEN")
	if endpoint == "" || bearer == "" {
		return "", errors.New("GitHub OIDC is unavailable; the job needs permissions: id-token: write")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"&audience="+url.QueryEscape(Audience), nil)
	if err != nil {
		return "", err
	}
	request.Header.Set("Authorization", "bearer "+bearer)
	response, err := (&http.Client{Timeout: 30 * time.Second}).Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	var body struct {
		Value string `json:"value"`
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("mint OIDC token: %s", response.Status)
	}
	if err := json.NewDecoder(io.LimitReader(response.Body, maxTokenSize)).Decode(&body); err != nil || body.Value == "" {
		return "", errors.Join(errors.New("mint OIDC token: empty response"), err)
	}
	return body.Value, nil
}

func request(ctx context.Context, conn *nats.Conn, subject string, payload []byte, timeout time.Duration) (Reply, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	message, err := conn.RequestWithContext(ctx, subject, payload)
	if err != nil {
		return Reply{}, err
	}
	var reply Reply
	return reply, json.Unmarshal(message.Data, &reply)
}

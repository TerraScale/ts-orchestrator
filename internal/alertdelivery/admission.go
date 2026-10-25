package alertdelivery

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/oklog/ulid/v2"
)

const admissionEndpoint = "https://auth.terrascale.tech/v1/terrascale/email/admission"

// admit reserves one non-auth email attempt. Never retry: a lost response may
// already have consumed capacity. The local ledger prevents webhook retries
// from obtaining another admission for the same notification.
func (r relay) admit(ctx context.Context, token string) (time.Time, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	payload, err := json.Marshal(struct {
		AttemptID string `json:"attemptId"`
	}{ulid.Make().String()})
	if err != nil {
		return time.Time{}, errors.New("email admission encoding failed")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, admissionEndpoint, bytes.NewReader(payload))
	if err != nil {
		return time.Time{}, errors.New("email admission request failed")
	}
	// Domain separation gives ts-alerts only admission authority. Never forward
	// the vendor token itself or reuse dashboard ClientBasic credentials.
	proof := hmac.New(sha256.New, []byte(token))
	_, _ = proof.Write([]byte("terrascale:email-admission:v1:ts-alerts"))
	request.Header.Set("Authorization", "Bearer "+hex.EncodeToString(proof.Sum(nil)))
	request.Header.Set("Content-Type", "application/json")
	client := *r.client
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	response, err := client.Do(request)
	if err != nil {
		return time.Time{}, errors.New("email admission unavailable")
	}
	defer response.Body.Close()
	var grant struct {
		Status string    `json:"status"`
		SendBy time.Time `json:"sendBy"`
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	now := time.Now()
	if err != nil || len(data) > 4096 || response.StatusCode != http.StatusOK || json.Unmarshal(data, &grant) != nil || grant.Status != "admitted" || !grant.SendBy.After(now) || grant.SendBy.After(now.Add(10*time.Second)) {
		return time.Time{}, errors.New("email admission denied or invalid")
	}
	return grant.SendBy, nil
}

package databaseadmission

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/nats-io/nats.go"
)

func usageRegistrationFixture() UsageRegistration {
	return UsageRegistration{
		SchemaVersion: 1, Environment: "prod", TenantID: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ProjectID: "01ARZ3NDEKTSV4RRFFQ69G5FB9", DatabaseID: "01ARZ3NDEKTSV4RRFFQ69G5FC0", MemberID: "01ARZ3NDEKTSV4RRFFQ69G5FC1", Region: "GRU", SelectedRegions: []string{"GRU", "SFO"}, Residency: "none", Partition: "billing-01", StreamEpoch: 7, PlacementProofDigest: strings.Repeat("a", 64), OperationID: "usage-op-1",
	}
}

func TestValidateUsageRegistrationRejectsIdentityAndOrderingMismatches(t *testing.T) {
	r := usageRegistrationFixture()
	if err := ValidateUsageRegistration(r); err != nil {
		t.Fatal(err)
	}
	r.SelectedRegions = []string{"SFO", "GRU"}
	if ValidateUsageRegistration(r) == nil {
		t.Fatal("accepted unsorted selected regions")
	}
	r = usageRegistrationFixture()
	r.Region = "FRA"
	if ValidateUsageRegistration(r) == nil {
		t.Fatal("accepted region absent from selected regions")
	}
}

func TestHandleHostUsageForwardsExactRegistrationAndRejectsReceiptMismatch(t *testing.T) {
	registration := usageRegistrationFixture()
	config := HostConfig{Environment: registration.Environment, Region: registration.Region, MemberID: registration.MemberID}
	var received UsageRegistration
	client := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		body, _ := io.ReadAll(request.Body)
		if json.Unmarshal(body, &received, json.RejectUnknownMembers(true)) != nil {
			t.Error("engine received invalid registration")
		}
		receipt := usageReceipt{UsageRegistration: registration, State: "registered"}
		data, _ := json.Marshal(receipt)
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(data))), Header: make(http.Header)}, nil
	})}
	data, _ := json.Marshal(usageEnvelope{Registration: registration})
	if !handleHostUsage(context.Background(), config, client, &nats.Msg{Data: data}) {
		t.Fatal("usage envelope was not handled")
	}
	if !sameUsageRegistration(received, registration) {
		t.Fatal("engine registration changed")
	}

	bad := usageReceipt{UsageRegistration: registration, State: "wrong"}
	badData, _ := json.Marshal(bad)
	client.Transport = roundTripFunc(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(badData))), Header: make(http.Header)}, nil
	})
	if !handleHostUsage(context.Background(), config, client, &nats.Msg{Data: data}) {
		t.Fatal("mismatched receipt was not handled")
	}
}

func TestHandleHostUsageRejectsOversizeAndRedirectResponses(t *testing.T) {
	registration := usageRegistrationFixture()
	config := HostConfig{Environment: registration.Environment, Region: registration.Region, MemberID: registration.MemberID}
	data, _ := json.Marshal(usageEnvelope{Registration: registration})
	data = append(data, bytes.Repeat([]byte("x"), usageMessageLimit)...)
	if !handleHostUsage(context.Background(), config, &http.Client{}, &nats.Msg{Data: data}) {
		t.Fatal("oversize usage envelope was not handled")
	}
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return &http.Response{StatusCode: http.StatusTemporaryRedirect, Header: http.Header{"Location": []string{"http://redirected.invalid"}}, Body: io.NopCloser(strings.NewReader("redirect"))}, nil
		}),
	}
	if !handleHostUsage(context.Background(), config, client, &nats.Msg{Data: mustJSON(usageEnvelope{Registration: registration})}) {
		t.Fatal("redirect response was not handled")
	}
}

func mustJSON(value any) []byte {
	data, err := json.Marshal(value)
	if err != nil {
		panic(err)
	}
	return data
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) { return f(request) }

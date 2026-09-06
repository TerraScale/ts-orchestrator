package databaseadmission

import (
	"bytes"
	"context"
	"encoding/json/v2"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nats-io/nats.go"
	"terrascale.tech/orchestrator/src/orchestrator/keylease"
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
	r = usageRegistrationFixture()
	r.Partition = "billing\u0080"
	if ValidateUsageRegistration(r) == nil {
		t.Fatal("accepted C1 control character in partition")
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
	data := append([]byte(`{"admission":{},"entries":[],"padding":"`), bytes.Repeat([]byte("x"), usageMessageLimit)...)
	data = append(data, []byte(`"}`)...)
	if handleHostUsage(context.Background(), config, &http.Client{}, &nats.Msg{Data: data}) {
		t.Fatal("oversize non-usage envelope was consumed")
	}
	oversizeUsage, _ := json.Marshal(usageEnvelope{Registration: func() UsageRegistration {
		r := registration
		r.Partition = strings.Repeat("x", usageMessageLimit)
		return r
	}()})
	if handleHostUsage(context.Background(), config, &http.Client{}, &nats.Msg{Data: oversizeUsage}) {
		t.Fatal("oversize usage envelope was consumed before install decoding")
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

func TestRemoteUsageRegistrationThroughAuthenticatedHost(t *testing.T) {
	cluster := newAdmissionJournalCluster(t)
	connection := cluster.connect(t)
	record := journalFixture(t)
	target := record.Targets[0]
	registration := usageRegistrationFixture()
	registration.Environment = record.Request.Environment
	registration.MemberID = target.MemberID
	registration.Region = target.Region
	registration.SelectedRegions = []string{target.Region}
	if err := ValidateUsageRegistration(registration); err != nil {
		t.Fatal(err)
	}
	config := pipelineConfig(t, NewMemoryJournal())
	if err := keylease.InitializeCatalog(config.CatalogPath); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"ok", "tuple", "state", "unknown", "oversize", "redirect"} {
		t.Run(mode, func(t *testing.T) {
			socket := filepath.Join(filepath.Dir(config.CatalogPath), "usage-"+mode+".sock")
			listener, err := listenPrivate(socket)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				if mode == "redirect" {
					w.Header().Set("Location", "http://redirect.invalid")
					w.WriteHeader(http.StatusTemporaryRedirect)
					return
				}
				receipt := usageReceipt{UsageRegistration: registration, State: "registered"}
				switch mode {
				case "tuple":
					receipt.DatabaseID = "01ARZ3NDEKTSV4RRFFQ69G5FC2"
				case "state":
					receipt.State = "pending"
				case "unknown":
					body := append(mustJSON(receipt), []byte(` `)...)
					body = append(body[:len(body)-1], []byte(`,"extra":true}`)...)
					_, _ = w.Write(body)
					return
				case "oversize":
					_, _ = w.Write(bytes.Repeat([]byte("x"), usageMessageLimit+1))
					return
				}
				_, _ = w.Write(mustJSON(receipt))
			})}
			go server.Serve(listener)
			defer server.Close()
			host, err := StartHost(t.Context(), HostConfig{Connection: connection, ServerIdentity: target.ServerIdentity, CatalogPath: config.CatalogPath, EngineSocket: socket, EngineUID: uint32(os.Geteuid()), Environment: record.Request.Environment, Region: target.Region, MemberID: target.MemberID})
			if err != nil {
				t.Fatal(err)
			}
			defer host.Close()
			err = RemoteUsageRegistration(connection)(t.Context(), target, registration)
			if mode == "ok" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil {
				t.Fatal("accepted invalid usage receipt")
			}
			if mode == "redirect" && calls.Load() != 1 {
				t.Fatalf("redirect handler called %d times", calls.Load())
			}
		})
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

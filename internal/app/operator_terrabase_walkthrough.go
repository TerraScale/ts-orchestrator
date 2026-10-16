package app

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"

	"github.com/TerraScale/ts-orchestrator/internal/managedmaterial"
)

const (
	walkthroughReplicationWait = 90 * time.Second
	maxWalkthroughResponse     = 8 << 20
)

// walkthroughForwards maps a member's signed HTTPS address to the local end
// of a Bastion port forward. TLS still verifies the signed member address.
type walkthroughForwards map[string]string

func (*walkthroughForwards) String() string { return "" }

func (forwards *walkthroughForwards) Set(value string) error {
	original, local, ok := strings.Cut(value, "=")
	if _, _, err := net.SplitHostPort(original); !ok || err != nil {
		return errors.New("--forward requires MEMBER_IP:PORT=LOCAL_IP:PORT")
	}
	if _, _, err := net.SplitHostPort(local); err != nil {
		return errors.New("--forward requires MEMBER_IP:PORT=LOCAL_IP:PORT")
	}
	if *forwards == nil {
		*forwards = make(walkthroughForwards)
	}
	if _, duplicate := (*forwards)[original]; duplicate {
		return errors.New("duplicate --forward member address")
	}
	(*forwards)[original] = local
	return nil
}

type walkthroughCheck struct {
	Check  string `json:"check"`
	Member string `json:"member,omitempty"`
	Result string `json:"result"`
	Detail string `json:"detail,omitempty"`
}

// runTerraBaseWalkthrough exercises the deployed pair as a customer: HTTPS
// with the prepared CA and API key, rejected missing, invalid and wrong-tenant
// credentials, then create, exact retry, cross-member read, update and delete
// of one disposable document. It uses no controller or NATS access.
func runTerraBaseWalkthrough(ctx context.Context, args []string, output io.Writer) error {
	flags := flag.NewFlagSet("operator terrabase-walkthrough", flag.ContinueOnError)
	flags.SetOutput(io.Discard)
	statePath := flags.String("state", "", "terrabase-deploy state directory")
	var forwards walkthroughForwards
	flags.Var(&forwards, "forward", "MEMBER_IP:PORT=LOCAL_IP:PORT Bastion forward (repeatable)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *statePath == "" || flags.NArg() != 0 {
		return errors.New("terrabase-walkthrough requires --state DIR")
	}
	state, err := openDeployState(*statePath)
	if err != nil {
		return err
	}
	// A profile written by an earlier orchestrator has other members, so read
	// its version before the strict decode below rejects them.
	if data, err := state.readFile(deployClientFile); err == nil {
		var probe struct {
			Version int `json:"version"`
		}
		if json.Unmarshal(data, &probe) == nil && probe.Version != terrabaseClientProfileVersion {
			return fmt.Errorf("client profile version %d is unsupported; this walkthrough reads version %d: "+
				"walk through this state with the orchestrator revision that deployed it, or redeploy with a new "+
				"--state and partition", probe.Version, terrabaseClientProfileVersion)
		}
	}
	var credentials managedmaterial.CustomerMaterial
	var profile terrabaseClientProfile
	for name, value := range map[string]any{deployCredentialsFile: &credentials, deployClientFile: &profile} {
		exists, err := state.readJSON(name, value)
		if err != nil {
			return err
		}
		if !exists {
			return fmt.Errorf("deployment state lacks %s; run terrabase-deploy first", name)
		}
	}
	if len(profile.Members) != 2 || len(profile.Collections) == 0 || len(profile.Collections[0].UTF8Fields) == 0 {
		return errors.New("client profile needs two members and a collection with a UTF-8 field")
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(credentials.HTTPSCAPEM)) {
		return errors.New("deployment HTTPS CA is invalid")
	}
	client := walkthroughClient{token: credentials.Token, profile: profile, forwards: forwards, roots: roots,
		output: output}
	return client.run(ctx)
}

type walkthroughClient struct {
	token    string
	profile  terrabaseClientProfile
	forwards walkthroughForwards
	roots    *x509.CertPool
	output   io.Writer
	failed   int
}

func (client *walkthroughClient) run(ctx context.Context) error {
	a, b := client.profile.Members[0], client.profile.Members[1]
	collection := client.profile.Collections[0]
	scope := fmt.Sprintf("/v1/tenants/%s/databases/%s/shards/%d", client.profile.TenantID,
		client.profile.DatabaseID, client.profile.ShardID)
	document := entityid.New()
	point := scope + "/collections/" + collection.CollectionID + "/documents/" + document
	for _, member := range client.profile.Members {
		status, _, err := client.request(ctx, member, http.MethodGet, "/openapi.json", nil, "")
		client.expect("openapi", member, err == nil && status == http.StatusOK, status, err)
	}
	status, _, err := client.request(ctx, a, http.MethodGet, point, nil, "-")
	client.expect("missing-credential-rejected", a, err == nil && status == http.StatusUnauthorized, status, err)
	status, _, err = client.request(ctx, a, http.MethodGet, point, nil, "tbk1.AAAAAAAAAAAAAAAAAAAAAA.AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")
	client.expect("invalid-credential-rejected", a, err == nil && status == http.StatusUnauthorized, status, err)
	foreign := fmt.Sprintf("/v1/tenants/%s/databases/%s/shards/%d/collections/%s/documents/%s", entityid.New(),
		client.profile.DatabaseID, client.profile.ShardID, collection.CollectionID, document)
	status, _, err = client.request(ctx, a, http.MethodGet, foreign, nil, "")
	client.expect("wrong-tenant-rejected", a, err == nil && status == http.StatusForbidden, status, err)
	if client.failed != 0 {
		return fmt.Errorf("%d walkthrough checks failed before any write", client.failed)
	}
	absent, err := client.read(ctx, b, point)
	client.expect("absent-before-write", b, err == nil && absent.State == "absent", 0, err)
	create := client.transaction(collection, document, jsontext.Value("[]"), "created by walkthrough")
	status, first, err := client.request(ctx, a, http.MethodPost, scope+"/transactions", create, "")
	client.expect("create", a, err == nil && status == http.StatusOK && receiptSequence(first) != "", status, err)
	status, retry, err := client.request(ctx, a, http.MethodPost, scope+"/transactions", create, "")
	client.expect("exact-retry-same-receipt", a, err == nil && status == http.StatusOK &&
		receiptSequence(retry) == receiptSequence(first), status, err)
	created, err := client.await(ctx, b, point, collection, "created by walkthrough")
	client.expect("replicated-read", b, err == nil, 0, err)
	if err != nil {
		return fmt.Errorf("%d walkthrough checks failed", client.failed)
	}
	update := client.transaction(collection, document, created.Context, "updated by walkthrough")
	status, _, err = client.request(ctx, b, http.MethodPost, scope+"/transactions", update, "")
	client.expect("update", b, err == nil && status == http.StatusOK, status, err)
	updated, err := client.await(ctx, a, point, collection, "updated by walkthrough")
	client.expect("replicated-update", a, err == nil, 0, err)
	if err == nil {
		tombstone := client.transaction(collection, document, updated.Context, "")
		status, _, err = client.request(ctx, a, http.MethodPost, scope+"/transactions", tombstone, "")
		client.expect("delete", a, err == nil && status == http.StatusOK, status, err)
		_, err = client.await(ctx, b, point, collection, "")
		client.expect("replicated-delete", b, err == nil, 0, err)
	}
	if client.failed != 0 {
		return fmt.Errorf("%d walkthrough checks failed", client.failed)
	}
	return printJSON(client.output, walkthroughCheck{Check: "walkthrough", Result: "passed", Detail: document})
}

func (client *walkthroughClient) expect(check string, member terrabaseClientMember, ok bool, status int, err error) {
	result := walkthroughCheck{Check: check, Member: member.SeatID, Result: "passed"}
	if !ok {
		client.failed++
		result.Result = "failed"
		switch {
		case err != nil:
			result.Detail = err.Error()
		case status != 0:
			result.Detail = "HTTP " + strconv.Itoa(status)
		}
	}
	_ = printJSON(client.output, result)
}

type walkthroughTransaction struct {
	Version       int                      `json:"version"`
	TransactionID walkthroughTransactionID `json:"transaction_id"`
	Writes        []walkthroughWrite       `json:"writes"`
}

type walkthroughTransactionID struct {
	ExpiresAtUnixMS string `json:"expires_at_unix_ms"`
	Nonce           string `json:"nonce"`
}

type walkthroughWrite struct {
	Collection string           `json:"collection"`
	Document   string           `json:"document"`
	Observed   jsontext.Value   `json:"observed"`
	Value      walkthroughValue `json:"value"`
}

// walkthroughValue is a complete named JSON document, or a tombstone when
// Document is nil.
type walkthroughValue struct {
	Kind     string            `json:"kind"`
	Document map[string]string `json:"document,omitzero"`
}

// transaction builds one single-write transaction that stores text in the
// collection's first UTF-8 field. An empty text writes a tombstone; observed
// is the prior read context.
func (client *walkthroughClient) transaction(collection terrabaseClientCollection, document string,
	observed jsontext.Value, text string,
) []byte {
	var nonce [16]byte
	_, _ = rand.Read(nonce[:])
	value := walkthroughValue{Kind: "tombstone"}
	if text != "" {
		value = walkthroughValue{Kind: "live", Document: map[string]string{collection.UTF8Fields[0]: text}}
	}
	wire, _ := json.Marshal(walkthroughTransaction{Version: 1,
		TransactionID: walkthroughTransactionID{
			ExpiresAtUnixMS: strconv.FormatInt(time.Now().Add(10*time.Minute).UnixMilli(), 10),
			Nonce:           hex.EncodeToString(nonce[:]),
		},
		Writes: []walkthroughWrite{{Collection: collection.CollectionID, Document: document, Observed: observed,
			Value: value}},
	})
	return wire
}

type walkthroughPoint struct {
	Version  int                  `json:"version"`
	State    string               `json:"state"`
	Context  jsontext.Value       `json:"context"`
	Siblings []walkthroughSibling `json:"siblings"`
}

type walkthroughSibling struct {
	Kind             string            `json:"kind"`
	SchemaGeneration string            `json:"schema_generation"`
	SchemaDigest     string            `json:"schema_digest"`
	Document         map[string]string `json:"document"`
}

func (client *walkthroughClient) read(ctx context.Context, member terrabaseClientMember, path string) (walkthroughPoint, error) {
	status, body, err := client.request(ctx, member, http.MethodGet, path, nil, "")
	if err != nil {
		return walkthroughPoint{}, err
	}
	if status != http.StatusOK {
		return walkthroughPoint{}, fmt.Errorf("read returned HTTP %d", status)
	}
	var point walkthroughPoint
	if err := json.Unmarshal(body, &point); err != nil || point.Version != 1 {
		return walkthroughPoint{}, errors.New("read returned an invalid point document")
	}
	return point, nil
}

// await polls one member until the document holds text, or is deleted when
// text is empty, within the replication visibility window.
func (client *walkthroughClient) await(ctx context.Context, member terrabaseClientMember, path string,
	collection terrabaseClientCollection, text string,
) (walkthroughPoint, error) {
	deadline := time.Now().Add(walkthroughReplicationWait)
	for {
		point, err := client.read(ctx, member, path)
		if err == nil && point.matches(collection, text) {
			return point, nil
		}
		if !time.Now().Before(deadline) {
			if err == nil {
				err = fmt.Errorf("document stayed %s", point.State)
			}
			return walkthroughPoint{}, fmt.Errorf("not visible within %s: %w", walkthroughReplicationWait, err)
		}
		select {
		case <-ctx.Done():
			return walkthroughPoint{}, ctx.Err()
		case <-time.After(500 * time.Millisecond):
		}
	}
}

// matches requires one tombstone when text is empty, or else one live
// version under the collection's catalog binding whose whole document is
// text in the first UTF-8 field.
func (point walkthroughPoint) matches(collection terrabaseClientCollection, text string) bool {
	if text == "" {
		return point.State == "deleted" && len(point.Siblings) == 1 && point.Siblings[0].Kind == "tombstone"
	}
	if point.State != "value" || len(point.Siblings) != 1 {
		return false
	}
	sibling := point.Siblings[0]
	return sibling.Kind == "live" && sibling.SchemaDigest == collection.SchemaDigest &&
		sibling.SchemaGeneration == strconv.FormatUint(collection.SchemaGeneration, 10) &&
		maps.Equal(sibling.Document, map[string]string{collection.UTF8Fields[0]: text})
}

func receiptSequence(body []byte) string {
	var receipt struct {
		CommitSequence string `json:"commit_sequence"`
	}
	if json.Unmarshal(body, &receipt) != nil {
		return ""
	}
	return receipt.CommitSequence
}

// request sends one HTTPS request to a member's signed address, dialing its
// local forward when one is configured. token "" uses the deployment key,
// "-" sends no Authorization header, and any other value is sent as is.
func (client *walkthroughClient) request(ctx context.Context, member terrabaseClientMember, method, path string,
	body []byte, token string,
) (int, []byte, error) {
	target, err := url.Parse(member.URL)
	if err != nil || target.Scheme != "https" {
		return 0, nil, errors.New("member URL must be HTTPS")
	}
	dial := target.Host
	if local, forwarded := client.forwards[target.Host]; forwarded {
		dial = local
	}
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: client.roots, ServerName: target.Hostname()},
		DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 10 * time.Second}).DialContext(ctx, network, dial)
		},
		ForceAttemptHTTP2: false,
	}
	defer transport.CloseIdleConnections()
	requestCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	request, err := http.NewRequestWithContext(requestCtx, method, member.URL+path, bytes.NewReader(body))
	if err != nil {
		return 0, nil, err
	}
	switch token {
	case "":
		request.Header.Set("Authorization", "Bearer "+client.token)
	case "-":
	default:
		request.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	response, err := (&http.Client{Transport: transport}).Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	data, err := io.ReadAll(io.LimitReader(response.Body, maxWalkthroughResponse+1))
	if err != nil || len(data) > maxWalkthroughResponse {
		return response.StatusCode, nil, errors.New("member response is unreadable or oversized")
	}
	return response.StatusCode, data, nil
}

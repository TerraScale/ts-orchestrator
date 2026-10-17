package rootsecret

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json/jsontext"
	"encoding/json/v2"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
	"github.com/TerraScale/ts-orchestrator/internal/netbird"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/journal"
	"github.com/TerraScale/ts-orchestrator/internal/netbird/manager"
)

const netBirdJournalResponseLimit = 8 << 20

// BootstrapAccount exposes only the canonical account-address recipe. It never
// accepts a request, provenance digest, transport or completion from its caller.
func (client *NetBirdJournalClient) BootstrapAccount(ctx context.Context, token string) error {
	if client == nil || ctx == nil || !netbird.ValidAdminPAT([]byte(token)) || client.Guard(ctx) != nil {
		return ErrDelivery
	}
	deadline, err := client.CurrentDeadline(ctx)
	if err != nil {
		return ErrDelivery
	}
	ctx, cancel := netBirdStartupReadContext(ctx, client.ctx, deadline)
	defer cancel()
	if client.bootstrapReadiness(ctx) != nil {
		return ErrDelivery
	}
	return manager.RunBootstrapAccountWithTransport(ctx, token, func() error { return client.Guard(ctx) }, client.doBootstrapMutation)
}

func (client *NetBirdJournalClient) bootstrapReadiness(ctx context.Context) error {
	started := time.Now().UTC()
	first := minDeadline(client.expires, started.Add(30*time.Second))
	if deadline, bounded := ctx.Deadline(); bounded {
		first = minDeadline(first, deadline)
	}
	ctx, cancel := netBirdStartupReadContext(ctx, client.ctx, first)
	defer cancel()
	client.mu.Lock()
	defer client.mu.Unlock()
	current, err := client.currentDeadline(ctx)
	if err != nil {
		return ErrDelivery
	}
	binding, err := client.bootstrapBinding()
	if err != nil {
		return ErrDelivery
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return ErrDelivery
	}
	_, err = client.exchangeJournal(ctx, journal.Request{SchemaVersion: 1, Domain: journal.Domain, Action: journal.Ready, Binding: binding,
		OperationID: entityid.New(), Nonce: hex.EncodeToString(nonce[:]), StartedAt: started, FirstDeadline: minDeadline(first, current).UTC()})
	return err
}

func (client *NetBirdJournalClient) doBootstrapMutation(request *http.Request) (*http.Response, error) {
	started := time.Now().UTC()
	first := minDeadline(client.expires, started.Add(30*time.Second))
	if request == nil || request.Context().Err() != nil {
		return nil, ErrDelivery
	}
	if deadline, bounded := request.Context().Deadline(); bounded {
		first = minDeadline(first, deadline)
	}
	ctx, cancel := netBirdStartupReadContext(request.Context(), client.ctx, first)
	defer cancel()
	mutation, err := journal.Freeze(request)
	if err != nil {
		return nil, ErrDelivery
	}
	token := strings.TrimPrefix(request.Header.Get("Authorization"), "Token ")
	if request.Header.Get("Authorization") != "Token "+token || !netbird.ValidAdminPAT([]byte(token)) {
		return nil, ErrDelivery
	}
	// The first cap is fixed before waiting for another original operation.
	client.mu.Lock()
	defer client.mu.Unlock()
	current, err := client.currentDeadline(ctx)
	if err != nil {
		return nil, ErrDelivery
	}
	first = minDeadline(first, current).UTC()
	ctx, cancelCurrent := context.WithDeadline(ctx, first)
	defer cancelCurrent()
	if client.checkBootstrapAccountMutation(ctx, mutation, token) != nil {
		return nil, ErrDelivery
	}
	binding, err := client.bootstrapBinding()
	if err != nil {
		return nil, ErrDelivery
	}
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return nil, ErrDelivery
	}
	action := journal.Request{SchemaVersion: 1, Domain: journal.Domain, Action: journal.Ready, Binding: binding,
		OperationID: entityid.New(), Nonce: hex.EncodeToString(nonce[:]), StartedAt: started, FirstDeadline: first}
	ready, err := client.exchangeJournal(ctx, action)
	if err != nil {
		return nil, ErrDelivery
	}
	reservation := journal.Reservation{SchemaVersion: 1, Counter: ready.NextCounter, PreviousCompletionSHA256: ready.PreviousCompletionSHA256,
		OperationID: action.OperationID, Nonce: action.Nonce, Binding: binding, Mutation: mutation, StartedAt: started, FirstDeadline: first}
	action.Action, action.Reservation = journal.Reserve, &reservation
	if _, err := client.exchangeJournal(ctx, action); err != nil {
		return nil, ErrDelivery
	}
	// Reservation is consumed even if the independent final account read fails.
	// No later path can dispatch this reservation or clear its pending result.
	if client.checkBootstrapAccountMutation(ctx, mutation, token) != nil {
		return nil, ErrDelivery
	}
	current, err = client.currentDeadline(ctx)
	if err != nil {
		return nil, ErrDelivery
	}
	ctx, cancelDispatch := context.WithDeadline(ctx, minDeadline(first, current))
	defer cancelDispatch()
	if ctx.Err() != nil || client.original.Err() != nil || client.ctx.Err() != nil || checkNetBirdStartupProcess(client.process, client.processBinding) != nil {
		return nil, ErrDelivery
	}
	local, transport := newNetBirdJournalHTTPClient()
	defer transport.CloseIdleConnections()
	localRequest, err := http.NewRequestWithContext(ctx, mutation.Method, "http://127.0.0.1:18081"+mutation.Path, bytes.NewReader(mutation.Body))
	if err != nil {
		return nil, ErrDelivery
	}
	localRequest.GetBody = nil
	localRequest.Header.Set("Authorization", "Token "+token)
	localRequest.Header.Set("Accept", "application/json")
	localRequest.Header.Set("Content-Type", "application/json")
	response, err := local.Do(localRequest)
	if err != nil || response == nil {
		return nil, ErrDelivery
	}
	wire, err := readNetBirdJournalResponse(response, netBirdJournalResponseLimit)
	if err != nil {
		return nil, ErrDelivery
	}
	// Only this private, synchronous HTTP 200 body can produce completion.
	completion := journal.Completion{StatusCode: http.StatusOK, ResponseSHA256: netBirdDigest(wire), CompletedAt: time.Now().UTC()}
	completion.ReservationSHA256, err = reservation.Digest()
	if err != nil || completion.Validate(reservation) != nil {
		return nil, ErrDelivery
	}
	action.Action, action.Completion = journal.Complete, &completion
	if _, err := client.exchangeJournal(ctx, action); err != nil {
		return nil, ErrDelivery
	}
	current, err = client.currentDeadline(ctx)
	if err != nil || ctx.Err() != nil || client.original.Err() != nil || !time.Now().Before(minDeadline(first, current)) {
		return nil, ErrDelivery
	}
	response.Body, response.ContentLength = io.NopCloser(bytes.NewReader(wire)), int64(len(wire))
	return response, nil
}

func (client *NetBirdJournalClient) bootstrapBinding() (journal.Binding, error) {
	public := client.source.Source()
	binding := journal.Binding{AccountOperationDomain: journal.BootstrapAccountDomain, PurposeSHA256: client.source.Purpose().Digest(), SourceSHA256: public.Startup().SourceSHA256(),
		GrantSHA256: client.source.Purpose().GrantDigest(), TemplateSHA256: client.source.Purpose().TemplateDigest(),
		CredentialID: client.credential.ID, CredentialSubject: client.credential.Subject, CredentialSHA256: client.credential.SHA256,
		CurrentID: client.currentID, CurrentVersion: client.currentVersion, CurrentSHA256: client.currentSHA256,
		ManagerInstanceID: client.source.Underlay().ManagerInstanceID(), ManagerVNICID: client.source.Underlay().ManagerVNICID(),
		WriterInstanceID: client.source.Underlay().WriterInstanceID(), WriterVNICID: client.source.Underlay().WriterVNICID(),
		UnderlaySHA256: client.source.Underlay().Digest(), ManagerAdmissionSHA256: client.observation.AdmissionSHA256,
		ManagerProcessSHA256: client.processBinding, ManagerLaunchRecipeSHA256: client.observation.LaunchRecipeSHA256,
		ManagerBinarySHA256: client.observation.Binary.SHA256}
	if binding.Validate() != nil {
		return journal.Binding{}, ErrDelivery
	}
	return binding, nil
}

func (client *NetBirdJournalClient) exchangeJournal(ctx context.Context, action journal.Request) (journal.Reply, error) {
	deadline, err := client.currentDeadline(ctx)
	if err != nil {
		return journal.Reply{}, ErrDelivery
	}
	ctx, cancel := context.WithDeadline(ctx, minDeadline(action.FirstDeadline, deadline))
	defer cancel()
	wire, err := action.Encode()
	if err != nil {
		return journal.Reply{}, ErrDelivery
	}
	signature, err := client.signer.Sign(wire)
	if err != nil || len(signature) != 64 {
		return journal.Reply{}, ErrDelivery
	}
	config, credential, err := CheckNetBirdJournalMaterial(client.material, client.source, time.Now().UTC())
	if err != nil || credential.ID != client.credential.ID || credential.Subject != client.credential.Subject || credential.SHA256 != client.credential.SHA256 ||
		!credential.IssuedAt.Equal(client.credential.IssuedAt) || !credential.ExpiresAt.Equal(client.credential.ExpiresAt) {
		return journal.Reply{}, ErrDelivery
	}
	config.ServerName = "controller-a"
	httpClient, transport := newNetBirdJournalHTTPClient()
	defer transport.CloseIdleConnections()
	transport.TLSClientConfig = config
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://"+net.JoinHostPort(client.source.Underlay().WriterPrivateIP(), "443")+journal.Endpoint, bytes.NewReader(wire))
	if err != nil {
		return journal.Reply{}, ErrDelivery
	}
	request.GetBody = nil
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set(journal.SignatureHeader, base64.StdEncoding.EncodeToString(signature))
	deadline, err = client.currentDeadline(ctx)
	if err != nil {
		return journal.Reply{}, ErrDelivery
	}
	requestCtx, stop := context.WithDeadline(ctx, minDeadline(action.FirstDeadline, deadline))
	defer stop()
	request = request.WithContext(requestCtx)
	if requestCtx.Err() != nil || client.original.Err() != nil || client.ctx.Err() != nil || checkNetBirdStartupProcess(client.process, client.processBinding) != nil {
		return journal.Reply{}, ErrDelivery
	}
	response, err := httpClient.Do(request)
	if err != nil || response == nil {
		return journal.Reply{}, ErrDelivery
	}
	replyWire, err := readNetBirdJournalResponse(response, journal.MaxMessageBytes)
	if err != nil {
		return journal.Reply{}, ErrDelivery
	}
	deadline, err = client.currentDeadline(requestCtx)
	if err != nil || client.original.Err() != nil || requestCtx.Err() != nil || !time.Now().Before(minDeadline(action.FirstDeadline, deadline)) {
		return journal.Reply{}, ErrDelivery
	}
	return journal.DecodeReply(replyWire, action)
}

func newNetBirdJournalHTTPClient() (*http.Client, *http.Transport) {
	protocols := new(http.Protocols)
	protocols.SetHTTP1(true)
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	transport := &http.Transport{Proxy: nil, Protocols: protocols, DialContext: dialer.DialContext, DisableKeepAlives: true,
		TLSHandshakeTimeout: 10 * time.Second, ResponseHeaderTimeout: 30 * time.Second}
	return &http.Client{Transport: transport, Timeout: 30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport
}

func readNetBirdJournalResponse(response *http.Response, limit int64) ([]byte, error) {
	if response.Body == nil {
		return nil, ErrDelivery
	}
	if response.StatusCode != http.StatusOK || response.ContentLength > limit {
		response.Body.Close()
		return nil, ErrDelivery
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, limit+1))
	closeErr := response.Body.Close()
	if err != nil || closeErr != nil || int64(len(wire)) > limit || response.ContentLength >= 0 && response.ContentLength != int64(len(wire)) {
		return nil, ErrDelivery
	}
	return wire, nil
}

type netBirdBootstrapAccount struct {
	ID         string                    `json:"id"`
	Settings   map[string]jsontext.Value `json:"settings"`
	Onboarding jsontext.Value            `json:"onboarding,omitzero"`
}

type netBirdBootstrapAccountUpdate struct {
	Settings   map[string]jsontext.Value `json:"settings"`
	Onboarding jsontext.Value            `json:"onboarding,omitzero"`
}

func (client *NetBirdJournalClient) checkBootstrapAccountMutation(ctx context.Context, mutation journal.Mutation, token string) error {
	if mutation.Method != http.MethodPut || !strings.HasPrefix(mutation.Path, "/api/accounts/") || mutation.Validate() != nil {
		return ErrDelivery
	}
	deadline, err := client.currentDeadline(ctx)
	if err != nil {
		return ErrDelivery
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	local, transport := newNetBirdJournalHTTPClient()
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://127.0.0.1:18081/api/accounts", nil)
	if err != nil {
		return ErrDelivery
	}
	request.Header.Set("Authorization", "Token "+token)
	response, err := local.Do(request)
	if err != nil || response == nil {
		return ErrDelivery
	}
	wire, err := readNetBirdJournalResponse(response, netBirdJournalResponseLimit)
	if err != nil {
		return ErrDelivery
	}
	var accounts []netBirdBootstrapAccount
	var update netBirdBootstrapAccountUpdate
	if json.Unmarshal(wire, &accounts) != nil || len(accounts) != 1 || accounts[0].ID == "" || accounts[0].Settings == nil ||
		mutation.Path != "/api/accounts/"+accounts[0].ID || json.Unmarshal(mutation.Body, &update, json.RejectUnknownMembers(true)) != nil {
		return ErrDelivery
	}
	wanted := accounts[0]
	recipe := manager.GRU()
	for name, value := range map[string]string{"network_range": recipe.NetworkRange, "dns_domain": recipe.PeerDNSDomain} {
		wanted.Settings[name], err = json.Marshal(value)
		if err != nil {
			return ErrDelivery
		}
	}
	expected, err := json.Marshal(netBirdBootstrapAccountUpdate{Settings: wanted.Settings, Onboarding: wanted.Onboarding}, json.Deterministic(true))
	actual, actualErr := json.Marshal(update, json.Deterministic(true))
	if err != nil || actualErr != nil || !bytes.Equal(expected, actual) {
		return ErrDelivery
	}
	deadline, err = client.currentDeadline(ctx)
	if err != nil || ctx.Err() != nil || client.original.Err() != nil || !time.Now().Before(deadline) {
		return ErrDelivery
	}
	return nil
}

//go:build linux

package serviceidentityrotation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/hostsecrets"
)

type RemoteMemberEndpoint struct {
	NodeID string `json:"node_id"`
	URL    string `json:"url"`
}
type RemoteMembersConfig struct {
	TLS *tls.Config
	// Endpoints must enumerate every admitted member from trusted control state.
	Endpoints func(context.Context) ([]RemoteMemberEndpoint, error)
	Authority func(context.Context) (uint64, string, error)
}
type RemoteMembers struct {
	config RemoteMembersConfig
	client *http.Client
}

func NewRemoteMembers(c RemoteMembersConfig) (*RemoteMembers, error) {
	if c.TLS == nil || c.TLS.InsecureSkipVerify || c.TLS.RootCAs == nil || (len(c.TLS.Certificates) == 0 && c.TLS.GetClientCertificate == nil) || c.Endpoints == nil || c.Authority == nil {
		return nil, ErrRotation
	}
	tlsConfig := c.TLS.Clone()
	tlsConfig.MinVersion = max(tlsConfig.MinVersion, tls.VersionTLS13)
	return &RemoteMembers{c, &http.Client{Transport: &http.Transport{TLSClientConfig: tlsConfig, DisableKeepAlives: true, ResponseHeaderTimeout: 15 * time.Second}, Timeout: 20 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}
func (m *RemoteMembers) DeliverTo(ctx context.Context, endpoints []RemoteMemberEndpoint, ref hostsecrets.IdentitySecretReference, generation uint64, secret []byte) error {
	if ref.Generation == 0 || ref.VersionNumber <= 0 {
		return ErrRotation
	}
	q := MemberRequest{Version: "oci-" + strconv.FormatUint(ref.Generation, 10), Generation: generation, Secret: string(secret)}
	defer func() { q.Secret = "" }()
	if !validMemberRequest(q) {
		return ErrRotation
	}
	if !validJournalRoster(endpoints) {
		return ErrRotation
	}
	trusted, err := m.config.Endpoints(ctx)
	if err != nil || !validJournalRoster(trusted) {
		return ErrRotation
	}
	trustedEndpoints := make(map[string]struct{}, len(trusted))
	for _, endpoint := range trusted {
		trustedEndpoints[endpointKey(endpoint)] = struct{}{}
	}
	// The coordinator's roster selects the recipients, but every recipient must
	// still be present in the independently sourced trusted inventory.
	for _, endpoint := range endpoints {
		if _, ok := trustedEndpoints[endpointKey(endpoint)]; !ok {
			return ErrRotation
		}
	}
	for _, endpoint := range endpoints {
		if m.deliver(ctx, endpoint, q) != nil {
			return ErrRotation
		}
	}
	return nil
}

func endpointKey(endpoint RemoteMemberEndpoint) string {
	u, _ := url.Parse(endpoint.URL)
	return endpoint.NodeID + "\x00" + strings.ToLower(u.Host)
}
func (m *RemoteMembers) deliver(ctx context.Context, endpoint RemoteMemberEndpoint, q MemberRequest) error {
	epoch, lease, err := m.config.Authority(ctx)
	if err != nil || epoch == 0 || lease == "" {
		return ErrRotation
	}
	payload, err := json.Marshal(remoteMemberRequest{NodeID: endpoint.NodeID, AuthorityEpoch: epoch, AuthorityLeaseID: lease, MemberRequest: q})
	defer clear(payload)
	if err != nil || len(payload) > 2048 {
		return ErrRotation
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimSuffix(endpoint.URL, "/")+HandlerPath, bytes.NewReader(payload))
	if err != nil {
		return ErrRotation
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := m.client.Do(req)
	if err != nil {
		return ErrRotation
	}
	defer res.Body.Close()
	body, err := io.ReadAll(io.LimitReader(res.Body, 2049))
	defer clear(body)
	var receipt MemberReceipt
	if err != nil || len(body) > 2048 || res.StatusCode != http.StatusOK || json.Unmarshal(body, &receipt, json.RejectUnknownMembers(true)) != nil || receipt.Version != q.Version || receipt.Generation != q.Generation || receipt.State != "adopted" {
		return ErrRotation
	}
	currentEpoch, currentLease, err := m.config.Authority(ctx)
	if err != nil || currentEpoch != epoch || currentLease != lease {
		return ErrRotation
	}
	return nil
}

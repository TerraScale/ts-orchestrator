package keyrotation

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json/v2"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/security"
)

var ErrMemberRotation = errors.New("key rotation: member operation failed")

// MemberEndpoint is trusted deployment configuration, never a URL received
// from a rotation request. IDs also select the issuer's per-host identity.
type MemberEndpoint struct {
	ID     string `json:"id"`
	Region string `json:"region"`
	URL    string `json:"url"`
}

type MemberGatewayConfig struct {
	AuthorityEpoch   uint64
	AuthorityLeaseID string
	Members          []MemberEndpoint
	TLS              *tls.Config
	CheckAuthority   func(context.Context) error
}

type MemberGateway struct {
	epoch     uint64
	leaseID   string
	endpoints map[string]MemberEndpoint
	regions   map[string][]string
	client    *http.Client
	authority func(context.Context) error
}

var _ security.MemberGateway = (*MemberGateway)(nil)

func NewMemberGateway(config MemberGatewayConfig) (*MemberGateway, error) {
	if len(config.Members) == 0 || config.TLS == nil || config.CheckAuthority == nil || config.AuthorityEpoch == 0 || !rotationToken(config.AuthorityLeaseID) {
		return nil, configurationError("member transport authority is required")
	}
	tlsConfig := config.TLS.Clone()
	if tlsConfig.InsecureSkipVerify || tlsConfig.RootCAs == nil || len(tlsConfig.Certificates) == 0 && tlsConfig.GetClientCertificate == nil {
		return nil, configurationError("verified member mTLS is required")
	}
	tlsConfig.MinVersion = max(tlsConfig.MinVersion, tls.VersionTLS13)
	g := &MemberGateway{epoch: config.AuthorityEpoch, leaseID: config.AuthorityLeaseID, endpoints: map[string]MemberEndpoint{}, regions: map[string][]string{}, authority: config.CheckAuthority, client: &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsConfig, ResponseHeaderTimeout: 15 * time.Second}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}
	for _, endpoint := range config.Members {
		parsed, err := url.Parse(endpoint.URL)
		if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.ForceQuery || parsed.Opaque != "" || parsed.Path != "" && parsed.Path != "/" || !rotationToken(endpoint.ID) || !rotationToken(endpoint.Region) {
			return nil, configurationError("member endpoint is invalid")
		}
		if _, exists := g.endpoints[endpoint.ID]; exists {
			return nil, configurationError("member identity is duplicated")
		}
		endpoint.URL = strings.TrimSuffix(endpoint.URL, "/")
		g.endpoints[endpoint.ID] = endpoint
		g.regions[endpoint.Region] = append(g.regions[endpoint.Region], endpoint.ID)
	}
	return g, nil
}
func (g *MemberGateway) Members(ctx context.Context, region string) ([]string, error) {
	if err := g.authority(ctx); err != nil {
		return nil, ErrMemberRotation
	}
	members := g.regions[region]
	if len(members) == 0 {
		return nil, ErrMemberRotation
	}
	return slices.Clone(members), nil
}
func (g *MemberGateway) Distribute(ctx context.Context, member string, credentials security.CredentialSet, key string) error {
	request, err := memberCredentialRequest(member, "member", "stage", credentials, key)
	if err != nil {
		return err
	}
	defer clearMemberRequest(&request)
	_, err = g.call(ctx, member, request)
	return err
}
func (g *MemberGateway) Verify(ctx context.Context, member string, generation uint64) (security.ConsumerObservation, error) {
	return g.observe(ctx, member, "member", generation)
}
func (g *MemberGateway) Activate(ctx context.Context, member string, generation uint64, key string) error {
	return g.action(ctx, member, "member", "activate", generation, key)
}
func (g *MemberGateway) Retire(ctx context.Context, member string, generation uint64, key string) error {
	return g.action(ctx, member, "member", "retire", generation, key)
}
func (g *MemberGateway) Rollback(ctx context.Context, member string, generation uint64, key string) error {
	return g.action(ctx, member, "member", "rollback", generation, key)
}
func (g *MemberGateway) Fence(ctx context.Context, region, key string) error {
	return g.regionAction(ctx, region, "member", "fence", 0, key)
}
func (g *MemberGateway) regionAction(ctx context.Context, region, consumer, action string, generation uint64, key string) error {
	members := g.regions[region]
	if len(members) == 0 {
		return ErrMemberRotation
	}
	var result error
	for _, member := range members {
		if err := g.action(ctx, member, consumer, action, generation, key+"/"+member); err != nil {
			result = ErrMemberRotation
		}
	}
	return result
}
func (g *MemberGateway) action(ctx context.Context, member, consumer, action string, generation uint64, key string) error {
	_, err := g.call(ctx, member, MemberRotationRequest{OperationID: key, NodeID: member, Consumer: consumer, Action: action, Generation: generation})
	return err
}
func (g *MemberGateway) observe(ctx context.Context, member, consumer string, generation uint64) (security.ConsumerObservation, error) {
	reply, err := g.call(ctx, member, MemberRotationRequest{OperationID: fmt.Sprintf("verify/%s/%d", consumer, generation), NodeID: member, Consumer: consumer, Action: "verify", Generation: generation})
	if err != nil || reply.Generation != generation || reply.State != "staged" && reply.State != "active" || reply.ValidUntil <= time.Now().Unix() {
		return security.ConsumerObservation{}, ErrMemberRotation
	}
	return security.ConsumerObservation{Generation: reply.Generation, ValidUntil: time.Unix(reply.ValidUntil, 0)}, nil
}
func (g *MemberGateway) call(ctx context.Context, member string, request MemberRotationRequest) (MemberRotationResponse, error) {
	endpoint, ok := g.endpoints[member]
	if !ok || !validOperationKey(request.OperationID) {
		return MemberRotationResponse{}, ErrMemberRotation
	}
	request.AuthorityEpoch = g.epoch
	request.AuthorityLeaseID = g.leaseID
	payload, err := json.Marshal(request)
	if err != nil || len(payload) > maximumMemberRotationBytes {
		return MemberRotationResponse{}, ErrMemberRotation
	}
	defer clear(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint.URL+memberRotationPath, bytes.NewReader(payload))
	if err != nil {
		return MemberRotationResponse{}, ErrMemberRotation
	}
	req.Header.Set("Content-Type", "application/json")
	if err = g.authority(ctx); err != nil {
		return MemberRotationResponse{}, ErrMemberRotation
	}
	response, err := g.client.Do(req)
	if err != nil {
		return MemberRotationResponse{}, ErrMemberRotation
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 4097))
	defer clear(body)
	var result MemberRotationResponse
	if err != nil || len(body) > 4096 || response.StatusCode != http.StatusOK || json.Unmarshal(body, &result, json.RejectUnknownMembers(true)) != nil || result.OperationID != request.OperationID {
		return MemberRotationResponse{}, ErrMemberRotation
	}
	return result, nil
}
func memberCredentialRequest(member, consumer, action string, credentials security.CredentialSet, key string) (MemberRotationRequest, error) {
	request := MemberRotationRequest{OperationID: key, NodeID: member, Consumer: consumer, Action: action, Generation: credentials.Identity.Version, ExpiresAt: credentials.Identity.ExpiresAt.Unix(), TrustBundle: bytes.Clone(credentials.Identity.TrustBundle)}
	if credentials.Identity.Version == 0 || credentials.Identity.ExpiresAt.IsZero() {
		clearMemberRequest(&request)
		return MemberRotationRequest{}, ErrMemberRotation
	}
	var err error
	if consumer == "control" {
		request.ControlTLS, err = selectMemberIdentity(credentials.Identity.ControlTLS, member)
	} else {
		request.WorkloadTLS, err = selectMemberIdentity(credentials.Identity.WorkloadTLS, member)
        // Rust's credential endpoint installs current_key into its origin
        // verifier. Customer capability keys must never enter this protocol.
        origin := credentials.OriginProof
        if origin.Version != request.Generation || origin.ID == "" || len(origin.Secret) != 32 || origin.ExpiresAt.IsZero() || origin.ID == credentials.Capability.ID || origin.Reference == credentials.Capability.Reference || bytes.Equal(origin.Secret, credentials.Capability.Key) {
            clearMemberRequest(&request)
            return MemberRotationRequest{}, ErrMemberRotation
        }
        request.ExpiresAt = min(request.ExpiresAt, origin.ExpiresAt.Unix())
        request.CurrentKeyID = origin.ID
        request.CurrentKey = bytes.Clone(origin.Secret)
        previous := credentials.PreviousOriginProof
        if previous.ID != "" {
            if previous.Version == 0 || previous.Version >= origin.Version || previous.ID == origin.ID || len(previous.Secret) != 32 || previous.ExpiresAt.IsZero() || bytes.Equal(previous.Secret, credentials.PreviousCapability.Key) {
                clearMemberRequest(&request)
                return MemberRotationRequest{}, ErrMemberRotation
            }
            request.PreviousGeneration = previous.Version
            request.PreviousKeyID = previous.ID
            request.PreviousKey = bytes.Clone(previous.Secret)
            request.PreviousExpiresAt = previous.ExpiresAt.Unix()
        }
	}
	if err != nil {
		clearMemberRequest(&request)
		return MemberRotationRequest{}, err
	}
	return request, nil
}
func selectMemberIdentity(encoded []byte, member string) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > 16<<20 {
		return nil, ErrMemberRotation
	}
	var principals map[string][]byte
	if json.Unmarshal(encoded, &principals) != nil {
		return nil, ErrMemberRotation
	}
	defer func() {
		for _, value := range principals {
			clear(value)
		}
	}()
	value := principals[member]
	if len(value) == 0 || len(value) > 128<<10 {
		return nil, ErrMemberRotation
	}
	return bytes.Clone(value), nil
}
func clearMemberRequest(request *MemberRotationRequest) {
	clear(request.CurrentKey)
	clear(request.PreviousKey)
	clear(request.WorkloadTLS)
	clear(request.ControlTLS)
	clear(request.TrustBundle)
}

// ControlReloader addresses every configured control process in a region.
// Each endpoint must install DynamicTLS into its actual control listener.
type ControlReloader struct{ gateway *MemberGateway }

var _ security.Reloader = (*ControlReloader)(nil)

func NewControlReloader(config MemberGatewayConfig) (*ControlReloader, error) {
	g, err := NewMemberGateway(config)
	if err != nil {
		return nil, err
	}
	return &ControlReloader{gateway: g}, nil
}
func (r *ControlReloader) Reload(ctx context.Context, region string, credentials security.CredentialSet, key string) error {
	members := r.gateway.regions[region]
	if len(members) == 0 {
		return ErrMemberRotation
	}
	for _, member := range members {
		request, err := memberCredentialRequest(member, "control", "reload", credentials, key+"/"+member)
		if err != nil {
			return err
		}
		_, err = r.gateway.call(ctx, member, request)
		clearMemberRequest(&request)
		if err != nil {
			return err
		}
	}
	return nil
}
func (r *ControlReloader) Verify(ctx context.Context, region string, generation uint64) (security.ConsumerObservation, error) {
	members := r.gateway.regions[region]
	if len(members) == 0 {
		return security.ConsumerObservation{}, ErrMemberRotation
	}
	var result security.ConsumerObservation
	for _, member := range members {
		observation, err := r.gateway.observe(ctx, member, "control", generation)
		if err != nil {
			return security.ConsumerObservation{}, err
		}
		if result.ValidUntil.IsZero() || observation.ValidUntil.Before(result.ValidUntil) {
			result = observation
		}
	}
	return result, nil
}
func (r *ControlReloader) Rollback(ctx context.Context, region string, generation uint64, key string) error {
	return r.gateway.regionAction(ctx, region, "control", "rollback", generation, key)
}
func (r *ControlReloader) Fence(ctx context.Context, region, key string) error {
	return r.gateway.regionAction(ctx, region, "control", "fence", 0, key)
}

func (g *MemberGateway) Close() error {
	if g != nil && g.client != nil {
		g.client.CloseIdleConnections()
	}
	return nil
}
func (r *ControlReloader) Close() error {
	if r == nil {
		return nil
	}
	return r.gateway.Close()
}

package functions

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json/v2"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/internal/release"
)

// ReadSnapshot reads one currently admitted worker over exact-function mTLS.
// The controller supplies the independently observed OCI primary address.
func ReadSnapshot(ctx context.Context, proof release.VerifiedFunction, address netip.AddrPort, certificate tls.Certificate, issuerPEM []byte) (Snapshot, error) {
	if !proof.Valid() || !address.IsValid() || !address.Addr().Is4() || (!address.Addr().IsPrivate() && !address.Addr().IsLoopback()) || address.Port() < 1024 || len(certificate.Certificate) == 0 {
		return Snapshot{}, ErrScope
	}
	claim := proof.Claim()
	identity := "spiffe://terrascale.tech/tenants/" + claim.TenantID + "/functions/" + claim.FunctionID
	leaf, err := x509.ParseCertificate(certificate.Certificate[0])
	if err != nil || len(leaf.URIs) != 1 || leaf.URIs[0].String() != identity || !slices.Equal(leaf.ExtKeyUsage, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}) {
		return Snapshot{}, ErrScope
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(issuerPEM) {
		return Snapshot{}, ErrScope
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	transport := &http.Transport{MaxResponseHeaderBytes: 8 << 10, DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots, Certificates: []tls.Certificate{certificate},
			ServerName: claim.FunctionID + "." + strings.ToLower(claim.TenantID) + ".functions." + strings.ToLower(claim.Cell) + ".terrascale.internal",
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 || len(state.PeerCertificates[0].URIs) != 1 || state.PeerCertificates[0].URIs[0].String() != identity {
					return ErrScope
				}
				return nil
			},
		}}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+address.String()+"/snapshot", nil)
	if err != nil {
		return Snapshot{}, errors.New("build function snapshot request")
	}
	response, err := client.Do(request)
	if err != nil {
		if ctx.Err() != nil {
			return Snapshot{}, ctx.Err()
		}
		return Snapshot{}, errors.New("authenticated function snapshot unavailable")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Snapshot{}, errors.New("function snapshot denied or unavailable")
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, (64<<10)+1))
	if err != nil || len(body) > 64<<10 {
		return Snapshot{}, errors.New("function snapshot exceeds its response bound or is incomplete")
	}
	var snapshot Snapshot
	if err := json.Unmarshal(body, &snapshot, json.RejectUnknownMembers(true)); err != nil || snapshot.SchemaVersion != 1 || snapshot.Manifest.ABI != claim.ABI || snapshot.Manifest.TenantID != claim.TenantID || snapshot.Manifest.FunctionID != claim.FunctionID || snapshot.Manifest.Revision != claim.Revision || snapshot.Manifest.Digest != claim.Digest || !slices.Equal(snapshot.Manifest.Capabilities, claim.Capabilities) || snapshot.ObservedAt.IsZero() || time.Since(snapshot.ObservedAt) > time.Minute || snapshot.ObservedAt.After(time.Now().Add(time.Minute)) || snapshot.Active < 0 || snapshot.Active > MaxConcurrent || snapshot.RuntimeVersion != RuntimeVersion || snapshot.Architecture != "arm64" && snapshot.Architecture != "amd64" || !proof.Valid() {
		return Snapshot{}, errors.New("function snapshot differs from current admitted identity or source time")
	}
	return snapshot, nil
}

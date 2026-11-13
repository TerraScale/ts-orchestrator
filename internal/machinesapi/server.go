// Package machinesapi is the controllers' Machines-style REST API over the
// shared app and machine model (internal/machines), authenticated with
// ts-auth access tokens and scoped to the caller's organization. See
// docs/machines-api.md.
package machinesapi

import (
	_ "embed"
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"slices"

	"github.com/TerraScale/ts-orchestrator/internal/entityid"
)

// Config is controller.machines_api of the controller config.
type Config struct {
	PlatformOrganizationID string `json:"platform_organization_id,omitempty"`
	// ListenAddress is the API's ip:port; the regional load balancer
	// forwards the public host to it. Anything but loopback needs TLS.
	ListenAddress string `json:"listen_address"`
	TLSCertFile   string `json:"tls_cert_file,omitempty"`
	TLSKeyFile    string `json:"tls_key_file,omitempty"`
	// Issuer is ts-auth's issuer exactly as tokens carry it, and Audience
	// the aud value tokens must hold for this API.
	Issuer   string `json:"issuer"`
	Audience string `json:"audience"`
	// JWKSURLs are where the controller fetches ts-auth's signing keys, in
	// order: the local replica first, then the other controllers'. Plain
	// http is allowed only to loopback and private addresses.
	JWKSURLs []string `json:"jwks_urls"`
	// Clients are the ts-auth client IDs whose tokens the API accepts.
	// Every ts-auth token carries every audience, so the client is what
	// keeps another service's tokens out.
	Clients []string `json:"clients"`
	// Members maps each organization ID to the ts-auth subjects (user ULIDs
	// or service client IDs) that act for it. ts-auth tokens carry no
	// organization yet, so this signed map is the tenancy.
	Members map[string][]string `json:"members"`
}

// Validate checks the configuration without binding or fetching anything.
func (c Config) Validate() error {
	listen, err := netip.ParseAddrPort(c.ListenAddress)
	if err != nil {
		return fmt.Errorf("machines_api listen_address: %w", err)
	}
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		return errors.New("machines_api tls_cert_file and tls_key_file go together")
	}
	// Requests carry bearer tokens, so only a loopback listener, which no
	// network sees, may serve plain HTTP.
	if c.TLSCertFile == "" && !listen.Addr().IsLoopback() {
		return errors.New("machines_api needs tls_cert_file and tls_key_file unless it listens on loopback")
	}
	issuer, err := url.Parse(c.Issuer)
	if err != nil || issuer.Scheme != "https" || issuer.Host == "" || issuer.RawQuery != "" || issuer.Fragment != "" {
		return errors.New("machines_api issuer must be an https URL")
	}
	if c.Audience == "" || len(c.Clients) == 0 || slices.Contains(c.Clients, "") {
		return errors.New("machines_api audience and clients are required")
	}
	if len(c.JWKSURLs) == 0 {
		return errors.New("machines_api jwks_urls are required")
	}
	for _, raw := range c.JWKSURLs {
		keys, err := url.Parse(raw)
		if err != nil || keys.Host == "" || keys.User != nil {
			return fmt.Errorf("machines_api jwks_url %q is not a URL", raw)
		}
		address, notIP := netip.ParseAddr(keys.Hostname())
		if keys.Scheme != "https" && (keys.Scheme != "http" || notIP != nil || !address.IsLoopback() && !address.IsPrivate()) {
			return fmt.Errorf("machines_api jwks_url %q must be https, or http to a loopback or private address", raw)
		}
	}
	if c.PlatformOrganizationID != "" && !entityid.Valid(c.PlatformOrganizationID) {
		return errors.New("machines_api platform_organization_id must be a canonical ULID")
	}
	for _, client := range c.Clients {
		if !entityid.Valid(client) {
			return errors.New("machines_api clients must be canonical ULIDs")
		}
	}
	seen := map[string]bool{}
	for org, subjects := range c.Members {
		if !entityid.Valid(org) {
			return fmt.Errorf("machines_api members: organization %q", org)
		}
		for _, subject := range subjects {
			if !entityid.Valid(subject) || seen[subject] {
				return fmt.Errorf("machines_api members: subject %q is empty or in two organizations", subject)
			}
			seen[subject] = true
		}
	}
	return nil
}

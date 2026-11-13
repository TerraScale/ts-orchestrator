package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"time"

	"github.com/TerraScale/ts-orchestrator/third_party/acme"
)

func main() {
	if err := journey(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func journey() error {
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	now := time.Now().UTC().Truncate(time.Second)
	aki, err := hex.DecodeString("69885b6b87464041e1b37b847ba0ae2cde01c8d4")
	if err != nil {
		return err
	}
	root := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "journey CA"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(100 * 24 * time.Hour), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign, SubjectKeyId: aki}
	var cert *x509.Certificate
	var certID string
	for _, serial := range []int64{0x7f, 0x80, 0x87654321} {
		template := &x509.Certificate{SerialNumber: big.NewInt(serial), DNSNames: []string{"ari.e2e.test"}, NotBefore: now.Add(-time.Hour), NotAfter: now.Add(90 * 24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature}
		der, err := x509.CreateCertificate(rand.Reader, template, root, key.Public(), key)
		if err != nil {
			return err
		}
		cert, err = x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		certID, err = authorityCertificateID(cert)
		if err != nil {
			return err
		}
		clientID, err := acme.CertificateID(cert)
		if err != nil || clientID != certID || strings.Contains(clientID, "=") {
			return fmt.Errorf("serial %x identifier: client %q authority %q: %v", serial, clientID, certID, err)
		}
	}
	if certID != "aYhba4dGQEHhs3uEe6CuLN4ByNQ.AIdlQyE" {
		return fmt.Errorf("RFC 9773 section 4.1 example differs: %s", certID)
	}
	fmt.Println("PASS independently derived identifiers, DER sign padding and RFC 9773 example")
	start, end := now.Add(30*24*time.Hour), now.Add(31*24*time.Hour)
	a := &authority{certID: certID, name: cert.DNSNames[0], key: &key.PublicKey, orders: map[string]string{}, nonces: map[string]bool{}}
	a.renewalResponse(renewalWindow(start, end), "30")
	server := httptest.NewServer(http.HandlerFunc(a.serve))
	defer server.Close()
	a.mu.Lock()
	a.base = server.URL
	a.mu.Unlock()
	client := &acme.Client{Key: key, KID: acme.KeyID(server.URL + "/account/1"), DirectoryURL: server.URL + "/directory", HTTPClient: server.Client()}
	public := &acme.Client{DirectoryURL: client.DirectoryURL, HTTPClient: server.Client()}
	before := time.Now()
	info, err := public.RenewalInfo(ctx, cert)
	after := time.Now()
	if err != nil {
		return err
	}
	if !info.SuggestedWindow.Start.Equal(start) || !info.SuggestedWindow.End.Equal(end) || info.ExplanationURL != "https://ca.e2e.test/explanation" || info.RetryAfterHeader != "30" || info.RetryAfter.Before(before.Add(30*time.Second)) || info.RetryAfter.After(after.Add(30*time.Second)) {
		return fmt.Errorf("renewal response or delta-seconds deadline differs: %+v", info)
	}
	a.mu.Lock()
	queries := a.queries
	a.mu.Unlock()
	if queries != 1 {
		return fmt.Errorf("premature renewal recheck: %d requests", queries)
	}
	fmt.Println("PASS unauthenticated renewal GET, window, explanation and 30-second Retry-After deadline")
	date := now.Add(time.Hour).Format(http.TimeFormat)
	a.renewalResponse(renewalWindow(start, end), date)
	info, err = public.RenewalInfo(ctx, cert)
	if err != nil || info.RetryAfterHeader != date || !info.RetryAfter.Equal(now.Add(time.Hour)) {
		return fmt.Errorf("HTTP-date Retry-After deadline differs: %+v: %v", info, err)
	}
	fmt.Println("PASS HTTP-date Retry-After deadline")
	without := &acme.Client{Key: key, KID: client.KID, DirectoryURL: server.URL + "/directory-no-ari", HTTPClient: server.Client()}
	if info, err := without.RenewalInfo(ctx, cert); info != nil || !errors.Is(err, acme.ErrRenewalInfoNotSupported) || !strings.Contains(err.Error(), "not supported") {
		return fmt.Errorf("missing ARI directory: %+v: %v", info, err)
	}
	ids := acme.DomainIDs(cert.DNSNames...)
	if _, err := without.AuthorizeOrder(ctx, ids, acme.WithOrderReplaces(certID)); !errors.Is(err, acme.ErrRenewalInfoNotSupported) {
		return fmt.Errorf("unsupported replacement order: %v", err)
	}
	a.mu.Lock()
	newOrders := a.newOrders
	a.mu.Unlock()
	if newOrders != 0 {
		return fmt.Errorf("unsupported replacement was sent to authority")
	}
	ordinary, err := without.AuthorizeOrder(ctx, ids)
	if err != nil || ordinary.Replaces != "" || ordinary.Status != acme.StatusReady {
		return fmt.Errorf("ordinary order without ARI: %+v: %v", ordinary, err)
	}
	fmt.Println("PASS unsupported ARI error, no unsupported replacement sent, ordinary order unchanged")
	if _, err := client.AuthorizeOrder(ctx, ids, acme.WithOrderReplaces("unknown.certificate")); !authorityError(err, http.StatusBadRequest, "malformed", "unknown replacement certificate") {
		return fmt.Errorf("unknown replacement error not surfaced: %v", err)
	}
	order, err := client.AuthorizeOrder(ctx, ids, acme.WithOrderReplaces(certID))
	if err != nil || order.Replaces != certID || order.Status != acme.StatusReady {
		return fmt.Errorf("replacement not accepted/reflected: %+v: %v", order, err)
	}
	fetched, err := client.GetOrder(ctx, order.URI)
	if err != nil || fetched.Replaces != certID {
		return fmt.Errorf("replacement not reflected on subsequent order request: %+v: %v", fetched, err)
	}
	if _, err := client.AuthorizeOrder(ctx, ids, acme.WithOrderReplaces(certID)); !authorityError(err, http.StatusConflict, "alreadyReplaced", "replacement certificate already has an order") {
		return fmt.Errorf("duplicate replacement error not surfaced: %v", err)
	}
	fmt.Println("PASS signed replacement order accepted once, reflected on retrieval; unknown and alreadyReplaced errors surfaced")
	badWindows := []struct {
		name string
		body map[string]any
	}{
		{"missing window", map[string]any{}},
		{"null window", map[string]any{"suggestedWindow": nil}},
		{"missing start", map[string]any{"suggestedWindow": map[string]any{"end": end}}},
		{"missing end", map[string]any{"suggestedWindow": map[string]any{"start": start}}},
		{"null start", map[string]any{"suggestedWindow": map[string]any{"start": nil, "end": end}}},
		{"invalid timestamp", map[string]any{"suggestedWindow": map[string]any{"start": "tomorrow", "end": end}}},
		{"reversed window", renewalWindow(end, start)},
		{"empty window", renewalWindow(start, start)},
		{"distant window", renewalWindow(now.AddDate(10, 0, 0), now.AddDate(10, 0, 1))},
		{"window before certificate", renewalWindow(cert.NotBefore.Add(-time.Hour), start)},
	}
	for _, bad := range badWindows {
		a.renewalResponse(bad.body, "30")
		if info, err := client.RenewalInfo(ctx, cert); err == nil || info != nil {
			return fmt.Errorf("%s returned to caller: %+v: %v", bad.name, info, err)
		}
		fmt.Println("PASS rejected", bad.name)
	}
	for _, bad := range []string{"", "tomorrow", "-1", "999999999999999999999999999"} {
		a.renewalResponse(renewalWindow(start, end), bad)
		if info, err := client.RenewalInfo(ctx, cert); err == nil || info != nil {
			return fmt.Errorf("invalid Retry-After %q returned to caller: %+v: %v", bad, info, err)
		}
	}
	fmt.Println("PASS rejected missing, invalid, negative and overflowing Retry-After")
	for _, bad := range []*x509.Certificate{nil, {}, {AuthorityKeyId: aki}, {AuthorityKeyId: aki, SerialNumber: big.NewInt(0)}, {AuthorityKeyId: aki, SerialNumber: big.NewInt(-1)}} {
		if _, err := acme.CertificateID(bad); err == nil {
			return fmt.Errorf("invalid certificate accepted")
		}
	}
	expired := *cert
	expired.NotAfter = now.Add(-time.Second)
	a.mu.Lock()
	queries = a.queries
	a.mu.Unlock()
	if info, err := client.RenewalInfo(ctx, &expired); err == nil || info != nil {
		return fmt.Errorf("expired certificate accepted: %+v: %v", info, err)
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.queries != queries {
		return fmt.Errorf("expired certificate queried")
	}
	fmt.Println("PASS invalid certificate identifiers and expired certificate rejected without request")
	fmt.Println("ACME ARI journey: PASS")
	return nil
}

func authorityError(err error, status int, kind, detail string) bool {
	var problem *acme.Error
	return errors.As(err, &problem) && problem.StatusCode == status && problem.ProblemType == "urn:ietf:params:acme:error:"+kind && problem.Detail == detail && problem.Header.Get("Content-Type") == "application/problem+json"
}

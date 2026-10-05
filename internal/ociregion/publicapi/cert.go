package publicapi

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"slices"
	"time"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/ociregion/command"
)

// certSteps plans the load balancer's origin certificate: a Cloudflare
// Origin CA certificate whose private key lives only in the cell's Vault
// secret and on the load balancer.
func (p Provisioner) certSteps(ctx context.Context, d Desired, cloudflare Cloudflare) ([]step, error) {
	if err := d.OriginPull.Validate(); err != nil {
		return nil, err
	}
	for key, value := range map[string]string{"control_compartment": d.Control, "network_compartment": d.Network, "vault": d.Vault, "key": d.Key} {
		if value == "" {
			return nil, fmt.Errorf("plan resource_ids.%s is required", key)
		}
	}
	secret, err := p.secret(ctx, d)
	if err != nil {
		return nil, err
	}
	balancer, err := p.balancer(ctx, d)
	if err != nil {
		return nil, err
	}
	hostnames := []string{d.APIHost, AuthHost}
	var origin, key string
	if secret != nil {
		if origin, key, err = p.originBundle(ctx, secret, hostnames); err != nil {
			return nil, err
		}
	}
	var steps []step
	if secret == nil {
		steps = append(steps, step{fmt.Sprintf("create a Cloudflare Origin CA certificate for %s and %s (RSA 2048, %d days) into vault secret %s",
			d.APIHost, AuthHost, originValidityDays, d.Names.Secret), func(ctx context.Context) error {
			certificate, private, id, err := issueOrigin(ctx, cloudflare, hostnames)
			if err != nil {
				return err
			}
			if err := p.storeSecret(ctx, d, certificate+private); err != nil {
				return fmt.Errorf("%w; revoke unused Origin CA certificate %s in Cloudflare", err, id)
			}
			origin, key = certificate, private
			return nil
		}})
	}
	if balancer != nil {
		if certificates, _ := balancer["certificates"].(map[string]any); certificates[originCertificate] == nil {
			id := fmt.Sprint(balancer["id"])
			steps = append(steps, step{fmt.Sprintf("install certificate %s on %s", originCertificate, d.Names.LB), func(ctx context.Context) error {
				if _, err := p.Client.Call(ctx, "lb", "certificate", "create", "--load-balancer-id", id, "--certificate", command.JSON(map[string]string{
					"certificateName": originCertificate, "publicCertificate": origin, "privateKey": key, "caCertificate": d.OriginPull.CACertificate})); err != nil {
					return err
				}
				_, err := p.await(ctx, d.Names.LB, func() (map[string]any, error) { return p.balancer(ctx, d) }, func(r map[string]any) bool {
					certificates, _ := r["certificates"].(map[string]any)
					return certificates[originCertificate] != nil && r["lifecycle-state"] == "ACTIVE"
				})
				return err
			}})
		}
	}
	return steps, nil
}

// issueOrigin creates a key and has Cloudflare's Origin CA certify it.
func issueOrigin(ctx context.Context, cloudflare Cloudflare, hostnames []string) (certificate, key, id string, err error) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", "", err
	}
	request, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: hostnames[0]}, DNSNames: hostnames}, private)
	if err != nil {
		return "", "", "", err
	}
	issued, id, err := cloudflare.OriginCertificate(ctx, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: request}), hostnames)
	if err != nil {
		return "", "", "", err
	}
	key = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(private)}))
	// Re-encode so the stored bundle always splits back into its two blocks.
	if block, _ := pem.Decode(issued); block != nil {
		certificate = string(pem.EncodeToMemory(&pem.Block{Type: block.Type, Bytes: block.Bytes}))
	}
	if err := checkOrigin(certificate, key, hostnames, time.Now().AddDate(14, 0, 0)); err != nil {
		return "", "", "", fmt.Errorf("Origin CA certificate %s: %w", id, err)
	}
	return certificate, key, id, nil
}

// checkOrigin accepts a certificate for key that names every hostname and
// stays valid until then.
func checkOrigin(certificatePEM, keyPEM string, hostnames []string, until time.Time) error {
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil || keyBlock.Type != "RSA PRIVATE KEY" {
		return errors.New("bundle needs a PEM certificate and RSA private key")
	}
	certificate, err := checkOriginCertificate(certificatePEM, hostnames, until)
	if err != nil {
		return err
	}
	private, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		return err
	}
	if !private.PublicKey.Equal(certificate.PublicKey) {
		return errors.New("certificate does not certify the key")
	}
	return nil
}

// checkOriginCertificate checks the PEM leaf without needing an OCI private
// key. Additional PEM chain certificates do not substitute for that leaf.
func checkOriginCertificate(certificatePEM string, hostnames []string, until time.Time) (*x509.Certificate, error) {
	block, _ := pem.Decode([]byte(certificatePEM))
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("origin needs a PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	for _, name := range hostnames {
		if !slices.Contains(certificate.DNSNames, name) {
			return nil, fmt.Errorf("certificate does not name %s", name)
		}
	}
	if time.Now().Before(certificate.NotBefore) {
		return nil, fmt.Errorf("certificate is not valid before %s", certificate.NotBefore.Format(time.RFC3339))
	}
	if !until.Before(certificate.NotAfter) {
		return nil, fmt.Errorf("certificate expires %s", certificate.NotAfter.Format(time.DateOnly))
	}
	return certificate, nil
}

// secret is the live Vault secret holding the origin bundle, or nil.
func (p Provisioner) secret(ctx context.Context, d Desired) (map[string]any, error) {
	rows, err := p.rows(ctx, "vault", "secret", "list", "--compartment-id", d.Control, "--vault-id", d.Vault, "--name", d.Names.Secret, "--all")
	if err != nil {
		return nil, err
	}
	var found map[string]any
	for _, r := range rows {
		if r["secret-name"] == d.Names.Secret && slices.Contains([]any{"CREATING", "ACTIVE", "UPDATING"}, r["lifecycle-state"]) {
			if found != nil {
				return nil, fmt.Errorf("more than one live vault secret is named %s", d.Names.Secret)
			}
			found = r
		}
	}
	return found, nil
}

func (p Provisioner) storeSecret(ctx context.Context, d Desired, bundle string) error {
	_, err := p.Client.Call(ctx, "vault", "secret", "create-base64", "--compartment-id", d.Control, "--vault-id", d.Vault, "--key-id", d.Key,
		"--secret-name", d.Names.Secret, "--description", "Cloudflare Origin CA certificate and key of "+d.Names.LB,
		"--secret-content-content", base64.StdEncoding.EncodeToString([]byte(bundle)))
	if err != nil {
		return err
	}
	_, err = p.await(ctx, d.Names.Secret, func() (map[string]any, error) { return p.secret(ctx, d) },
		func(r map[string]any) bool { return r["lifecycle-state"] == "ACTIVE" })
	return err
}

// originBundle reads the origin certificate and key from their secret.
func (p Provisioner) originBundle(ctx context.Context, secret map[string]any, hostnames []string) (certificate, key string, err error) {
	if secret["lifecycle-state"] != "ACTIVE" {
		return "", "", fmt.Errorf("vault secret %v is %v, not ACTIVE", secret["secret-name"], secret["lifecycle-state"])
	}
	id, err := command.ID(secret)
	if err != nil {
		return "", "", err
	}
	bundle, err := p.data(ctx, "secrets", "secret-bundle", "get", "--secret-id", id)
	if err != nil {
		return "", "", err
	}
	content, _ := bundle["secret-bundle-content"].(map[string]any)
	wire, err := base64.StdEncoding.DecodeString(fmt.Sprint(content["content"]))
	if err != nil {
		return "", "", fmt.Errorf("vault secret %v content: %w", secret["secret-name"], err)
	}
	block, rest := pem.Decode(wire)
	if block == nil {
		return "", "", fmt.Errorf("vault secret %v holds no PEM bundle", secret["secret-name"])
	}
	certificate, key = string(pem.EncodeToMemory(block)), string(bytes.TrimSpace(rest))+"\n"
	return certificate, key, checkOrigin(certificate, key, hostnames, time.Now())
}

// validCA accepts exactly one CA certificate in PEM.
func validCA(wire string) error {
	block, rest := pem.Decode([]byte(wire))
	if block == nil || block.Type != "CERTIFICATE" || len(bytes.TrimSpace(rest)) != 0 {
		return errors.New("member CA must be one PEM certificate")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil || !certificate.IsCA {
		return errors.New("member CA must be a CA certificate")
	}
	return nil
}

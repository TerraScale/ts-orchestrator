package transitionreceipts

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json/v2"
	"encoding/pem"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"terrascale.tech/orchestrator/src/orchestrator/bootstrapcredentials"
	"terrascale.tech/orchestrator/src/orchestrator/controltransition"
	"terrascale.tech/orchestrator/src/orchestrator/provider"
)

type commandInput struct {
	OwnerPublicKeyFile string `json:"ownerPublicKeyFile"`
	SignedPlanFile     string `json:"signedPlanFile"`
	OCIKeyID           string `json:"ociKeyId"`
	OCIPrivateKeyFile  string `json:"ociPrivateKeyFile"`
}

// Run checks remote host agreements using an explicit operator OCI signing key.
// All network requests use fixed regional Object Storage endpoints and GET.
func Run(ctx context.Context, path string, output io.Writer) error {
	return run(ctx, path, output, nil)
}

func run(ctx context.Context, path string, output io.Writer, client *http.Client) error {
	bad := errors.New("transitionreceipts: remote plan-pin check failed")
	if ctx == nil || output == nil {
		return bad
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	if err := ctx.Err(); err != nil {
		return err
	}
	raw, err := bootstrapcredentials.ReadFile(path, true, 32<<10)
	if err != nil {
		return bad
	}
	defer clear(raw)
	var input commandInput
	if json.Unmarshal(raw, &input, json.RejectUnknownMembers(true)) != nil || len(input.OCIKeyID) == 0 || len(input.OCIKeyID) > 2048 || strings.ContainsAny(input.OCIKeyID, "\r\n\"") {
		return bad
	}
	public, err := bootstrapcredentials.ReadFile(input.OwnerPublicKeyFile, false, 4096)
	if err != nil {
		return bad
	}
	signed, err := bootstrapcredentials.ReadFile(input.SignedPlanFile, true, controltransition.MaximumBytes)
	if err != nil {
		return bad
	}
	plan, err := controltransition.VerifyPlan(public, signed)
	if err != nil || plan.Check(time.Now()) != nil {
		return bad
	}
	key, err := readOCIKey(input.OCIPrivateKeyFile)
	if err != nil {
		return bad
	}
	signer, err := provider.NewInstancePrincipalSigner(input.OCIKeyID, key)
	if err != nil {
		return bad
	}
	p, err := plan.Plan()
	if err != nil {
		return bad
	}
	transports := map[string]*provider.OCIHTTPTransport{}
	for _, d := range p.Destinations {
		host, ok := provider.OCIServiceHost(provider.OCIServiceObjectStorage, d.Objects.OCIRegion)
		if !ok {
			return bad
		}
		config, err := provider.NewOCIServiceTransportConfig(provider.OCIServiceObjectStorage, d.Objects.OCIRegion, "https://"+host)
		if err != nil {
			return bad
		}
		config.Timeout = 10 * time.Second
		transport, err := provider.NewOCIHTTPTransport(config, client, signer)
		if err != nil {
			return bad
		}
		transports[d.Region] = transport
	}
	verified, err := ReadPlanPins(ctx, plan, transports)
	if err != nil {
		return bad
	}
	checked := time.Now().UTC()
	digests, err := verified.ReceiptDigests(checked)
	if err != nil {
		return bad
	}
	summary := struct {
		Status        string    `json:"status"`
		PlanSHA256    string    `json:"planSha256"`
		ReceiptSHA256 []string  `json:"receiptSha256"`
		CheckedAt     time.Time `json:"checkedAt"`
	}{"plan-pins-verified", plan.Digest(), digests, checked}
	encoded, err := json.Marshal(summary)
	if err != nil {
		return bad
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := plan.Check(time.Now()); err != nil {
		return bad
	}
	encoded = append(encoded, '\n')
	if n, err := output.Write(encoded); err != nil || n != len(encoded) {
		return bad
	}
	return nil
}

func readOCIKey(path string) (*rsa.PrivateKey, error) {
	bad := errors.New("transitionreceipts: invalid protected OCI key")
	raw, err := bootstrapcredentials.ReadFile(path, true, 32<<10)
	if err != nil {
		return nil, bad
	}
	defer clear(raw)
	block, rest := pem.Decode(raw)
	if block == nil || len(rest) != 0 || len(block.Headers) != 0 {
		return nil, bad
	}
	defer clear(block.Bytes)
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, bad
		}
		return key, nil
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		key, ok := parsed.(*rsa.PrivateKey)
		if err != nil || !ok {
			return nil, bad
		}
		return key, nil
	default:
		return nil, bad
	}
}

package ocireconcile

import "terrascale.tech/orchestrator/src/orchestrator/provider"

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"terrascale.tech/orchestrator/src/orchestrator/errs"
)

// OCI reconcilers create and repair the estate's OCI half (D-67). The legacy
// estate reader in oci_estate.go verified a reviewed, pre-built estate; these
// reconcilers invert that stance: the orchestrator is now the authority that
// creates and repairs those resources. Real cloud access goes through
// OCIHTTPTransport gateways; tests use gateway fakes and never touch OCI.

// OCIActionKind identifies one planned reconciler step for drift alerts,
// bootstrap output, and tests.
type OCIActionKind string

const (
	OCIActionCreateCompartment   OCIActionKind = "create-compartment"
	OCIActionCreateVCN           OCIActionKind = "create-vcn"
	OCIActionCreateSubnet        OCIActionKind = "create-subnet"
	OCIActionCreateNSG           OCIActionKind = "create-nsg"
	OCIActionReplaceNSGRules     OCIActionKind = "replace-nsg-rules"
	OCIActionCreateNATGateway    OCIActionKind = "create-nat-gateway"
	OCIActionCreateRouteTable    OCIActionKind = "create-route-table"
	OCIActionReplaceRouteRules   OCIActionKind = "replace-route-rules"
	OCIActionAttachSubnetRoute   OCIActionKind = "attach-subnet-route-table"
	OCIActionLaunchMember        OCIActionKind = "launch-member"
	OCIActionStartMember         OCIActionKind = "start-member"
	OCIActionTerminateMember     OCIActionKind = "terminate-member"
	OCIActionCreateVolume        OCIActionKind = "create-volume"
	OCIActionExpandVolume        OCIActionKind = "expand-volume"
	OCIActionAttachVolume        OCIActionKind = "attach-volume"
	OCIActionDetachAttachment    OCIActionKind = "detach-attachment"
	OCIActionCreateBucket        OCIActionKind = "create-bucket"
	OCIActionSetBucketVersioning OCIActionKind = "set-bucket-versioning"
	OCIActionSetBucketLifecycle  OCIActionKind = "set-bucket-lifecycle"
	OCIActionCreateVault         OCIActionKind = "create-vault"
	OCIActionCreateVaultKey      OCIActionKind = "create-vault-key"
	OCIActionCreateCertificate   OCIActionKind = "create-certificate"
	OCIActionRenewCertificate    OCIActionKind = "renew-certificate"
)

// OCIAction is one planned step. Payloads are the concrete per-resource action
// types declared in each reconciler file; a reconciler's Apply rejects action
// kinds it does not own.
type OCIAction interface {
	Kind() OCIActionKind
	Summary() string
}

// OCIPlan is the ordered gap between declared and observed state.
type OCIPlan struct {
	Actions []OCIAction
}

func (p OCIPlan) Empty() bool { return len(p.Actions) == 0 }

// Kinds lists planned action kinds in order, for drift reporting and tests.
func (p OCIPlan) Kinds() []OCIActionKind {
	kinds := make([]OCIActionKind, 0, len(p.Actions))
	for _, action := range p.Actions {
		kinds = append(kinds, action.Kind())
	}
	return kinds
}

// OCIReconciler is the local seam every resource reconciler implements:
// observe provider state, diff it against declared state into a plan, and
// apply that plan idempotently. The sibling reconcile loop's provider
// interface absorbs this shape when it lands; that adoption stays in this
// file so reconciler bodies never change.
type OCIReconciler[D any, O any] interface {
	Observe(ctx context.Context, declared D) (O, error)
	Reconcile(ctx context.Context, declared D, observed O) (OCIPlan, error)
	Apply(ctx context.Context, declared D, observed O, plan OCIPlan) error
}

// OCIShapeCapacityError means OCI reported no host capacity for the requested
// shape. Ampere A1 exhaustion is routine, so the compute reconciler retries
// the declared fallback shape automatically (D-69).
type OCIShapeCapacityError struct{ Shape string }

func (e *OCIShapeCapacityError) Error() string {
	return "OCI shape has no host capacity"
}

// OCIQuotaError means a tenancy service limit or quota rejected the request.
// Quota is never worked around automatically; it needs an owner decision.
type OCIQuotaError struct{ Code string }

func (e *OCIQuotaError) Error() string {
	return "OCI quota or service limit rejected the request"
}

// classifyOCIRejection maps a decoded OCI REST rejection onto a reconciler
// error. Rejection detail is matched, never propagated: OCI error bodies can
// echo request metadata.
func classifyOCIRejection(status int, code, message string) error {
	if status == http.StatusTooManyRequests || code == "TooManyRequests" || code == "LimitExceeded" || code == "QuotaExceeded" {
		return &OCIQuotaError{Code: code}
	}
	if strings.Contains(strings.ToLower(message), "out of host capacity") {
		return &OCIShapeCapacityError{}
	}
	return &provider.InvalidDataError{Message: "OCI request was rejected"}
}

type ociRejectionDocument struct {
	Code        string `json:"code"`
	Message     string `json:"message"`
	Status      int    `json:"status,omitempty"`
	TrailerCode string `json:"codeInTrailer"`
}

// doOCIJSON performs one signed JSON request against a service transport and
// decodes the bounded response body into out. A nil out is allowed for calls
// whose response body is irrelevant. Non-2xx responses become classified
// reconciler errors.
func doOCIJSON[T any](ctx context.Context, transport *provider.OCIHTTPTransport, method, path string, payload any, headers map[string]string, out *T) error {
	if transport == nil {
		return &provider.InvalidOperationError{Message: "OCI transport is unavailable"}
	}
	var request io.Reader
	if payload != nil {
		raw, err := json.Marshal(payload)
		if err != nil {
			return &errs.Argument{Message: "OCI request payload is invalid"}
		}
		request = bytes.NewReader(raw)
	}
	resp, err := transport.DoWithHeaders(ctx, method, path, request, headers)
	if err != nil {
		return err
	}
	raw, err := provider.ReadBoundedBody(resp, transport.Config.MaxBodyBytes)
	if err != nil {
		return err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		var rejection ociRejectionDocument
		_ = json.Unmarshal(raw, &rejection)
		if rejection.Code == "" {
			rejection.Code = rejection.TrailerCode
		}
		return classifyOCIRejection(resp.StatusCode, rejection.Code, rejection.Message)
	}
	if out == nil || len(raw) == 0 {
		return nil
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return &provider.InvalidDataError{Message: "OCI response is invalid"}
	}
	return nil
}

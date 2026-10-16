package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/oracle/oci-go-sdk/v65/core"

	"github.com/TerraScale/ts-orchestrator/internal/nodescale"
	"github.com/TerraScale/ts-orchestrator/internal/oci"
)

func checkpointCapacityGrowth(compartment string, store nodescale.RecordStore, journal *oci.KVJournal) func(context.Context, nodescale.Recipe, core.UpdateInstancePoolRequest) (core.UpdateInstancePoolRequest, error) {
	return func(ctx context.Context, recipe nodescale.Recipe, request core.UpdateInstancePoolRequest) (core.UpdateInstancePoolRequest, error) {
		record, _, err := store.Load(ctx)
		if err != nil {
			return request, err
		}
		if record.Action == nil || record.Action.Kind != nodescale.Up || record.Recipe == nil || record.Reservation == nil ||
			record.Recipe.SHA256() != recipe.SHA256() || record.Reservation.OperationID != record.Action.ID ||
			record.Reservation.RecipeSHA256 != recipe.SHA256() || record.Reservation.CompartmentID != compartment ||
			!strings.EqualFold(record.Reservation.Cell, recipe.Cell) || request.InstancePoolId == nil || request.Size == nil ||
			record.TargetFrom == nil || *request.Size != *record.TargetFrom+1 {
			return request, fmt.Errorf("%w: exact durable action, receipt and target are required before OCI growth", nodescale.ErrCapacityPending)
		}
		receipt := record.Reservation
		prior, found, err := journal.GetCapacityRequest(ctx, record.Action.ID)
		if err != nil {
			return request, err
		}
		started := record.Action.Started.UTC()
		if found {
			// An unknown outcome replays the original precondition and token, never a refreshed request.
			request.IfMatch, request.OpcRetryToken = new(prior.IfMatch), new(prior.RetryToken)
			started = prior.StartedAt
		}
		digest, err := capacityGrowthRequestSHA256(request)
		if err != nil {
			return request, err
		}
		checkpoint := oci.CapacityRequest{OperationID: record.Action.ID, RecipeSHA256: recipe.SHA256(),
			LogicalScopeSHA256: receipt.ScopeSHA256, ResolvedScopeSHA256: receipt.ResolvedScopeSHA256,
			BindingSHA256: receipt.BindingSHA256, GrantSHA256: receipt.GrantSHA256, GrantGeneration: receipt.GrantGeneration,
			TenancyID: receipt.TenancyID, Region: oci.Region(strings.ToUpper(recipe.Cell)), CompartmentID: compartment,
			PoolID: *request.InstancePoolId, RequestSHA256: digest, RetryToken: *request.OpcRetryToken, IfMatch: *request.IfMatch,
			Currency: receipt.Currency, ReservedMonthlyCents: receipt.MonthlyCents, QuoteSHA256: receipt.QuoteSHA256,
			TargetSize: uint32(*request.Size), StartedAt: started}
		if found && checkpoint != prior {
			return request, fmt.Errorf("%w: exact growth request differs from its original durable checkpoint", nodescale.ErrCapacityPending)
		}
		return request, journal.RecordCapacityRequest(ctx, checkpoint)
	}
}

func capacityGrowthRequestSHA256(request core.UpdateInstancePoolRequest) (string, error) {
	if request.InstancePoolId == nil || request.IfMatch == nil || request.OpcRetryToken == nil || request.Size == nil ||
		*request.Size < 1 || *request.Size > nodescale.MaxPoolNodes {
		return "", fmt.Errorf("%w: incomplete exact OCI growth request", nodescale.ErrCapacityPending)
	}
	raw, err := request.HTTPRequest(http.MethodPut, "/instancePools/{instancePoolId}", nil, nil)
	if err != nil {
		return "", err
	}
	defer raw.Body.Close()
	body, err := io.ReadAll(raw.Body)
	if err != nil {
		return "", err
	}
	// Pin the SDK payload and effect-bearing headers; signing headers vary per attempt.
	digest := sha256.New()
	_, _ = fmt.Fprintf(digest, "%s\n%s\n%s\n%s\n%s\n", raw.Method, raw.URL.EscapedPath(),
		raw.Header.Get("Content-Type"), raw.Header.Get("if-match"), raw.Header.Get("opc-retry-token"))
	_, _ = digest.Write(body)
	return hex.EncodeToString(digest.Sum(nil)), nil
}

package ocireconcile

import "terrascale.tech/orchestrator/src/orchestrator/provider"

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// Certificates uses its documented collection object, unlike OCI Core's
// bare arrays. Its continuation token still belongs in opc-next-page.
func (g *OCICertificatesGateway) listCertificateSummaries(ctx context.Context) ([]ociCertSummaryDocument, error) {
	query := url.Values{"compartmentId": {g.CompartmentID}, "limit": {strconv.Itoa(g.MaxListed)}}
	result := []ociCertSummaryDocument{}
	seenPages, seenIDs := map[string]bool{}, map[string]bool{}
	for page := 0; page < 128; page++ {
		response, err := g.Certs.Do(ctx, http.MethodGet, "/20210224/certificates?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		if err := provider.CheckOCIStatus(response, "certificate listing"); err != nil {
			return nil, err
		}
		raw, err := provider.ReadBoundedBody(response, g.Certs.Config.MaxBodyBytes)
		if err != nil {
			return nil, err
		}
		var collection struct {
			Items []ociCertSummaryDocument `json:"items"`
		}
		if json.Unmarshal(raw, &collection) != nil || collection.Items == nil || len(result)+len(collection.Items) > g.MaxListed {
			return nil, &provider.InvalidDataError{Message: "OCI certificate collection exceeds its bound or is invalid"}
		}
		for _, item := range collection.Items {
			if item.ID == "" || seenIDs[item.ID] {
				return nil, &provider.InvalidDataError{Message: "OCI certificate collection repeats an identity"}
			}
			seenIDs[item.ID] = true
		}
		result = append(result, collection.Items...)
		next := response.Header.Get("opc-next-page")
		if next == "" {
			return result, nil
		}
		if len(next) > 4096 || strings.ContainsAny(next, "\r\n\x00") || seenPages[next] {
			return nil, &provider.InvalidDataError{Message: "OCI certificate pagination is invalid"}
		}
		seenPages[next] = true
		query.Set("page", next)
	}
	return nil, &provider.InvalidDataError{Message: "OCI certificate pagination exceeds its bound"}
}

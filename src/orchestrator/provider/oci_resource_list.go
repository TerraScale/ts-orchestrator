package provider

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// Resource reconciliations must consider every page and must not treat a
// repeated identity as a second resource or evidence of absence.
func ReadOCIResourceList[T any](ctx context.Context, transport *OCIHTTPTransport, path string, query url.Values, identity func(T) string) ([]T, error) {
	items, err := ReadOCICollection[T](ctx, transport, path, query)
	if err != nil {
		return nil, err
	}
	seen := make(map[string]bool, len(items))
	for _, item := range items {
		id := identity(item)
		if id == "" || seen[id] {
			return nil, &InvalidDataError{Message: "OCI resource list has missing or repeated identity"}
		}
		seen[id] = true
	}
	return items, nil
}

func ReadOCICollection[T any](ctx context.Context, transport *OCIHTTPTransport, path string, query url.Values) ([]T, error) {
	var result []T
	seen := map[string]bool{}
	for page := 0; page < 128; page++ {
		response, err := transport.Do(ctx, http.MethodGet, path+"?"+query.Encode(), nil)
		if err != nil {
			return nil, err
		}
		body, err := ReadBoundedBody(response, transport.Config.MaxBodyBytes)
		if err != nil {
			return nil, err
		}
		if response.StatusCode != http.StatusOK {
			return nil, errors.New("provider: OCI control receipt read failed")
		}
		var items []T
		if json.Unmarshal(body, &items) != nil || items == nil || len(result)+len(items) > 10000 {
			return nil, errors.New("provider: invalid OCI control receipt collection")
		}
		result = append(result, items...)
		next := response.Header.Get("opc-next-page")
		if next == "" {
			return result, nil
		}
		if len(next) > 4096 || strings.ContainsAny(next, "\r\n\x00") || seen[next] {
			return nil, errors.New("provider: invalid OCI receipt pagination")
		}
		seen[next] = true
		query.Set("page", next)
	}
	return nil, errors.New("provider: OCI receipt pagination limit")
}

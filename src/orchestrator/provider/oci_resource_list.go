package provider

import (
	"context"
	"net/url"
)

// Resource reconciliations must consider every page and must not treat a
// repeated identity as a second resource or evidence of absence.
func readOCIResourceList[T any](ctx context.Context, transport *OCIHTTPTransport, path string, query url.Values, identity func(T) string) ([]T, error) {
	items, err := readBootstrapControlList[T](ctx, transport, path, query)
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

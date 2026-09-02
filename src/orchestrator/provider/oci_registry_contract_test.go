package provider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestOCIRegistryRequiresCanonicalScopedAuthority(t *testing.T) {
	for _, test := range []struct {
		name     string
		username string
		token    string
	}{
		{name: "missing namespace", username: "runner", token: "token"},
		{name: "empty principal", username: "tenancy/", token: "token"},
		{name: "empty principal segment", username: "tenancy/team//runner", token: "token"},
		{name: "uppercase namespace", username: "Tenancy/runner", token: "token"},
		{name: "username colon", username: "tenancy/run:ner", token: "token"},
		{name: "username control", username: "tenancy/run\tner", token: "token"},
		{name: "token whitespace", username: "tenancy/runner", token: " token"},
		{name: "token control", username: "tenancy/runner", token: "to\x00ken"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewOCIRegistryTokenSigner(test.username, test.token); err == nil {
				t.Fatal("invalid registry credential was accepted")
			}
		})
	}

	newTransport := func(t *testing.T) *OCIHTTPTransport {
		t.Helper()
		transport := testOCITransport(t, OCIServiceRegistry, func(*http.Request) (*http.Response, error) {
			t.Fatal("adapter construction sent a provider request")
			return nil, io.ErrUnexpectedEOF
		})
		signer, err := NewOCIRegistryTokenSigner("tenancy/runner", "registry-token")
		if err != nil {
			t.Fatal(err)
		}
		transport.Signer = signer
		return transport
	}
	for _, test := range []struct {
		name  string
		scope OCIRegistryScope
	}{
		{name: "missing namespace", scope: OCIRegistryScope{Repositories: []string{"member"}}},
		{name: "credential namespace mismatch", scope: OCIRegistryScope{Namespace: "another", Repositories: []string{"member"}}},
		{name: "missing repositories", scope: OCIRegistryScope{Namespace: "tenancy"}},
		{name: "duplicate repository", scope: OCIRegistryScope{Namespace: "tenancy", Repositories: []string{"member", "member"}}},
		{name: "uppercase repository", scope: OCIRegistryScope{Namespace: "tenancy", Repositories: []string{"Member"}}},
		{name: "repository traversal", scope: OCIRegistryScope{Namespace: "tenancy", Repositories: []string{"team/../member"}}},
		{name: "repository empty segment", scope: OCIRegistryScope{Namespace: "tenancy", Repositories: []string{"team//member"}}},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewOCIRegistryAdapter(newTransport(t), test.scope); err == nil {
				t.Fatal("invalid registry scope was accepted")
			}
		})
	}

	t.Run("missing token signer", func(t *testing.T) {
		transport := newTransport(t)
		transport.Signer = nil
		if _, err := NewOCIRegistryAdapter(transport, OCIRegistryScope{Namespace: "tenancy", Repositories: []string{"member"}}); err == nil {
			t.Fatal("registry adapter accepted a missing OCIR credential")
		}
	})
}

func TestOCIRegistryRejectsUnscopedOrMutableRequestsBeforeIO(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)
	for _, test := range []struct {
		name       string
		repository string
		reference  string
	}{
		{name: "other namespace", repository: "another/member", reference: digest},
		{name: "unlisted repository", repository: "tenancy/private", reference: digest},
		{name: "uppercase", repository: "tenancy/Member", reference: digest},
		{name: "encoded separator", repository: "tenancy/member%2fother", reference: digest},
		{name: "traversal", repository: "tenancy/../member", reference: digest},
		{name: "empty segment", repository: "tenancy//member", reference: digest},
		{name: "mutable tag", repository: "tenancy/member", reference: "latest"},
		{name: "uppercase digest", repository: "tenancy/member", reference: "sha256:" + strings.Repeat("A", 64)},
		{name: "digest suffix", repository: "tenancy/member", reference: digest + "0"},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			transport := testOCITransport(t, OCIServiceRegistry, func(*http.Request) (*http.Response, error) {
				calls++
				return nil, io.ErrUnexpectedEOF
			})
			adapter := testRegistryAdapter(t, transport)
			if _, err := adapter.PullManifest(context.Background(), RegistryManifestRequest{Repository: test.repository, Reference: test.reference}); err == nil {
				t.Fatal("invalid manifest request was accepted")
			}
			if _, _, err := adapter.PullBlob(context.Background(), RegistryBlobRequest{Repository: test.repository, Digest: test.reference}); err == nil {
				t.Fatal("invalid blob request was accepted")
			}
			if calls != 0 {
				t.Fatalf("invalid requests sent %d provider calls", calls)
			}
		})
	}
}

func validRegistryManifestBody(mediaType string) string {
	descriptor := `{"mediaType":"application/vnd.oci.image.config.v1+json","digest":"sha256:` + strings.Repeat("b", 64) + `","size":2}`
	if mediaType == ociImageIndexMediaType || mediaType == dockerImageListMediaType {
		return `{"schemaVersion":2,"mediaType":"` + mediaType + `","manifests":[` + descriptor + `]}`
	}
	return `{"schemaVersion":2,"mediaType":"` + mediaType + `","config":` + descriptor + `,"layers":[]}`
}

func TestOCIRegistryManifestRequiresCanonicalProviderTruth(t *testing.T) {
	validBody := func(mediaType string) string {
		return validRegistryManifestBody(mediaType)
	}
	for _, mediaType := range []string{ociImageManifestMediaType, ociImageIndexMediaType, dockerImageManifestMediaType, dockerImageListMediaType} {
		t.Run("valid "+mediaType, func(t *testing.T) {
			body := validBody(mediaType)
			digest := "sha256:" + objectSHA256([]byte(body))
			transport := testOCITransport(t, OCIServiceRegistry, func(request *http.Request) (*http.Response, error) {
				if request.Header.Get("Accept") != registryManifestAccept || request.Header.Get("Accept-Encoding") != "identity" {
					t.Fatalf("manifest request headers = %v", request.Header)
				}
				return testHTTPResponse(http.StatusOK, body, http.Header{"Content-Length": {stringInt(len(body))}, "Docker-Content-Digest": {digest}, "Content-Type": {mediaType}}), nil
			})
			manifest, err := testRegistryAdapter(t, transport).PullManifest(context.Background(), RegistryManifestRequest{Repository: "tenancy/member", Reference: digest})
			if err != nil || manifest.Digest != digest || manifest.MediaType != mediaType || string(manifest.Content) != body {
				t.Fatalf("manifest=%+v err=%v", manifest, err)
			}
		})
	}

	tests := []struct {
		name        string
		status      int
		body        string
		digest      []string
		length      []string
		contentType []string
		encoding    []string
	}{
		{name: "non-200", status: http.StatusPartialContent},
		{name: "missing digest", digest: []string{}},
		{name: "duplicate digest", digest: []string{"request", "request"}},
		{name: "uppercase digest", digest: []string{"uppercase"}},
		{name: "missing length", length: []string{}},
		{name: "duplicate length", length: []string{"request", "request"}},
		{name: "leading-zero length", length: []string{"leading-zero"}},
		{name: "declared short", length: []string{"short"}},
		{name: "declared long", length: []string{"long"}},
		{name: "missing content type", contentType: []string{}},
		{name: "duplicate content type", contentType: []string{ociImageManifestMediaType, ociImageManifestMediaType}},
		{name: "unsupported content type", contentType: []string{"application/json"}},
		{name: "parameterized content type", contentType: []string{ociImageManifestMediaType + "; charset=utf-8"}},
		{name: "gzip encoding", encoding: []string{"gzip"}},
		{name: "duplicate identity encoding", encoding: []string{"identity", "identity"}},
		{name: "empty body", body: ""},
		{name: "malformed body", body: `{"schemaVersion":`},
		{name: "schema one", body: `{"schemaVersion":1,"mediaType":"` + ociImageManifestMediaType + `"}`},
		{name: "missing body media type", body: `{"schemaVersion":2}`},
		{name: "wrong-case schema field", body: `{"SchemaVersion":2,"mediaType":"` + ociImageManifestMediaType + `"}`},
		{name: "wrong-case media field", body: `{"schemaVersion":2,"MediaType":"` + ociImageManifestMediaType + `"}`},
		{name: "mismatched body media type", body: `{"schemaVersion":2,"mediaType":"` + ociImageIndexMediaType + `"}`},
		{name: "manifest missing config", body: `{"schemaVersion":2,"mediaType":"` + ociImageManifestMediaType + `","layers":[]}`},
		{name: "manifest missing layers", body: `{"schemaVersion":2,"mediaType":"` + ociImageManifestMediaType + `","config":{"mediaType":"application/test","digest":"sha256:` + strings.Repeat("b", 64) + `","size":2}}`},
		{name: "index empty", body: `{"schemaVersion":2,"mediaType":"` + ociImageIndexMediaType + `","manifests":[]}`},
		{name: "descriptor digest invalid", body: `{"schemaVersion":2,"mediaType":"` + ociImageManifestMediaType + `","config":{"mediaType":"application/test","digest":"sha256:no","size":2},"layers":[]}`},
		{name: "descriptor negative size", body: `{"schemaVersion":2,"mediaType":"` + ociImageManifestMediaType + `","config":{"mediaType":"application/test","digest":"sha256:` + strings.Repeat("b", 64) + `","size":-1},"layers":[]}`},
		{name: "descriptor external URL", body: `{"schemaVersion":2,"mediaType":"` + ociImageManifestMediaType + `","config":{"mediaType":"application/test","digest":"sha256:` + strings.Repeat("b", 64) + `","size":2,"urls":["https://attacker.test/blob"]},"layers":[]}`},
		{name: "descriptor embedded data", body: `{"schemaVersion":2,"mediaType":"` + ociImageManifestMediaType + `","config":{"mediaType":"application/test","digest":"sha256:` + strings.Repeat("b", 64) + `","size":2,"data":"YQ=="},"layers":[]}`},
		{name: "descriptor wrong-case digest", body: `{"schemaVersion":2,"mediaType":"` + ociImageManifestMediaType + `","config":{"mediaType":"application/test","Digest":"sha256:` + strings.Repeat("b", 64) + `","size":2},"layers":[]}`},
		{name: "duplicate schema", body: `{"schemaVersion":2,"schemaVersion":2,"mediaType":"` + ociImageManifestMediaType + `"}`},
		{name: "case duplicate media type", body: `{"schemaVersion":2,"mediaType":"` + ociImageManifestMediaType + `","MediaType":"` + ociImageManifestMediaType + `"}`},
		{name: "nested duplicate", body: `{"schemaVersion":2,"mediaType":"` + ociImageManifestMediaType + `","annotations":{"key":"one","key":"two"}}`},
		{name: "trailing document", body: validBody(ociImageManifestMediaType) + `{}`},
	}
	tests = append(tests, struct {
		name        string
		status      int
		body        string
		digest      []string
		length      []string
		contentType []string
		encoding    []string
	}{
		name: "excessive nesting",
		body: `{"schemaVersion":2,"mediaType":"` + ociImageManifestMediaType + `","nested":` +
			strings.Repeat("[", 66) + "0" + strings.Repeat("]", 66) + `}`,
	})
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			body := test.body
			if body == "" && test.name != "empty body" {
				body = validBody(ociImageManifestMediaType)
			}
			digest := "sha256:" + objectSHA256([]byte(body))
			digestHeaders := test.digest
			if digestHeaders == nil {
				digestHeaders = []string{digest}
			} else {
				for index, value := range digestHeaders {
					switch value {
					case "request":
						digestHeaders[index] = digest
					case "uppercase":
						digestHeaders[index] = "sha256:" + strings.Repeat("A", 64)
					}
				}
			}
			contentType := test.contentType
			if contentType == nil {
				contentType = []string{ociImageManifestMediaType}
			}
			length := test.length
			if length == nil {
				length = []string{stringInt(len(body))}
			} else {
				for index, value := range length {
					switch value {
					case "request":
						length[index] = stringInt(len(body))
					case "leading-zero":
						length[index] = "0" + stringInt(len(body))
					case "short":
						length[index] = stringInt(len(body) - 1)
					case "long":
						length[index] = stringInt(len(body) + 1)
					}
				}
			}
			status := test.status
			if status == 0 {
				status = http.StatusOK
			}
			transport := testOCITransport(t, OCIServiceRegistry, func(*http.Request) (*http.Response, error) {
				return testHTTPResponse(status, body, http.Header{
					"Content-Length":        length,
					"Docker-Content-Digest": digestHeaders,
					"Content-Type":          contentType,
					"Content-Encoding":      test.encoding,
				}), nil
			})
			manifest, err := testRegistryAdapter(t, transport).PullManifest(context.Background(), RegistryManifestRequest{Repository: "tenancy/member", Reference: digest})
			if err == nil || manifest.Digest != "" || manifest.MediaType != "" || manifest.Content != nil {
				t.Fatalf("manifest=%+v err=%v", manifest, err)
			}
		})
	}
}

type registryInterruptedBody struct{ sent bool }

func (body *registryInterruptedBody) Read(buffer []byte) (int, error) {
	if body.sent {
		return 0, io.ErrUnexpectedEOF
	}
	body.sent = true
	return copy(buffer, "a"), nil
}

func (*registryInterruptedBody) Close() error { return nil }

func TestOCIRegistryBlobRequiresCanonicalMetadataAndVerifiedEOF(t *testing.T) {
	for _, test := range []struct {
		name        string
		status      int
		body        string
		expected    string
		length      []string
		digest      []string
		contentType []string
		encoding    []string
		interrupted bool
		wantPullErr bool
		wantReadErr bool
	}{
		{name: "valid", body: "abc", expected: "abc"},
		{name: "zero length", body: "", expected: ""},
		{name: "short body", body: "ab", expected: "abc", wantReadErr: true},
		{name: "long body", body: "abcd", expected: "abc", wantReadErr: true},
		{name: "corrupt body", body: "abd", expected: "abc", wantReadErr: true},
		{name: "transport loss", expected: "abc", interrupted: true, wantReadErr: true},
		{name: "non-200", status: http.StatusPartialContent, body: "abc", expected: "abc", wantPullErr: true},
		{name: "missing length", body: "abc", expected: "abc", length: []string{}, wantPullErr: true},
		{name: "duplicate length", body: "abc", expected: "abc", length: []string{"3", "3"}, wantPullErr: true},
		{name: "leading-zero length", body: "abc", expected: "abc", length: []string{"03"}, wantPullErr: true},
		{name: "missing digest", body: "abc", expected: "abc", digest: []string{}, wantPullErr: true},
		{name: "duplicate digest", body: "abc", expected: "abc", digest: []string{"request", "request"}, wantPullErr: true},
		{name: "wrong digest header", body: "abc", expected: "abc", digest: []string{"sha256:" + strings.Repeat("b", 64)}, wantPullErr: true},
		{name: "missing content type", body: "abc", expected: "abc", contentType: []string{}, wantPullErr: true},
		{name: "duplicate content type", body: "abc", expected: "abc", contentType: []string{"application/octet-stream", "application/octet-stream"}, wantPullErr: true},
		{name: "parameterized content type", body: "abc", expected: "abc", contentType: []string{"application/octet-stream; charset=binary"}, wantPullErr: true},
		{name: "wrong content type", body: "abc", expected: "abc", contentType: []string{"application/json"}, wantPullErr: true},
		{name: "gzip encoding", body: "abc", expected: "abc", encoding: []string{"gzip"}, wantPullErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			digest := "sha256:" + objectSHA256([]byte(test.expected))
			length := test.length
			if length == nil {
				length = []string{stringInt(len(test.expected))}
			}
			digestHeaders := test.digest
			if digestHeaders == nil {
				digestHeaders = []string{digest}
			} else {
				for index, value := range digestHeaders {
					if value == "request" {
						digestHeaders[index] = digest
					}
				}
			}
			transport := testOCITransport(t, OCIServiceRegistry, func(request *http.Request) (*http.Response, error) {
				if request.Header.Get("Accept") != "application/octet-stream" || request.Header.Get("Accept-Encoding") != "identity" {
					t.Fatalf("blob request headers = %v", request.Header)
				}
				status := test.status
				if status == 0 {
					status = http.StatusOK
				}
				contentType := test.contentType
				if contentType == nil {
					contentType = []string{"application/octet-stream"}
				}
				response := testHTTPResponse(status, test.body, http.Header{
					"Content-Length":        length,
					"Content-Type":          contentType,
					"Docker-Content-Digest": digestHeaders,
					"Content-Encoding":      test.encoding,
				})
				if test.interrupted {
					response.Body = &registryInterruptedBody{}
				}
				return response, nil
			})
			reader, size, err := testRegistryAdapter(t, transport).PullBlob(context.Background(), RegistryBlobRequest{Repository: "tenancy/member", Digest: digest})
			if test.wantPullErr {
				if err == nil || reader != nil || size != 0 {
					t.Fatalf("reader=%v size=%d err=%v", reader, size, err)
				}
				return
			}
			if err != nil || size != int64(len(test.expected)) {
				t.Fatalf("size=%d err=%v", size, err)
			}
			content, readErr := io.ReadAll(reader)
			closeErr := reader.Close()
			if (readErr != nil) != test.wantReadErr || (closeErr != nil) != test.wantReadErr {
				t.Fatalf("body=%q readErr=%v closeErr=%v", content, readErr, closeErr)
			}
			if !test.wantReadErr && string(content) != test.expected {
				t.Fatalf("body=%q want=%q", content, test.expected)
			}
		})
	}

	t.Run("early close fails", func(t *testing.T) {
		content := "abc"
		digest := "sha256:" + objectSHA256([]byte(content))
		transport := testOCITransport(t, OCIServiceRegistry, func(*http.Request) (*http.Response, error) {
			return testHTTPResponse(http.StatusOK, content, http.Header{"Content-Length": {"3"}, "Content-Type": {"application/octet-stream"}, "Docker-Content-Digest": {digest}}), nil
		})
		reader, _, err := testRegistryAdapter(t, transport).PullBlob(context.Background(), RegistryBlobRequest{Repository: "tenancy/member", Digest: digest})
		if err != nil {
			t.Fatal(err)
		}
		var invalid *InvalidDataError
		if err := reader.Close(); !errors.As(err, &invalid) {
			t.Fatalf("early close err=%v", err)
		}
	})
}

func stringInt(value int) string {
	if value == 0 {
		return "0"
	}
	var digits [20]byte
	index := len(digits)
	for value > 0 {
		index--
		digits[index] = byte('0' + value%10)
		value /= 10
	}
	return string(digits[index:])
}

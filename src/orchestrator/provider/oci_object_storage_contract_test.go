package provider

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func objectMetadataHeaders(content []byte) http.Header {
	return http.Header{
		"Content-Encoding":           {"identity"},
		"Content-Length":             {stringInt(len(content))},
		"Content-Type":               {"application/octet-stream"},
		"Etag":                       {"object-etag"},
		"Opc-Meta-Terrascale-Sha256": {objectSHA256(content)},
	}
}

func objectListResponse(status int, body string, headers http.Header) *http.Response {
	if headers == nil {
		headers = make(http.Header)
	}
	if status == http.StatusOK {
		if len(headers.Values("Content-Encoding")) == 0 {
			headers["Content-Encoding"] = []string{"identity"}
		}
		if len(headers.Values("Content-Length")) == 0 {
			headers["Content-Length"] = []string{stringInt(len(body))}
		}
		if len(headers.Values("Content-Type")) == 0 {
			headers["Content-Type"] = []string{"application/json"}
		}
	}
	return testHTTPResponse(status, body, headers)
}

func TestOCIObjectStorageSnapshotsTransportSignerAndScope(t *testing.T) {
	object := ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "gru/ledger.json"}
	authorized, hostile := 0, 0
	transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
		authorized++
		if request.URL.Scheme != "https" || request.URL.Host != "objectstorage.sa-saopaulo-1.oraclecloud.com" ||
			!strings.Contains(request.Header.Get("Authorization"), `keyId="ocid1.instance.oc1.sa-saopaulo-1.testsigner"`) {
			t.Fatalf("snapshotted authority changed: url=%s authorization=%q", request.URL, request.Header.Get("Authorization"))
		}
		return testHTTPResponse(http.StatusOK, "", objectMetadataHeaders([]byte("ledger"))), nil
	})
	adapter := testObjectAdapter(t, transport, testJournal(t), object)

	originalSigner := transport.Signer.(*InstancePrincipalSigner)
	transport.Config.Service = OCIServiceCore
	transport.Config.Region = "us-sanjose-1"
	transport.Config.Endpoint.Host = "attacker.test"
	transport.Config.MaxBodyBytes = 1
	transport.Client.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
		hostile++
		if request.Header.Get("Authorization") != "" {
			t.Fatal("signed credential reached caller-mutated transport")
		}
		return nil, io.ErrUnexpectedEOF
	})
	originalSigner.KeyID = "attacker"
	originalSigner.Key = nil
	transport.Signer = nil

	if _, found, err := adapter.HeadObject(context.Background(), object); err != nil || !found {
		t.Fatalf("snapshotted HEAD found=%v err=%v", found, err)
	}
	if authorized != 1 || hostile != 0 {
		t.Fatalf("authorized=%d hostile=%d", authorized, hostile)
	}
	for _, outside := range []ObjectRef{
		{Namespace: "other", Bucket: "ledger", Name: object.Name},
		{Namespace: "namespace", Bucket: "private", Name: object.Name},
		{Namespace: "namespace", Bucket: "ledger", Name: "unreserved"},
	} {
		if _, _, err := adapter.HeadObject(context.Background(), outside); err == nil {
			t.Fatalf("outside object %+v was authorized", outside)
		}
	}
	if authorized != 1 || hostile != 0 {
		t.Fatal("scope rejection performed provider I/O")
	}
}

func TestOCIObjectStorage404NeedsBoundedContradictionSafeListProof(t *testing.T) {
	object := ObjectRef{Namespace: "namespace", Bucket: "backups", Name: "gru/db/snapshot"}
	for _, test := range []struct {
		name      string
		listBody  string
		headers   http.Header
		wantFound bool
		wantErr   bool
	}{
		{name: "complete absence", listBody: `{"objects":[]}`},
		{name: "head contradiction", listBody: `{"objects":[{"name":"gru/db/snapshot"}]}`, wantErr: true},
		{name: "null objects", listBody: `{"objects":null}`, wantErr: true},
		{name: "duplicate property", listBody: `{"objects":[],"objects":[]}`, wantErr: true},
		{name: "outside prefix", listBody: `{"objects":[{"name":"another"}]}`, wantErr: true},
		{name: "duplicate content type", listBody: `{"objects":[]}`, headers: http.Header{"Content-Type": {"application/json", "application/json"}}, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
				calls++
				if request.Method == http.MethodHead {
					return testHTTPResponse(http.StatusNotFound, "", nil), nil
				}
				if request.Method != http.MethodGet || request.URL.Query().Get("prefix") != object.Name || request.URL.Query().Get("limit") != stringInt(maximumOCIListResults) {
					t.Fatalf("unbounded list request %s", request.URL)
				}
				return objectListResponse(http.StatusOK, test.listBody, test.headers), nil
			})
			adapter := testObjectAdapter(t, transport, testJournal(t), object)
			_, found, err := adapter.HeadObject(context.Background(), object)
			if found != test.wantFound || (err != nil) != test.wantErr || calls != 2 {
				t.Fatalf("found=%v err=%v calls=%d", found, err, calls)
			}
		})
	}

	t.Run("continuation cycle", func(t *testing.T) {
		calls := 0
		transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
			calls++
			if request.Method == http.MethodHead {
				return testHTTPResponse(http.StatusNotFound, "", nil), nil
			}
			return objectListResponse(http.StatusOK, `{"objects":[],"nextStartWith":"gru/db/snapshot-next"}`, nil), nil
		})
		adapter := testObjectAdapter(t, transport, testJournal(t), object)
		if _, _, err := adapter.HeadObject(context.Background(), object); err == nil || calls != 3 {
			t.Fatalf("cycle err=%v calls=%d", err, calls)
		}
	})
}

func TestOCIObjectStoragePut412ReconcilesOrFailsKnown(t *testing.T) {
	content := []byte("backup")
	object := ObjectRef{Namespace: "namespace", Bucket: "backups", Name: "gru/db/backup"}
	for _, test := range []struct {
		name        string
		headContent []byte
		wantErr     bool
	}{
		{name: "exact existing object", headContent: content},
		{name: "conflicting existing object", headContent: []byte("other"), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			puts := 0
			transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
				switch request.Method {
				case http.MethodPut:
					puts++
					return testHTTPResponse(http.StatusPreconditionFailed, "", nil), nil
				case http.MethodHead:
					return testHTTPResponse(http.StatusOK, "", objectMetadataHeaders(test.headContent)), nil
				default:
					return nil, io.ErrUnexpectedEOF
				}
			})
			journal := testJournal(t)
			adapter := testObjectAdapter(t, transport, journal, object)
			request := ObjectPutRequest{Object: object, Content: content, SHA256: objectSHA256(content)}
			request.Mutation = testMutation("object.put", ObjectPutMutationScope(request), ObjectPutMutationFingerprint(request), 1)
			_, err := adapter.PutObject(context.Background(), request)
			if (err != nil) != test.wantErr || puts != 1 {
				t.Fatalf("puts=%d err=%v", puts, err)
			}
			if _, err := adapter.PutObject(context.Background(), request); (err != nil) != test.wantErr || puts != 1 {
				t.Fatalf("durable replay puts=%d err=%v", puts, err)
			}
		})
	}
}

func TestOCIObjectStorageSubmittedMutationsReconcileWithoutReemission(t *testing.T) {
	content := []byte("durable-object")
	object := ObjectRef{Namespace: "namespace", Bucket: "backups", Name: "gru/db/backup"}

	t.Run("put", func(t *testing.T) {
		puts := 0
		transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodPut {
				puts++
				t.Fatal("submitted PUT was re-emitted")
			}
			return testHTTPResponse(http.StatusOK, "", objectMetadataHeaders(content)), nil
		})
		journal := testJournal(t)
		adapter := testObjectAdapter(t, transport, journal, object)
		request := ObjectPutRequest{Object: object, Content: content, SHA256: objectSHA256(content)}
		request.Mutation = testMutation("object.put", ObjectPutMutationScope(request), ObjectPutMutationFingerprint(request), 1)
		if _, err := journal.Prepare(context.Background(), request.Mutation); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.MarkSubmitted(context.Background(), request.Mutation); err != nil {
			t.Fatal(err)
		}
		if _, err := adapter.PutObject(context.Background(), request); err != nil || puts != 0 {
			t.Fatalf("puts=%d err=%v", puts, err)
		}
	})

	t.Run("delete", func(t *testing.T) {
		deletes := 0
		transport := testOCITransport(t, OCIServiceObjectStorage, func(request *http.Request) (*http.Response, error) {
			if request.Method == http.MethodDelete {
				deletes++
				t.Fatal("submitted DELETE was re-emitted")
			}
			if request.Method == http.MethodHead {
				return testHTTPResponse(http.StatusNotFound, "", nil), nil
			}
			return objectListResponse(http.StatusOK, `{"objects":[]}`, nil), nil
		})
		journal := testJournal(t)
		adapter := testObjectAdapter(t, transport, journal, object)
		request := ObjectDeleteRequest{Object: object, IfMatch: "object-etag"}
		request.Mutation = testMutation("object.delete", ObjectDeleteMutationScope(request), ObjectDeleteMutationFingerprint(request), 1)
		if _, err := journal.Prepare(context.Background(), request.Mutation); err != nil {
			t.Fatal(err)
		}
		if _, err := journal.MarkSubmitted(context.Background(), request.Mutation); err != nil {
			t.Fatal(err)
		}
		if err := adapter.DeleteObject(context.Background(), request); err != nil || deletes != 0 {
			t.Fatalf("deletes=%d err=%v", deletes, err)
		}
	})
}

func TestOCIObjectStorageGetVerifiesMetadataLengthDigestAndEOF(t *testing.T) {
	object := ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "gru/ledger"}
	content := []byte("verified-ledger")
	for _, test := range []struct {
		name       string
		body       string
		headers    http.Header
		earlyClose bool
		wantErr    bool
	}{
		{name: "verified EOF", body: string(content), headers: objectMetadataHeaders(content)},
		{name: "truncated", body: "short", headers: objectMetadataHeaders(content), wantErr: true},
		{name: "extra bytes", body: string(content) + "x", headers: objectMetadataHeaders(content), wantErr: true},
		{name: "digest mismatch", body: string(content), headers: objectMetadataHeaders([]byte("same-length-bad")), wantErr: true},
		{name: "early close", body: string(content), headers: objectMetadataHeaders(content), earlyClose: true, wantErr: true},
		{name: "duplicate length", body: string(content), headers: func() http.Header {
			h := objectMetadataHeaders(content)
			h["Content-Length"] = []string{stringInt(len(content)), stringInt(len(content))}
			return h
		}(), wantErr: true},
		{name: "missing identity encoding", body: string(content), headers: func() http.Header { h := objectMetadataHeaders(content); h.Del("Content-Encoding"); return h }(), wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			transport := testOCITransport(t, OCIServiceObjectStorage, func(*http.Request) (*http.Response, error) {
				return testHTTPResponse(http.StatusOK, test.body, test.headers), nil
			})
			adapter := testObjectAdapter(t, transport, testJournal(t), object)
			reader, _, err := adapter.GetObject(context.Background(), object)
			if err == nil && test.earlyClose {
				err = reader.Close()
			} else if err == nil {
				_, err = io.ReadAll(reader)
				closeErr := reader.Close()
				if err == nil {
					err = closeErr
				}
			}
			if (err != nil) != test.wantErr {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestOCIObjectStorageNeverFollowsRedirects(t *testing.T) {
	object := ObjectRef{Namespace: "namespace", Bucket: "ledger", Name: "gru/ledger"}
	calls := 0
	transport := testOCITransport(t, OCIServiceObjectStorage, func(*http.Request) (*http.Response, error) {
		calls++
		return testHTTPResponse(http.StatusTemporaryRedirect, "", http.Header{"Location": {"https://attacker.test/steal"}}), nil
	})
	adapter := testObjectAdapter(t, transport, testJournal(t), object)
	_, _, err := adapter.HeadObject(context.Background(), object)
	var invalid *InvalidOperationError
	if !errors.As(err, &invalid) || calls != 1 {
		t.Fatalf("redirect err=%v calls=%d", err, calls)
	}
}

package ociclient

import (
	"io"
	"net/http"
	"testing"

	"github.com/oracle/oci-go-sdk/v65/common"
)

type fakeResponse struct{ raw *http.Response }

type fakeServiceError struct{ status int }

func (e fakeServiceError) Error() string           { return http.StatusText(e.status) }
func (e fakeServiceError) GetHTTPStatusCode() int  { return e.status }
func (e fakeServiceError) GetCode() string         { return "" }
func (e fakeServiceError) GetOpcRequestID() string { return "" }

func attempt(method string, status int, token string, err error) common.OCIOperationResponse {
	request, _ := http.NewRequest(method, "https://iaas.sa-saopaulo-1.oraclecloud.com/x", nil)
	if token != "" {
		request.Header.Set("opc-retry-token", token)
	}
	raw := &http.Response{StatusCode: status, Request: request, Header: http.Header{}}
	if err == nil && status >= 300 {
		err = fakeServiceError{status: status}
	}
	return common.OCIOperationResponse{Response: fakeResponse{raw: raw}, Error: err, AttemptNumber: 1}
}

func TestShouldRetryNeverReplaysUnsafeMutations(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		status int
		token  string
		want   bool
	}{
		{"success", http.MethodGet, 200, "", false},
		{"read throttled", http.MethodGet, 429, "", true},
		{"delete throttled", http.MethodDelete, 429, "", true},
		{"put throttled", http.MethodPut, 429, "", true},
		{"read 503", http.MethodGet, 503, "", true},
		{"head 500", http.MethodHead, 500, "", true},
		{"read 501", http.MethodGet, 501, "", false},
		{"read 404", http.MethodGet, 404, "", false},
		{"read 409", http.MethodGet, 409, "", false},
		{"tokened post 502", http.MethodPost, 502, "token", true},
		{"untokened post 502", http.MethodPost, 502, "", false},
		{"delete 503", http.MethodDelete, 503, "", false},
		{"put 500", http.MethodPut, 500, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ShouldRetry(attempt(tc.method, tc.status, tc.token, nil)); got != tc.want {
				t.Fatalf("ShouldRetry=%v want %v", got, tc.want)
			}
		})
	}
	if !ShouldRetry(common.OCIOperationResponse{Error: fakeServiceError{status: 429}}) {
		t.Fatal("429 without a raw response was not retried")
	}
	if ShouldRetry(common.OCIOperationResponse{Error: fakeServiceError{status: 503}}) {
		t.Fatal("5xx on an unknown request was retried")
	}
	if !ShouldRetry(attempt(http.MethodGet, 0, "", io.ErrUnexpectedEOF)) {
		t.Fatal("transport error on a read was not retried")
	}
	if ShouldRetry(attempt(http.MethodPost, 0, "", io.ErrUnexpectedEOF)) {
		t.Fatal("transport error on an untokened post was retried")
	}
	parts := IdempotentPutRetryPolicy(RetryOptions{})
	if !parts.ShouldRetryOperation(attempt(http.MethodPut, 503, "", nil)) ||
		parts.ShouldRetryOperation(attempt(http.MethodDelete, 503, "", nil)) ||
		parts.ShouldRetryOperation(attempt(http.MethodPost, 503, "", nil)) {
		t.Fatal("idempotent PUT policy classified a method incorrectly")
	}
}

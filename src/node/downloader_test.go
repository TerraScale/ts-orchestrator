package node

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type downloaderRoundTripper func(*http.Request) (*http.Response, error)

func (f downloaderRoundTripper) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type trackingDownloaderBody struct {
	reader *strings.Reader
	read   int
	closed bool
}

func (b *trackingDownloaderBody) Read(p []byte) (int, error) {
	n, err := b.reader.Read(p)
	b.read += n
	return n, err
}

func (b *trackingDownloaderBody) Close() error {
	b.closed = true
	return nil
}

func TestHTTPDownloaderRejectsRedirectsWithoutFollowingThem(t *testing.T) {
	targetHits := 0
	target := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetHits++
	}))
	defer target.Close()
	redirect := httptest.NewTLSServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		http.Redirect(response, request, target.URL+"?token=redirect-secret", http.StatusFound)
	}))
	defer redirect.Close()

	downloader := HTTPDownloader{Client: redirect.Client(), AllowedHosts: []string{redirect.Listener.Addr().String()}, MaxBytes: 64}
	_, err := downloader.Download(context.Background(), Artifact{URL: redirect.URL + "/artifact"})
	if err == nil || !strings.Contains(err.Error(), "HTTP 302") {
		t.Fatalf("redirect error = %v", err)
	}
	if targetHits != 0 {
		t.Fatalf("redirect target was contacted %d times", targetHits)
	}
	if strings.Contains(err.Error(), redirect.URL) || strings.Contains(err.Error(), "redirect-secret") {
		t.Fatalf("redirect error leaked URL or secret: %v", err)
	}
}

func TestHTTPDownloaderRejectsUntrustedHost(t *testing.T) {
	called := false
	client := &http.Client{Transport: downloaderRoundTripper(func(*http.Request) (*http.Response, error) {
		called = true
		return nil, nil
	})}
	downloader := HTTPDownloader{Client: client, AllowedHosts: []string{"release.example"}, MaxBytes: 64}
	_, err := downloader.Download(context.Background(), Artifact{URL: "https://other.example/artifact"})
	if err == nil || !strings.Contains(err.Error(), "host is not trusted") {
		t.Fatalf("untrusted host error = %v", err)
	}
	if called {
		t.Fatal("untrusted host reached the HTTP client")
	}
}

func TestHTTPDownloaderRejectsOversizedChunkedResponseAndClosesBody(t *testing.T) {
	body := &trackingDownloaderBody{reader: strings.NewReader("123456789")}
	client := &http.Client{Transport: downloaderRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body, ContentLength: -1}, nil
	})}
	downloader := HTTPDownloader{Client: client, MaxBytes: 4}
	_, err := downloader.Download(context.Background(), Artifact{URL: "https://release.invalid/artifact"})
	if err == nil || !strings.Contains(err.Error(), "exceeds 4 bytes") {
		t.Fatalf("oversized response error = %v", err)
	}
	if body.read > 5 {
		t.Fatalf("bounded reader consumed %d bytes", body.read)
	}
	if !body.closed {
		t.Fatal("oversized response body was not closed")
	}
}

func TestHTTPDownloaderRejectsDeclaredOversizedResponseBeforeRead(t *testing.T) {
	body := &trackingDownloaderBody{reader: strings.NewReader("123456789")}
	client := &http.Client{Transport: downloaderRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusOK, Body: body, ContentLength: 9}, nil
	})}
	downloader := HTTPDownloader{Client: client, MaxBytes: 4}
	_, err := downloader.Download(context.Background(), Artifact{URL: "https://release.invalid/artifact"})
	if err == nil || !strings.Contains(err.Error(), "exceeds 4 bytes") {
		t.Fatalf("declared oversized response error = %v", err)
	}
	if body.read != 0 {
		t.Fatalf("declared oversized response was read: %d bytes", body.read)
	}
	if !body.closed {
		t.Fatal("declared oversized response body was not closed")
	}
}

func TestHTTPDownloaderRejectsNonSuccessStatusAndRedactsURL(t *testing.T) {
	body := &trackingDownloaderBody{reader: strings.NewReader("provider secret")}
	client := &http.Client{Transport: downloaderRoundTripper(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: http.StatusBadGateway, Body: body}, nil
	})}
	secretURL := "https://release.invalid/artifact?token=status-secret"
	_, err := (HTTPDownloader{Client: client, MaxBytes: 64}).Download(context.Background(), Artifact{URL: secretURL})
	if err == nil || !strings.Contains(err.Error(), "HTTP 502") {
		t.Fatalf("status error = %v", err)
	}
	if strings.Contains(err.Error(), secretURL) || strings.Contains(err.Error(), "status-secret") {
		t.Fatalf("status error leaked URL or secret: %v", err)
	}
	if !body.closed {
		t.Fatal("status response body was not closed")
	}
}

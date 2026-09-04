package vmimage

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const maxDownloadDiagnostic = 512

var (
	diagnosticURLPattern = regexp.MustCompile(`(?i)https?://[^\s]+`)
	diagnosticBearer     = regexp.MustCompile(`(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]+`)
	diagnosticKeyValue   = regexp.MustCompile(`(?i)\b(token|password|passwd|secret|api[_-]?key|authorization|cookie)\s*[:=]\s*[^\s,;]+`)
)

// Downloader is the injectable network boundary for pinned VM artifacts.
// Implementations receive a typed URL, writer, and hard byte ceiling. They do
// not choose a destination path or run a command.
type Downloader interface {
	Download(context.Context, string, io.Writer, int64) error
}

// DownloaderFunc adapts a function to Downloader for deterministic tests.
type DownloaderFunc func(context.Context, string, io.Writer, int64) error

func (function DownloaderFunc) Download(ctx context.Context, source string, destination io.Writer, maxBytes int64) error {
	return function(ctx, source, destination, maxBytes)
}

type httpDownloader struct {
	client                     *http.Client
	allowGitHubReleaseRedirect bool
}

func (downloader httpDownloader) Download(ctx context.Context, source string, destination io.Writer, maxBytes int64) error {
	if ctx == nil {
		return errors.New("vmimage: download context is nil")
	}
	if destination == nil {
		return errors.New("vmimage: download destination is nil")
	}
	if maxBytes <= 0 || maxBytes > maxArtifactSize {
		return errors.New("vmimage: download limit is outside the permitted range")
	}
	client := downloader.client
	if client == nil {
		client = &http.Client{Timeout: 10 * time.Minute}
	} else {
		clone := *client
		client = &clone
	}
	client.CheckRedirect = downloader.redirectPolicy(source)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, source, nil)
	if err != nil {
		return newDownloadError("create artifact request", source, err)
	}
	response, err := client.Do(request)
	if err != nil {
		return newDownloadError("fetch pinned artifact", source, err)
	}
	if response.Body == nil {
		return errors.New("vmimage: pinned artifact response has no body")
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return fmt.Errorf("vmimage: pinned artifact source answered HTTP %d", response.StatusCode)
	}
	if response.ContentLength >= 0 && response.ContentLength != maxBytes {
		return fmt.Errorf("vmimage: pinned artifact declares %d bytes, expected %d", response.ContentLength, maxBytes)
	}
	written, err := io.Copy(destination, contextReader{ctx: ctx, reader: io.LimitReader(response.Body, maxBytes+1)})
	if err != nil {
		return newDownloadError("read pinned artifact", source, err)
	}
	if written > maxBytes {
		return fmt.Errorf("vmimage: pinned artifact exceeds %d-byte limit", maxBytes)
	}
	return nil
}

func (downloader httpDownloader) redirectPolicy(source string) func(*http.Request, []*http.Request) error {
	return func(request *http.Request, via []*http.Request) error {
		if !downloader.allowGitHubReleaseRedirect {
			return errors.New("vmimage: artifact redirects are not allowed")
		}
		// GitHub's immutable release URL necessarily redirects once to its
		// signed asset host. The archive size and digest still bind the bytes.
		if len(via) != 1 || via[0].URL.String() != source || via[0].URL.Scheme != "https" ||
			via[0].URL.Host != "github.com" || request.Method != http.MethodGet ||
			request.URL.Scheme != "https" || request.URL.Host != "release-assets.githubusercontent.com" ||
			request.URL.User != nil || request.URL.Fragment != "" {
			return errors.New("vmimage: Firecracker release redirect is not allowed")
		}
		return nil
	}
}

func downloadPinned(ctx context.Context, downloader Downloader, source, target, wantDigest string, wantSize int64, mode os.FileMode) error {
	if ctx == nil {
		return errors.New("vmimage: download context is nil")
	}
	if downloader == nil {
		return errors.New("vmimage: downloader is nil")
	}
	if !validDigest(wantDigest) || wantSize <= 0 || wantSize > maxArtifactSize {
		return errors.New("vmimage: download pin is invalid")
	}
	if err := rejectSymlinkAncestors(filepath.Dir(target)); err != nil {
		return fmt.Errorf("vmimage: download target is unsafe: %w", err)
	}
	if _, err := os.Lstat(target); err == nil {
		return fmt.Errorf("vmimage: download target already exists: %w", os.ErrExist)
	} else if !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("vmimage: inspect download target: %w", err)
	}

	temporary, err := createDownloadStaging(target, mode)
	if err != nil {
		return err
	}
	removeTemporary := true
	defer func() {
		if removeTemporary {
			_ = os.Remove(temporary)
		}
	}()
	file, err := os.OpenFile(temporary, os.O_WRONLY, 0)
	if err != nil {
		return fmt.Errorf("vmimage: open download staging file: %w", err)
	}
	hash := sha256.New()
	limited := &boundedWriter{ctx: ctx, destination: io.MultiWriter(file, hash), remaining: wantSize}
	if err := downloader.Download(ctx, source, limited, wantSize); err != nil {
		_ = file.Close()
		if contextError := ctx.Err(); contextError != nil {
			return contextError
		}
		return newDownloadError("download pinned artifact", source, err)
	}
	if err := ctx.Err(); err != nil {
		_ = file.Close()
		return err
	}
	if limited.written != wantSize || hex.EncodeToString(hash.Sum(nil)) != wantDigest {
		_ = file.Close()
		return fmt.Errorf("vmimage: downloaded bytes do not match pinned size and sha256 (got %d bytes, want %d)", limited.written, wantSize)
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return fmt.Errorf("vmimage: sync downloaded artifact: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("vmimage: close downloaded artifact: %w", err)
	}
	if err := publishDownload(temporary, target); err != nil {
		return fmt.Errorf("vmimage: publish downloaded artifact: %w", err)
	}
	removeTemporary = false
	if err := syncDir(filepath.Dir(target)); err != nil {
		// The target was created by this invocation, so it is safe to remove it
		// if the containing directory could not be made durable. The file was
		// fully checked before publication and can never be partial.
		_ = os.Remove(target)
		return fmt.Errorf("vmimage: sync download parent: %w", err)
	}
	return nil
}

func createDownloadStaging(target string, mode os.FileMode) (string, error) {
	parent := filepath.Dir(target)
	base := filepath.Base(target)
	for attempt := 0; attempt < 8; attempt++ {
		file, err := os.CreateTemp(parent, "."+base+".download-*")
		if err != nil {
			return "", fmt.Errorf("vmimage: create download staging file: %w", err)
		}
		path := file.Name()
		if err := file.Chmod(mode.Perm()); err != nil {
			_ = file.Close()
			_ = os.Remove(path)
			return "", fmt.Errorf("vmimage: set download staging mode: %w", err)
		}
		if err := file.Close(); err != nil {
			_ = os.Remove(path)
			return "", fmt.Errorf("vmimage: close download staging file: %w", err)
		}
		return path, nil
	}
	return "", errors.New("vmimage: create download staging file: too many collisions")
}

// publishDownload links the fully synced staging inode into place. A hard
// link is an atomic no-replace operation on the same filesystem and, unlike
// os.Rename, cannot overwrite a concurrently installed artifact.
func publishDownload(staging, target string) error {
	if err := os.Link(staging, target); err != nil {
		return err
	}
	if err := os.Remove(staging); err != nil {
		// The target is still complete. Keep it visible rather than risking a
		// replacement or reporting a partial artifact.
		return fmt.Errorf("remove download staging file: %w", err)
	}
	return nil
}

type redactedDownloadError struct {
	operation string
	source    string
	cause     error
}

func newDownloadError(operation, source string, cause error) error {
	if cause == nil {
		return nil
	}
	return &redactedDownloadError{operation: operation, source: source, cause: cause}
}

func (err *redactedDownloadError) Error() string {
	return fmt.Sprintf("vmimage: %s %s: %s", err.operation, redactDownloadSource(err.source), redactDownloadDiagnostic(err.cause.Error()))
}

func (err *redactedDownloadError) Unwrap() error { return err.cause }

func redactDownloadSource(source string) string {
	parsed, err := url.Parse(source)
	if err != nil || parsed.Scheme == "" || parsed.Hostname() == "" {
		return "<redacted-source>"
	}
	path := parsed.EscapedPath()
	if path == "" {
		path = "/"
	}
	if len(path) > maxDownloadDiagnostic/2 {
		path = path[:maxDownloadDiagnostic/2] + "..."
	}
	return strings.ToLower(parsed.Scheme) + "://" + strings.ToLower(parsed.Hostname()) + path
}

func redactDownloadDiagnostic(value string) string {
	value = diagnosticURLPattern.ReplaceAllStringFunc(value, redactDownloadSource)
	value = diagnosticBearer.ReplaceAllString(value, "$1 [redacted]")
	value = diagnosticKeyValue.ReplaceAllString(value, "$1=[redacted]")
	if len(value) > maxDownloadDiagnostic {
		value = value[:maxDownloadDiagnostic] + "..."
	}
	return value
}

type boundedWriter struct {
	ctx         context.Context
	destination io.Writer
	remaining   int64
	written     int64
}

func (writer *boundedWriter) Write(data []byte) (int, error) {
	if writer.ctx != nil {
		if err := writer.ctx.Err(); err != nil {
			return 0, err
		}
	}
	if int64(len(data)) > writer.remaining {
		if writer.remaining > 0 {
			allowed := int(writer.remaining)
			written, err := writer.destination.Write(data[:allowed])
			if written < 0 || written > allowed {
				return 0, errors.New("vmimage: download writer returned an invalid byte count")
			}
			writer.remaining -= int64(written)
			writer.written += int64(written)
			if err != nil {
				return written, err
			}
			return written, errors.New("vmimage: downloaded artifact exceeds pinned size")
		}
		return 0, errors.New("vmimage: downloaded artifact exceeds pinned size")
	}
	written, err := writer.destination.Write(data)
	if written < 0 || written > len(data) {
		return 0, errors.New("vmimage: download writer returned an invalid byte count")
	}
	writer.remaining -= int64(written)
	writer.written += int64(written)
	if err == nil && written != len(data) {
		return written, io.ErrShortWrite
	}
	return written, err
}

func validateRemoteURL(value string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Hostname() == "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("source must be an HTTPS URL without credentials or a fragment")
	}
	if parsed.Host != parsed.Hostname() || parsed.Host != strings.ToLower(parsed.Host) {
		return errors.New("source host must be canonical and must not contain a port")
	}
	return nil
}

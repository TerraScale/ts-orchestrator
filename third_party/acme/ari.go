// Copyright 2026 The TerraScale Authors. All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package acme

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// ErrRenewalInfoNotSupported indicates that the directory does not advertise ARI.
var ErrRenewalInfoNotSupported = errors.New("acme: renewal information not supported")

// RenewalInfo contains the RFC 9773 suggested renewal window and checking deadline.
// RetryAfterHeader preserves the server's value; RetryAfter is its absolute time.
// The caller is responsible for scheduling future checks and renewal attempts.
type RenewalInfo struct {
	SuggestedWindow struct {
		Start time.Time
		End   time.Time
	}
	ExplanationURL   string
	RetryAfterHeader string
	RetryAfter       time.Time
}

// CertificateID constructs the identifier specified by RFC 9773, Section 4.1.
// The serial is the DER INTEGER value, including a leading zero when necessary.
func CertificateID(cert *x509.Certificate) (string, error) {
	if cert == nil || len(cert.AuthorityKeyId) == 0 || cert.SerialNumber == nil || cert.SerialNumber.Sign() <= 0 {
		return "", errors.New("acme: certificate requires an authority key identifier and positive serial number")
	}
	serial := cert.SerialNumber.Bytes()
	if serial[0]&0x80 != 0 {
		serial = append([]byte{0}, serial...)
	}
	return base64.RawURLEncoding.EncodeToString(cert.AuthorityKeyId) + "." + base64.RawURLEncoding.EncodeToString(serial), nil
}

// RenewalInfo fetches renewal information using an unauthenticated GET (RFC 9773).
// It rejects missing or invalid Retry-After values and windows outside the
// certificate's validity. It never waits or schedules a subsequent request.
// Callers must not query certificates they already consider replaced.
func (c *Client) RenewalInfo(ctx context.Context, cert *x509.Certificate) (*RenewalInfo, error) {
	id, err := CertificateID(cert)
	if err != nil {
		return nil, err
	}
	if !time.Now().Before(cert.NotAfter) {
		return nil, errors.New("acme: cannot fetch renewal information for an expired certificate")
	}
	dir, err := c.Discover(ctx)
	if err != nil {
		return nil, err
	}
	if dir.RenewalInfoURL == "" {
		return nil, ErrRenewalInfoNotSupported
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(dir.RenewalInfoURL, "/")+"/"+id, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	res, err := c.doNoRetry(ctx, req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return nil, responseError(res)
	}
	body, err := io.ReadAll(io.LimitReader(res.Body, (1<<20)+1))
	if err != nil {
		return nil, err
	}
	if len(body) > 1<<20 {
		return nil, errors.New("acme: renewal information response too large")
	}
	var info RenewalInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("acme: invalid renewal information: %w", err)
	}
	start, end := info.SuggestedWindow.Start, info.SuggestedWindow.End
	if start.IsZero() || end.IsZero() || !end.After(start) || start.Before(cert.NotBefore) || end.After(cert.NotAfter) {
		return nil, errors.New("acme: invalid suggested renewal window")
	}
	info.RetryAfterHeader = res.Header.Get("Retry-After")
	now := time.Now()
	if seconds, err := strconv.ParseUint(info.RetryAfterHeader, 10, 64); err == nil && seconds <= uint64((1<<63-1)/int64(time.Second)) {
		info.RetryAfter = now.Add(time.Duration(seconds) * time.Second)
	} else if deadline, err := http.ParseTime(info.RetryAfterHeader); err == nil {
		info.RetryAfter = deadline
	} else {
		return nil, errors.New("acme: invalid or missing renewal information Retry-After")
	}
	return &info, nil
}

// WithOrderReplaces identifies the predecessor certificate (RFC 9773, Section 5).
// Use CertificateID to construct the identifier. Unsupported CAs return
// ErrRenewalInfoNotSupported before any newOrder request is sent.
func WithOrderReplaces(id string) OrderOption {
	return orderReplacesOpt(id)
}

type orderReplacesOpt string

func (orderReplacesOpt) privateOrderOpt() {}

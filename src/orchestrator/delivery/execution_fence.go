package delivery

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strings"
)

type executionFenceKey struct{}
type executionFence struct {
	fence OperationFence
	check FenceChecker
}

// WithExecutionFence binds host requests to their durable delivery operation.
// The checker must re-read authority and operation ownership before mutation.
func WithExecutionFence(ctx context.Context, fence OperationFence, check FenceChecker) (context.Context, error) {
	if ctx == nil || fence.OperationID == "" || fence.RequestDigest == "" || fence.OwnerID == "" || fence.Generation == 0 || check == nil {
		return nil, errors.New("delivery: complete execution fence is required")
	}
	return context.WithValue(ctx, executionFenceKey{}, executionFence{fence, check}), nil
}

// CheckExecutionFence is the concrete mutation gate used by host transports.
func CheckExecutionFence(ctx context.Context) error {
	if ctx == nil {
		return ErrOperationLeaseActive
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	value, ok := ctx.Value(executionFenceKey{}).(executionFence)
	if !ok || value.check == nil {
		return ErrOperationLeaseActive
	}
	return value.check(value.fence)
}

// HostCommandID remains stable when another process recovers an operation.
// Changed host/action/payload facts produce a different command identity.
func HostCommandID(ctx context.Context, host, action, payloadDigest string) (string, error) {
	if err := CheckExecutionFence(ctx); err != nil {
		return "", err
	}
	for _, value := range []string{host, action, payloadDigest} {
		if value == "" || len(value) > 256 || strings.ContainsRune(value, '\x00') {
			return "", errors.New("delivery: invalid host command identity")
		}
	}
	value := ctx.Value(executionFenceKey{}).(executionFence)
	digest := sha256.Sum256([]byte(strings.Join([]string{value.fence.OperationID, value.fence.RequestDigest, host, action, payloadDigest}, "\x00")))
	return "delivery-" + hex.EncodeToString(digest[:27]), nil
}

func (s *Executor) checkAuthority(ctx context.Context, request *Request) error {
	if s.config.Authority != nil {
		return s.config.Authority(ctx, request)
	}
	return ErrOperationLeaseActive
}

func (s *Executor) checker(ctx context.Context, request *Request) FenceChecker {
	return func(fence OperationFence) error {
		if err := s.checkAuthority(ctx, request); err != nil {
			return err
		}
		return s.config.Journal.VerifyFence(fence)
	}
}

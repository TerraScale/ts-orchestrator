package functions

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"
)

func TestProvisionRequestRetriesUnansweredRequestUntilCallerDeadline(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		attempts := 0
		value, err := provisionRequest(t.Context(), func(ctx context.Context) (int, error) {
			attempts++
			if attempts == 1 {
				<-ctx.Done() // the first reply is never sent
				return 0, ctx.Err()
			}
			return 7, nil
		})
		if err != nil || value != 7 || attempts != 2 {
			t.Fatalf("unanswered request was not retried: value=%d attempts=%d err=%v", value, attempts, err)
		}

		rejected := errors.New("rejected")
		attempts = 0
		if _, err := provisionRequest(t.Context(), func(context.Context) (int, error) { attempts++; return 0, rejected }); !errors.Is(err, rejected) || attempts != 1 {
			t.Fatalf("answered error was retried: attempts=%d err=%v", attempts, err)
		}

		ctx, cancel := context.WithTimeout(t.Context(), 3*provisionRequestTimeout/2)
		defer cancel()
		attempts = 0
		if _, err := provisionRequest(ctx, func(ctx context.Context) (int, error) { attempts++; <-ctx.Done(); return 0, ctx.Err() }); !errors.Is(err, context.DeadlineExceeded) || attempts != 2 {
			t.Fatalf("caller deadline did not end retries: attempts=%d err=%v", attempts, err)
		}
	})
}

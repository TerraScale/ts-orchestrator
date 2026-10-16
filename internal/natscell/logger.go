package natscell

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"

	"github.com/TerraScale/ts-orchestrator/internal/observability"
	"github.com/nats-io/nats.go"
)

// natsLogger sends the embedded server's output to the structured log. It
// never exits: a server that cannot start already fails the readiness wait.
type natsLogger struct{}

func (natsLogger) Noticef(format string, v ...any) {
	logNATS(slog.LevelInfo, fmt.Sprintf(format, v...))
}

func (natsLogger) Warnf(format string, v ...any) {
	message := fmt.Sprintf(format, v...)
	level := slog.LevelWarn
	// A peer that is catching up logs this on every snapshot; it is routine.
	if strings.HasPrefix(message, "Metalayer blocking snapshot") {
		level = slog.LevelInfo
	}
	logNATS(level, message)
}

func (natsLogger) Fatalf(format string, v ...any) {
	logNATS(slog.LevelError, fmt.Sprintf(format, v...))
}

func (natsLogger) Errorf(format string, v ...any) {
	logNATS(slog.LevelError, fmt.Sprintf(format, v...))
}

func (natsLogger) Debugf(format string, v ...any) {
	logNATS(slog.LevelDebug, fmt.Sprintf(format, v...))
}

func (natsLogger) Tracef(format string, v ...any) {
	logNATS(slog.LevelDebug, fmt.Sprintf(format, v...))
}

func logNATS(level slog.Level, message string) {
	slog.Log(context.Background(), level, message, observability.ComponentKey, "nats")
}

// ErrorHandler logs an asynchronous client error that nats.go would otherwise
// print to stderr as plain text.
func ErrorHandler(conn *nats.Conn, sub *nats.Subscription, err error) {
	level := slog.LevelWarn
	if errors.Is(err, nats.ErrPermissionViolation) || errors.Is(err, nats.ErrAuthorization) {
		level = slog.LevelError
	}
	attrs := []any{observability.ComponentKey, "nats-client", "error", err}
	if conn != nil {
		attrs = append(attrs, "connection", conn.Opts.Name)
	}
	if sub != nil {
		attrs = append(attrs, "subject", sub.Subject)
	}
	slog.Log(context.Background(), level, "nats client error", attrs...)
}

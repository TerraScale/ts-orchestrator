package logs

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/nats-io/nats.go"

	"git.terrascale.tech/TerraScale/ts-orchestrator/internal/protocol"
)

const maxRequestBytes = 4 << 10

var invalidRequest = []byte(`{"v":1,"error":"invalid_request"}`)

// Serve answers query.logs.v1 for cell from view until ctx ends. Every controller
// answers in queue group logs, so a requester takes the first reply.
func Serve(ctx context.Context, conn *nats.Conn, cell string, view *View) (*nats.Subscription, error) {
	if conn == nil || view == nil {
		return nil, errors.New("log query responder requires a connection and a view")
	}
	subject := protocol.Regional(cell, "query", "logs.v1")
	if subject == "" {
		return nil, errors.New("log query subject is invalid")
	}
	subscription, err := conn.QueueSubscribe(subject, "logs", func(message *nats.Msg) {
		if message.Reply == "" {
			return
		}
		_ = message.Respond(answer(view, message.Data, conn.MaxPayload(), time.Now()))
	})
	if err != nil {
		return nil, err
	}
	context.AfterFunc(ctx, func() { _ = subscription.Unsubscribe() })
	return subscription, nil
}

// answer encodes the reply to one request. A reply larger than the connection's
// payload keeps the most frequent classes that fit and is marked truncated.
func answer(view *View, data []byte, maxPayload int64, now time.Time) []byte {
	var request Request
	if protocol.DecodeStrict(data, &request, maxRequestBytes) != nil || request.Validate() != nil {
		return invalidRequest
	}
	reply := view.Summary(request, now)
	for {
		encoded, err := json.Marshal(reply)
		if err != nil {
			return invalidRequest
		}
		if int64(len(encoded)) <= maxPayload || len(reply.Classes) == 0 {
			return encoded
		}
		reply.Classes = reply.Classes[:len(reply.Classes)/2]
		reply.Truncated = true
	}
}

// Handler serves GET /v1/logs on the private listener with the same reply as
// query.logs.v1, for this region. Missing parameters take the defaults.
func Handler(view *View) http.Handler {
	return http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		params := request.URL.Query()
		req := Request{Version: 1, Window: cmp.Or(params.Get("window"), "1h"),
			MinLevel: cmp.Or(params.Get("min_level"), LevelDebug), Service: params.Get("service")}
		if params.Has("limit") {
			limit, err := strconv.Atoi(params.Get("limit"))
			if err != nil {
				http.Error(writer, "limit must be a number", http.StatusBadRequest)
				return
			}
			req.Limit = limit
		}
		if err := req.Validate(); err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Cache-Control", "no-store")
		_ = json.NewEncoder(writer).Encode(view.Summary(req, time.Now()))
	})
}

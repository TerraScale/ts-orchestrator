package nodeauthority

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// ReadLeaderKV reads a current KV value through the ordinary stream-leader API.
// Connection authentication belongs to its production composition. This helper
// deliberately never uses the follower-capable DIRECT.GET API or a watch cache.
// A tombstone returns an error; absence cannot be interpreted as epoch zero.
func ReadLeaderKV(ctx context.Context, connection *nats.Conn, bucket, key string) ([]byte, uint64, error) {
	if ctx == nil || connection == nil || !connection.IsConnected() || !authorityBucket(bucket) || len(key) == 0 || len(key) > 256 || strings.ContainsAny(key, " *>\t\r\n") {
		return nil, 0, errors.New("nodeauthority: invalid leader read configuration")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	subject := "$KV." + bucket + "." + key
	request, _ := json.Marshal(struct {
		Last string `json:"last_by_subj"`
	}{subject})
	response, err := connection.RequestWithContext(ctx, "$JS.API.STREAM.MSG.GET.KV_"+bucket, request)
	if err != nil {
		return nil, 0, err
	}
	if response == nil || len(response.Data) > 4*1024*1024 {
		return nil, 0, errors.New("nodeauthority: invalid leader reply")
	}
	var wire struct {
		Type    string `json:"type"`
		Message *struct {
			Subject  string    `json:"subject"`
			Sequence uint64    `json:"seq"`
			Data     []byte    `json:"data"`
			Headers  []byte    `json:"hdrs"`
			Time     time.Time `json:"time"`
		} `json:"message"`
		Error *struct {
			Code      int `json:"code"`
			ErrorCode int `json:"err_code"`
		} `json:"error"`
	}
	if json.Unmarshal(response.Data, &wire) != nil {
		return nil, 0, errors.New("nodeauthority: malformed leader response")
	}
	if wire.Error != nil && wire.Error.ErrorCode == 10037 {
		return nil, 0, jetstream.ErrKeyNotFound
	}
	if wire.Type != "io.nats.jetstream.api.v1.stream_msg_get_response" || wire.Error != nil || wire.Message == nil || wire.Message.Subject != subject || wire.Message.Sequence == 0 || wire.Message.Time.IsZero() {
		return nil, 0, errors.New("nodeauthority: leader did not return a current value")
	}
	if len(wire.Message.Headers) != 0 {
		headers, err := nats.DecodeHeadersMsg(wire.Message.Headers)
		if err == nil && (headers.Get("KV-Operation") == "DEL" || headers.Get("KV-Operation") == "PURGE") {
			return nil, wire.Message.Sequence, jetstream.ErrKeyDeleted
		}
		if err != nil || headers.Get("KV-Operation") != "" {
			return nil, 0, errors.New("nodeauthority: leader returned a deleted or invalid value")
		}
	}
	if len(wire.Message.Data) == 0 || len(wire.Message.Data) > (2<<20)+(16<<10) {
		return nil, 0, errors.New("nodeauthority: leader returned empty value")
	}
	return append([]byte(nil), wire.Message.Data...), wire.Message.Sequence, nil
}

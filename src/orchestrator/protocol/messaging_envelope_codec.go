package protocol

import "terrascale.tech/orchestrator/src/orchestrator/natspolicy"

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"
)

const (
	MessagingEnvelopeMaximumBytes        = 1 << 20
	messagingEnvelopeMaximumNestingDepth = 64
)

type messagingSchemaVersionDocument struct {
	Major int `json:"major"`
	Minor int `json:"minor"`
}

type messagingSourceDocument struct {
	Instance string `json:"instance"`
	Session  string `json:"session"`
	Cell     string `json:"cell"`
	Cluster  string `json:"cluster"`
}

type messagingTargetDocument struct {
	Namespace natspolicy.NatsSubjectNamespace `json:"namespace"`
	Subject   string                          `json:"subject"`
	Cell      *string                         `json:"cell,omitempty"`
}

type messagingTraceContextDocument struct {
	TraceId string `json:"traceId"`
	SpanId  string `json:"spanId"`
}

type messagingEnvelopeDocument struct {
	ProtocolRoot  string                         `json:"protocolRoot"`
	SchemaVersion messagingSchemaVersionDocument `json:"schemaVersion"`
	MessageId     string                         `json:"messageId"`
	CorrelationId *string                        `json:"correlationId,omitempty"`
	CausationId   *string                        `json:"causationId,omitempty"`
	Source        messagingSourceDocument        `json:"source"`
	Target        messagingTargetDocument        `json:"target"`
	PayloadType   string                         `json:"payloadType"`
	TraceContext  *messagingTraceContextDocument `json:"traceContext,omitempty"`
	ObservedAt    time.Time                      `json:"observedAt"`
	Payload       json.RawMessage                `json:"payload"`
}

// MarshalMessagingEnvelope serializes a non-command control message into the
// only admitted v1 JSON wire shape. Signed commands retain their canonical
// command codec and are rejected here so the two formats cannot be confused.
func MarshalMessagingEnvelope(envelope *MessagingEnvelope, payload any) ([]byte, error) {
	if envelope == nil || envelope.Command != nil || envelope.SchemaVersion != MessagingSchemaVersionCurrent {
		return nil, errors.New("messaging envelope is not an unsigned v1 payload")
	}
	context := NewMessagingValidationContext(
		map[int]struct{}{MessagingSchemaVersionCurrent.Major: {}},
		map[string]struct{}{envelope.PayloadType: {}}, nil)
	if !MessagingEnvelopeValidator.Validate(envelope, context).IsAccepted() {
		return nil, errors.New("messaging envelope metadata is invalid")
	}

	encodedPayload, err := json.Marshal(payload)
	if err != nil || len(encodedPayload) == 0 || bytes.Equal(encodedPayload, []byte("null")) {
		return nil, errors.New("messaging envelope payload is invalid")
	}
	document := messagingEnvelopeDocument{
		ProtocolRoot: natspolicy.NatsSubjectTaxonomy.Root(),
		SchemaVersion: messagingSchemaVersionDocument{
			Major: envelope.SchemaVersion.Major,
			Minor: envelope.SchemaVersion.Minor,
		},
		MessageId: envelope.MessageId.Value,
		Source: messagingSourceDocument{
			Instance: envelope.Source.Instance,
			Session:  envelope.Source.Session,
			Cell:     envelope.Source.Cell,
			Cluster:  envelope.Source.Cluster,
		},
		Target: messagingTargetDocument{
			Namespace: envelope.Target.Namespace,
			Subject:   envelope.Target.Subject,
			Cell:      envelope.Target.Cell,
		},
		PayloadType: envelope.PayloadType,
		ObservedAt:  envelope.ObservedAt.UTC(),
		Payload:     encodedPayload,
	}
	if envelope.CorrelationId != nil {
		document.CorrelationId = &envelope.CorrelationId.Value
	}
	if envelope.CausationId != nil {
		document.CausationId = &envelope.CausationId.Value
	}
	if envelope.TraceContext != nil {
		document.TraceContext = &messagingTraceContextDocument{
			TraceId: envelope.TraceContext.TraceId,
			SpanId:  envelope.TraceContext.SpanId,
		}
	}

	encoded, err := json.Marshal(document)
	if err != nil || len(encoded) > MessagingEnvelopeMaximumBytes ||
		messagingEnvelopeJSONViolatesWireBounds(encoded) {
		return nil, errors.New("messaging envelope exceeds its wire bound")
	}
	return encoded, nil
}

// UnmarshalMessagingEnvelope rejects legacy roots, unknown JSON members,
// newer or older majors, subject substitution, and unapproved payload types.
func UnmarshalMessagingEnvelope(document []byte, subject string, permittedPayloadTypes map[string]struct{}) (*MessagingEnvelope, json.RawMessage, error) {
	if len(document) == 0 || len(document) > MessagingEnvelopeMaximumBytes || len(permittedPayloadTypes) == 0 ||
		messagingEnvelopeJSONViolatesWireBounds(document) {
		return nil, nil, errors.New("messaging envelope document is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(document))
	decoder.DisallowUnknownFields()
	var decoded messagingEnvelopeDocument
	if err := decoder.Decode(&decoded); err != nil {
		return nil, nil, errors.New("messaging envelope document is invalid")
	}
	if err := ensureMessagingEnvelopeEOF(decoder); err != nil {
		return nil, nil, errors.New("messaging envelope document is invalid")
	}
	if decoded.ProtocolRoot != natspolicy.NatsSubjectTaxonomy.Root() || decoded.Target.Subject != subject ||
		len(decoded.Payload) == 0 || bytes.Equal(decoded.Payload, []byte("null")) {
		return nil, nil, errors.New("messaging envelope protocol binding is invalid")
	}

	messageId, messageOk := MessageIdentityTokenTryCreate(decoded.MessageId)
	if !messageOk {
		return nil, nil, errors.New("messaging envelope identity is invalid")
	}
	var correlation *MessageIdentityToken
	if decoded.CorrelationId != nil {
		value, ok := MessageIdentityTokenTryCreate(*decoded.CorrelationId)
		if !ok {
			return nil, nil, errors.New("messaging envelope identity is invalid")
		}
		correlation = &value
	}
	var causation *MessageIdentityToken
	if decoded.CausationId != nil {
		value, ok := MessageIdentityTokenTryCreate(*decoded.CausationId)
		if !ok {
			return nil, nil, errors.New("messaging envelope identity is invalid")
		}
		causation = &value
	}

	envelope := &MessagingEnvelope{
		SchemaVersion: MessagingSchemaVersion{Major: decoded.SchemaVersion.Major, Minor: decoded.SchemaVersion.Minor},
		MessageId:     messageId,
		CorrelationId: correlation,
		CausationId:   causation,
		Source: MessagingSource{
			Instance: decoded.Source.Instance,
			Session:  decoded.Source.Session,
			Cell:     decoded.Source.Cell,
			Cluster:  decoded.Source.Cluster,
		},
		Target: MessagingTargetScope{
			Namespace: decoded.Target.Namespace,
			Subject:   decoded.Target.Subject,
			Cell:      decoded.Target.Cell,
		},
		PayloadType: decoded.PayloadType,
		ObservedAt:  decoded.ObservedAt,
	}
	if decoded.TraceContext != nil {
		envelope.TraceContext = &MessagingTraceContext{
			TraceId: decoded.TraceContext.TraceId,
			SpanId:  decoded.TraceContext.SpanId,
		}
	}
	context := NewMessagingValidationContext(
		map[int]struct{}{MessagingSchemaVersionCurrent.Major: {}}, permittedPayloadTypes, nil)
	if envelope.SchemaVersion != MessagingSchemaVersionCurrent ||
		!MessagingEnvelopeValidator.Validate(envelope, context).IsAccepted() {
		return nil, nil, errors.New("messaging envelope metadata is invalid")
	}
	return envelope, append(json.RawMessage(nil), decoded.Payload...), nil
}

func ensureMessagingEnvelopeEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err == io.EOF {
		return nil
	}
	return errors.New("trailing messaging envelope content")
}

func messagingEnvelopeJSONViolatesWireBounds(document []byte) bool {
	decoder := json.NewDecoder(bytes.NewReader(document))
	token, err := decoder.Token()
	if err != nil || messagingEnvelopeJSONValueViolatesWireBounds(decoder, token, 0) {
		return true
	}
	_, err = decoder.Token()
	return err == nil
}

func messagingEnvelopeJSONValueViolatesWireBounds(decoder *json.Decoder, token json.Token, depth int) bool {
	delimiter, ok := token.(json.Delim)
	if !ok {
		return false
	}
	depth++
	if depth > messagingEnvelopeMaximumNestingDepth {
		return true
	}
	if delimiter == '[' {
		for {
			value, err := decoder.Token()
			if err != nil {
				return true
			}
			if value == json.Delim(']') {
				return false
			}
			if messagingEnvelopeJSONValueViolatesWireBounds(decoder, value, depth) {
				return true
			}
		}
	}
	if delimiter != '{' {
		return true
	}
	seen := map[string]struct{}{}
	for {
		key, err := decoder.Token()
		if err != nil {
			return true
		}
		if key == json.Delim('}') {
			return false
		}
		name, ok := key.(string)
		if !ok {
			return true
		}
		if _, duplicate := seen[name]; duplicate {
			return true
		}
		seen[name] = struct{}{}
		value, err := decoder.Token()
		if err != nil || messagingEnvelopeJSONValueViolatesWireBounds(decoder, value, depth) {
			return true
		}
	}
}

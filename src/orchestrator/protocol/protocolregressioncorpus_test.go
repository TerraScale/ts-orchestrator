// The C# test-assembly helper becomes a same-package test helper; the embedded
// resource is the byte-identical copy of test-corpus/protocol/minimal-fail-closed-seeds.json.
package protocol

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

//go:embed testdata/minimal-fail-closed-seeds.json
var embeddedRegressionCorpus []byte

type CorpusLoadCode int

const (
	CorpusLoadAccepted               CorpusLoadCode = 0
	CorpusLoadMissingResource        CorpusLoadCode = 1
	CorpusLoadTooLarge               CorpusLoadCode = 2
	CorpusLoadInvalidJson            CorpusLoadCode = 3
	CorpusLoadInvalidSchema          CorpusLoadCode = 4
	CorpusLoadInvalidDigest          CorpusLoadCode = 5
	CorpusLoadContentAddressMismatch CorpusLoadCode = 6
)

type ProtocolCorpusEntry struct {
	Family   string
	Seed     int64
	Input    string
	Expected string
	Digest   string
}

type CorpusLoadResult struct {
	Code    CorpusLoadCode
	Entries []ProtocolCorpusEntry
}

const (
	corpusMaximumBytes      = 32768
	corpusMaximumEntries    = 64
	corpusMaximumTextLength = 256
	corpusContentSha256     = "4f08f00d68bb88e2a935dcef54f80f0048a93ca455afd8bdd97ceebd6d2f363d"
)

var corpusRootFields = []string{"version", "entries"}
var corpusEntryFields = []string{"family", "seed", "input", "expected", "digest"}

func corpusGrammarErrors() []string {
	return []string{
		"InvalidLimits", "Empty", "SubjectTooLong", "TooManyTokens", "EmptyToken", "TokenTooLong",
		"WhitespaceNotAllowed", "ControlCharacterNotAllowed", "InvalidUnicodeScalarSequence",
		"WildcardNotAllowed", "InvalidWildcard", "TerminalWildcardMustBeFinal",
	}
}

func corpusExpectedByFamily() map[string][]string {
	envelopeErrors := []string{
		"InvalidValidationContext", "MalformedEnvelope", "UnsupportedProtocolVersion",
		"InvalidValidityWindow", "NotYetValid", "Expired", "WrongCell", "WrongAggregateIdentity",
		"StaleGeneration", "StaleWriterEpoch", "PayloadDigestMismatch",
		"PayloadDigestVerificationFailed", "InvalidSignature", "SignatureVerificationFailed",
	}

	return map[string][]string{
		"concrete-subject":   corpusGrammarErrors(),
		"permission-pattern": corpusGrammarErrors(),
		"command-envelope":   envelopeErrors,
	}
}

func corpusResult(code CorpusLoadCode, entries []ProtocolCorpusEntry) CorpusLoadResult {
	if entries == nil {
		entries = []ProtocolCorpusEntry{}
	}

	return CorpusLoadResult{Code: code, Entries: entries}
}

// protocolRegressionCorpusLoadEmbedded mirrors LoadEmbedded.
func protocolRegressionCorpusLoadEmbedded() CorpusLoadResult {
	// The resource is embedded; the MissingResource branch is unreachable here.
	if len(embeddedRegressionCorpus) == 0 {
		return corpusResult(CorpusLoadMissingResource, nil)
	}

	return protocolRegressionCorpusLoadBytes(embeddedRegressionCorpus, true)
}

// protocolRegressionCorpusLoadString rejects invalid UTF-8 as InvalidJson.
func protocolRegressionCorpusLoadString(source string) CorpusLoadResult {
	if source == "" {
		return corpusResult(CorpusLoadTooLarge, nil)
	}

	return protocolRegressionCorpusLoadBytes([]byte(source), false)
}

// protocolRegressionCorpusLoadBytes mirrors Load(ReadOnlySpan<byte>, bool).
func protocolRegressionCorpusLoadBytes(source []byte, requireContentAddress bool) CorpusLoadResult {
	if len(source) == 0 || len(source) > corpusMaximumBytes {
		return corpusResult(CorpusLoadTooLarge, nil)
	}

	if requireContentAddress {
		digest := sha256.Sum256(source)
		if hex.EncodeToString(digest[:]) != corpusContentSha256 {
			return corpusResult(CorpusLoadContentAddressMismatch, nil)
		}
	}

	document, err := parseCorpusDocument(source)
	if err != nil {
		return corpusResult(CorpusLoadInvalidJson, nil)
	}

	if document == nil {
		return corpusResult(CorpusLoadInvalidSchema, nil)
	}

	return *document
}

// parseCorpusDocument performs the strict, order-preserving, duplicate-aware
// JSON walk the C# JsonDocument loop performed: exact root/entry field sets,
// bounded depth (8), integers as numbers (not strings), and typed text rules.
func parseCorpusDocument(source []byte) (*CorpusLoadResult, error) {
	decoder := json.NewDecoder(bytes.NewReader(source))
	decoder.UseNumber()

	root, err := readCorpusValue(decoder, 1)
	if err != nil {
		return nil, err
	}

	// Trailing content (other than whitespace) is malformed JSON.
	if _, err := decoder.Token(); err != io.EOF {
		return nil, errors.New("trailing content")
	}

	rootObject, ok := root.(map[string]interface{})
	if !ok || !corpusExactFieldsOrderInsensitive(rootObject, corpusRootFields) {
		return nil, nil
	}

	versionValue, present := rootObject["version"]
	if !present {
		return nil, nil
	}

	versionNumber, ok := versionValue.(json.Number)
	if !ok {
		return nil, nil
	}

	version, err := strconv.Atoi(versionNumber.String())
	if err != nil || version != 1 {
		return nil, nil
	}

	entriesValue, present := rootObject["entries"]
	if !present {
		return nil, nil
	}

	entryList, ok := entriesValue.([]interface{})
	if !ok || len(entryList) > corpusMaximumEntries {
		return nil, nil
	}

	entries := []ProtocolCorpusEntry{}
	for _, item := range entryList {
		itemObject, ok := item.(map[string]interface{})
		if !ok || !corpusExactFieldsOrderInsensitive(itemObject, corpusEntryFields) {
			return nil, nil
		}

		seedValue, present := itemObject["seed"]
		if !present {
			return nil, nil
		}

		seedNumber, ok := seedValue.(json.Number)
		if !ok {
			return nil, nil
		}

		seed, err := seedNumber.Int64()
		if err != nil || seed <= 0 {
			return nil, nil
		}

		family, familyOk := itemObject["family"].(string)
		input, inputOk := itemObject["input"].(string)
		expected, expectedOk := itemObject["expected"].(string)
		digest, digestOk := itemObject["digest"].(string)
		if !familyOk || !inputOk || !expectedOk || !digestOk ||
			!corpusCanonicalText(family) || !corpusBoundedText(input) ||
			!corpusCanonicalText(expected) || !corpusDigestText(digest) {
			return nil, nil
		}

		allowedExpected := false
		for _, candidate := range corpusExpectedByFamily()[family] {
			if candidate == expected {
				allowedExpected = true
				break
			}
		}

		if !allowedExpected {
			return nil, nil
		}

		entry := ProtocolCorpusEntry{Family: family, Seed: seed, Input: input, Expected: expected, Digest: digest}
		if protocolRegressionCorpusDigest(entry) != digest {
			result := corpusResult(CorpusLoadInvalidDigest, nil)
			return &result, nil
		}

		entries = append(entries, entry)
	}

	seen := map[string]struct{}{}
	for _, entry := range entries {
		key := entry.Family + "|" + strconv.FormatInt(entry.Seed, 10)
		if _, duplicate := seen[key]; duplicate {
			return nil, nil
		}

		seen[key] = struct{}{}
	}

	result := corpusResult(CorpusLoadAccepted, entries)
	return &result, nil
}

// readCorpusValue reads one JSON value with a depth bound; object key order and
// duplicates are discarded but duplicate keys are rejected downstream by the
// exact-field-set check only in the C# sense (three properties where two are
// expected). To preserve that, duplicates are counted as an extra property.
func readCorpusValue(decoder *json.Decoder, depth int) (interface{}, error) {
	if depth > 8 {
		return nil, errors.New("depth exceeded")
	}

	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}

	delim, ok := token.(json.Delim)
	if !ok {
		if number, ok := token.(json.Number); ok {
			return number, nil
		}

		return token, nil
	}

	switch delim {
	case '{':
		object := map[string]interface{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return nil, err
			}

			key, ok := keyToken.(string)
			if !ok {
				return nil, errors.New("object key is not a string")
			}

			if _, duplicate := object[key]; duplicate {
				// Mirror the C# behavior: a duplicate property makes the
				// property count disagree with the exact field set.
				object[key+"\u0000duplicate"+strconv.Itoa(len(object))] = nil
			}

			value, err := readCorpusValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}

			object[key] = value
		}

		if _, err := decoder.Token(); err != nil { // consume '}'
			return nil, err
		}

		return object, nil
	case '[':
		list := []interface{}{}
		for decoder.More() {
			value, err := readCorpusValue(decoder, depth+1)
			if err != nil {
				return nil, err
			}

			list = append(list, value)
		}

		if _, err := decoder.Token(); err != nil { // consume ']'
			return nil, err
		}

		return list, nil
	default:
		return nil, fmt.Errorf("unexpected delimiter %v", delim)
	}
}

func corpusExactFieldsOrderInsensitive(object map[string]interface{}, expected []string) bool {
	if len(object) != len(expected) {
		return false
	}

	for _, field := range expected {
		if _, present := object[field]; !present {
			return false
		}
	}

	return true
}

func corpusCanonicalText(value string) bool {
	if !corpusBoundedText(value) {
		return false
	}

	for _, character := range value {
		if (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' {
			continue
		}

		return false
	}

	return true
}

func corpusBoundedText(value string) bool {
	return len(value) > 0 && len(value) <= corpusMaximumTextLength
}

func corpusDigestText(value string) bool {
	if len(value) != 64 {
		return false
	}

	for index := 0; index < len(value); index++ {
		character := value[index]
		if (character < '0' || character > '9') && (character < 'a' || character > 'f') {
			return false
		}
	}

	return true
}

// protocolRegressionCorpusDigest mirrors ProtocolRegressionCorpus.Digest.
func protocolRegressionCorpusDigest(entry ProtocolCorpusEntry) string {
	digest := sha256.Sum256([]byte(protocolRegressionCorpusCanonical(entry)))
	return hex.EncodeToString(digest[:])
}

// protocolRegressionCorpusCanonical mirrors ProtocolRegressionCorpus.Canonical.
func protocolRegressionCorpusCanonical(entry ProtocolCorpusEntry) string {
	return "v1|family=" + strconv.Itoa(len(entry.Family)) + ":" + entry.Family +
		"|seed=" + strconv.FormatInt(entry.Seed, 10) +
		"|input=" + strconv.Itoa(len(entry.Input)) + ":" + entry.Input +
		"|expected=" + strconv.Itoa(len(entry.Expected)) + ":" + entry.Expected
}

// corpusReadBounded mirrors ProtocolRegressionCorpus.ReadBounded.
func corpusReadBounded(stream io.Reader) []byte {
	buffer := make([]byte, corpusMaximumBytes+1)
	count := 0
	for count < len(buffer) {
		read, err := stream.Read(buffer[count:])
		count += read
		if err != nil || read == 0 {
			break
		}
	}

	if count > corpusMaximumBytes {
		return nil
	}

	return buffer[:count]
}

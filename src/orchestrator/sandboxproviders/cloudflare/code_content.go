package cloudflare

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"mime/multipart"
	"net/http"
	"net/textproto"
)

// parseCodeUpload deliberately rejects the retired JSON/base64 contract.
func parseCodeUpload(r *http.Request, body []byte, field, filename string) (json.RawMessage, []byte, error) {
	mediaType, params, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || mediaType != "multipart/form-data" || params["boundary"] == "" {
		return nil, nil, errors.New("multipart upload required")
	}
	reader := multipart.NewReader(bytes.NewReader(body), params["boundary"])
	var metadata json.RawMessage
	var source []byte
	for {
		part, err := reader.NextPart()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, err
		}
		raw, err := io.ReadAll(part)
		if err != nil {
			return nil, nil, err
		}
		switch {
		case part.FormName() == "metadata" && metadata == nil:
			if part.Header.Get("Content-Type") != "application/json" {
				return nil, nil, errors.New("JSON metadata required")
			}
			metadata = raw
		case part.FormName() == field && part.FileName() == filename && source == nil:
			if part.Header.Get("Content-Type") != "application/javascript+module" {
				return nil, nil, errors.New("module content type required")
			}
			source = raw
		default:
			return nil, nil, errors.New("unexpected upload part")
		}
	}
	var entry struct {
		MainModule string `json:"main_module"`
	}
	if json.Unmarshal(metadata, &entry) != nil || entry.MainModule != filename || len(source) == 0 {
		return nil, nil, errors.New("module or metadata missing")
	}
	return metadata, source, nil
}

func writeCodeContent(w http.ResponseWriter, filename string, source []byte) {
	writer := multipart.NewWriter(w)
	w.Header().Set("Content-Type", writer.FormDataContentType())
	part, err := writer.CreatePart(textproto.MIMEHeader{
		"Content-Disposition": {`form-data; name="files"; filename="` + filename + `"`},
		"Content-Type":        {"application/javascript+module"},
	})
	if err == nil {
		_, _ = part.Write(source)
	}
	_ = writer.Close()
}

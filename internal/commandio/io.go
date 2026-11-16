// Package commandio preserves output failures and cancellation in CLI I/O.
package commandio

import (
	"io"
)

// Writer records the first output failure so commands cannot report success
// after a discarded status write. A Writer belongs to one command invocation.
type Writer struct {
	destination io.Writer
	err         error
}

func NewWriter(destination io.Writer) *Writer {
	return &Writer{destination: destination}
}

func (writer *Writer) Write(contents []byte) (int, error) {
	if writer.err != nil {
		return 0, writer.err
	}
	written, err := writer.destination.Write(contents)
	if err == nil && written != len(contents) {
		err = io.ErrShortWrite
	}
	writer.err = err
	return written, err
}

func (writer *Writer) Err() error { return writer.err }

// Package commandio preserves output failures and cancellation in CLI I/O.
package commandio

import (
	"context"
	"errors"
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

// Reader checks cancellation around every read, including the final read.
// Wrapping the source prevents io.Copy from bypassing these checks through a
// source's WriterTo implementation.
func Reader(ctx context.Context, source io.Reader) io.Reader {
	return reader{ctx: ctx, source: source}
}

type reader struct {
	ctx    context.Context
	source io.Reader
}

func (reader reader) Read(contents []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	read, err := reader.source.Read(contents)
	if canceled := reader.ctx.Err(); canceled != nil {
		return read, errors.Join(err, canceled)
	}
	return read, err
}

package commandio

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// os.File normalizes short writes; retain the kernel result to exercise Writer.
type pipeDestination int

func (fd pipeDestination) Write(contents []byte) (int, error) {
	written, err := unix.Write(int(fd), contents)
	return max(written, 0), err
}

func commandPipe(t *testing.T) (*os.File, *os.File) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { reader.Close(); writer.Close() })
	return reader, writer
}

func TestWriterPreservesFailureAndRejectsShortWrites(t *testing.T) {
	t.Run("closed consumer", func(t *testing.T) {
		reader, output := commandPipe(t)
		fd := int(output.Fd())
		if err := reader.Close(); err != nil {
			t.Fatal(err)
		}
		writer := NewWriter(pipeDestination(fd))
		if _, err := writer.Write([]byte("verified receipt\n")); !errors.Is(err, unix.EPIPE) {
			t.Fatalf("closed pipe error = %v, want EPIPE", err)
		}

		path := filepath.Join(t.TempDir(), "recovered-output")
		recovered, err := os.Create(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { recovered.Close() })
		// Make the destination writable again without changing the Writer.
		if err := unix.Dup2(int(recovered.Fd()), fd); err != nil {
			t.Fatal(err)
		}
		if n, err := writer.Write([]byte("another status\n")); n != 0 || !errors.Is(err, unix.EPIPE) {
			t.Fatalf("subsequent write = %d, %v, want the original EPIPE", n, err)
		}
		if !errors.Is(writer.Err(), unix.EPIPE) {
			t.Fatalf("writer lost its first error: %v", writer.Err())
		}
		if data, err := os.ReadFile(path); err != nil || len(data) != 0 {
			t.Fatalf("writer reused the recovered destination: %q, %v", data, err)
		}
	})

	t.Run("kernel short write", func(t *testing.T) {
		reader, output := commandPipe(t)
		readFD, writeFD := int(reader.Fd()), int(output.Fd())
		for _, fd := range []int{readFD, writeFD} {
			if err := unix.SetNonblock(fd, true); err != nil {
				t.Fatal(err)
			}
		}
		padding := make([]byte, 4096)
		filled := 0
		for {
			n, err := unix.Write(writeFD, padding)
			if errors.Is(err, unix.EAGAIN) {
				break
			}
			if err != nil || n <= 0 {
				t.Fatalf("fill pipe = %d, %v", n, err)
			}
			filled += n
			if filled > 1<<20 {
				t.Fatal("pipe did not reach its capacity within 1 MiB")
			}
		}
		freed, err := unix.Read(readFD, padding)
		if err != nil || freed != len(padding) {
			t.Fatalf("make room in pipe = %d, %v", freed, err)
		}
		payload := bytes.Repeat([]byte("r"), filled*2)
		writer := NewWriter(pipeDestination(writeFD))
		written, err := writer.Write(payload)
		if written <= 0 || written >= len(payload) || !errors.Is(err, io.ErrShortWrite) {
			t.Fatalf("kernel partial write = %d/%d, %v", written, len(payload), err)
		}
		want := append(make([]byte, filled-freed), payload[:written]...)
		got := make([]byte, len(want))
		for offset := 0; offset < len(got); {
			n, err := unix.Read(readFD, got[offset:])
			if err != nil || n <= 0 {
				t.Fatalf("drain pipe = %d, %v", n, err)
			}
			offset += n
		}
		if !bytes.Equal(got, want) {
			t.Fatal("pipe contents differ from the partial write")
		}
		if n, err := writer.Write([]byte("another status\n")); n != 0 || !errors.Is(err, io.ErrShortWrite) || !errors.Is(writer.Err(), io.ErrShortWrite) {
			t.Fatalf("subsequent write = %d, %v; stored error = %v", n, err, writer.Err())
		}
		if n, err := unix.Read(readFD, padding); n > 0 || !errors.Is(err, unix.EAGAIN) {
			t.Fatalf("writer reused the drained pipe: read %d, %v", n, err)
		}
	})
}

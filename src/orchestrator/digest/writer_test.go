package digest

import (
	"testing"
	"time"
)

func TestWriterPreservesVersionOneEncoding(t *testing.T) {
	text := "value"
	truth := true
	number := int64(-7)
	w := NewWriter()
	w.WriteNull()
	w.WriteString("😀")
	w.WriteStringPointer(&text)
	w.WriteBoolPointer(&truth)
	w.WriteInt64Pointer(&number)
	w.WriteTime(time.Unix(0, 0).UTC())
	w.WriteDuration(1500 * time.Nanosecond)
	w.WriteArrayHeader(1)
	w.WriteRaw("S1:x;")
	w.WriteArrayFooter()

	want := "N;S2:😀;S5:value;B1;L-7;T621355968000000000;D15;A1[S1:x;];"
	if got := w.Finish(); got != want {
		t.Fatalf("encoded material = %q, want %q", got, want)
	}
}

func TestWriterNilPointersUseNullEncoding(t *testing.T) {
	w := NewWriter()
	w.WriteStringPointer(nil)
	w.WriteBoolPointer(nil)
	w.WriteInt64Pointer(nil)
	if got := w.Finish(); got != "N;N;N;" {
		t.Fatalf("nil encoding = %q, want N;N;N;", got)
	}
}

func TestUTF16CodeUnitCountUsesSurrogatePairsForNonBMPScalars(t *testing.T) {
	if got := UTF16CodeUnitCount("a😀b"); got != 4 {
		t.Fatalf("UTF16CodeUnitCount = %d, want 4", got)
	}
}

func TestHashIsStableLowercaseSHA256(t *testing.T) {
	const want = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
	if got := Hash("abc"); got != want {
		t.Fatalf("Hash = %q, want %q", got, want)
	}
}

func TestCanAddTimeHonorsPersistedTimestampBounds(t *testing.T) {
	if !CanAddTime(time.Unix(0, 0).UTC(), time.Hour) {
		t.Fatal("ordinary timestamp addition was rejected")
	}
	if CanAddTime(dotNetMaxTimestamp, time.Nanosecond) {
		t.Fatal("timestamp addition beyond the maximum was accepted")
	}
}

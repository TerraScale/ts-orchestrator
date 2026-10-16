// Copyright 2019-2026 The NATS Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//go:build !skip_store_tests

package server

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"math/rand/v2"
	"reflect"
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/nats-io/nats-server/v2/server/gsl"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nuid"
)

func TestMemStoreBasics(t *testing.T) {
	ms, err := newMemStore(&StreamConfig{Storage: MemoryStorage})
	require_NoError(t, err)
	defer ms.Stop()

	subj, msg := "foo", []byte("Hello World")
	now := time.Now().UnixNano()
	if seq, ts, err := ms.StoreMsg(subj, nil, msg, 0); err != nil {
		t.Fatalf("Error storing msg: %v", err)
	} else if seq != 1 {
		t.Fatalf("Expected sequence to be 1, got %d", seq)
	} else if ts < now || ts > now+int64(time.Millisecond) {
		t.Fatalf("Expected timestamp to be current, got %v", ts-now)
	}

	state := ms.State()
	if state.Msgs != 1 {
		t.Fatalf("Expected 1 msg, got %d", state.Msgs)
	}
	expectedSize := memStoreMsgSize(subj, nil, msg)
	if state.Bytes != expectedSize {
		t.Fatalf("Expected %d bytes, got %d", expectedSize, state.Bytes)
	}
	sm, err := ms.LoadMsg(1, nil)
	if err != nil {
		t.Fatalf("Unexpected error looking up msg: %v", err)
	}
	if sm.subj != subj {
		t.Fatalf("Subjects don't match, original %q vs %q", subj, sm.subj)
	}
	if !bytes.Equal(sm.msg, msg) {
		t.Fatalf("Msgs don't match, original %q vs %q", msg, sm.msg)
	}
}

func TestMemStoreMsgLimit(t *testing.T) {
	ms, err := newMemStore(&StreamConfig{Storage: MemoryStorage, MaxMsgs: 10})
	require_NoError(t, err)
	defer ms.Stop()

	subj, msg := "foo", []byte("Hello World")
	for i := 0; i < 10; i++ {
		ms.StoreMsg(subj, nil, msg, 0)
	}
	state := ms.State()
	if state.Msgs != 10 {
		t.Fatalf("Expected %d msgs, got %d", 10, state.Msgs)
	}
	if _, _, err := ms.StoreMsg(subj, nil, msg, 0); err != nil {
		t.Fatalf("Error storing msg: %v", err)
	}
	state = ms.State()
	if state.Msgs != 10 {
		t.Fatalf("Expected %d msgs, got %d", 10, state.Msgs)
	}
	if state.LastSeq != 11 {
		t.Fatalf("Expected the last sequence to be 11 now, but got %d", state.LastSeq)
	}
	if state.FirstSeq != 2 {
		t.Fatalf("Expected the first sequence to be 2 now, but got %d", state.FirstSeq)
	}
	// Make sure we can not lookup seq 1.
	if _, err := ms.LoadMsg(1, nil); err == nil {
		t.Fatalf("Expected error looking up seq 1 but got none")
	}
}

func TestMemStoreBytesLimit(t *testing.T) {
	subj, msg := "foo", make([]byte, 512)
	storedMsgSize := memStoreMsgSize(subj, nil, msg)

	toStore := uint64(1024)
	maxBytes := storedMsgSize * toStore

	ms, err := newMemStore(&StreamConfig{Storage: MemoryStorage, MaxBytes: int64(maxBytes)})
	require_NoError(t, err)
	defer ms.Stop()

	for i := uint64(0); i < toStore; i++ {
		ms.StoreMsg(subj, nil, msg, 0)
	}
	state := ms.State()
	if state.Msgs != toStore {
		t.Fatalf("Expected %d msgs, got %d", toStore, state.Msgs)
	}
	if state.Bytes != storedMsgSize*toStore {
		t.Fatalf("Expected bytes to be %d, got %d", storedMsgSize*toStore, state.Bytes)
	}

	// Now send 10 more and check that bytes limit enforced.
	for i := 0; i < 10; i++ {
		if _, _, err := ms.StoreMsg(subj, nil, msg, 0); err != nil {
			t.Fatalf("Error storing msg: %v", err)
		}
	}
	state = ms.State()
	if state.Msgs != toStore {
		t.Fatalf("Expected %d msgs, got %d", toStore, state.Msgs)
	}
	if state.Bytes != storedMsgSize*toStore {
		t.Fatalf("Expected bytes to be %d, got %d", storedMsgSize*toStore, state.Bytes)
	}
	if state.FirstSeq != 11 {
		t.Fatalf("Expected first sequence to be 11, got %d", state.FirstSeq)
	}
	if state.LastSeq != toStore+10 {
		t.Fatalf("Expected last sequence to be %d, got %d", toStore+10, state.LastSeq)
	}
}

// https://github.com/nats-io/nats-server/issues/4771
func TestMemStoreBytesLimitWithDiscardNew(t *testing.T) {
	subj, msg := "tiny", make([]byte, 7)
	storedMsgSize := memStoreMsgSize(subj, nil, msg)

	toStore := uint64(3)
	maxBytes := 100

	ms, err := newMemStore(&StreamConfig{Storage: MemoryStorage, MaxBytes: int64(maxBytes), Discard: DiscardNew})
	require_NoError(t, err)
	defer ms.Stop()

	// Now send 10 messages and check that bytes limit enforced.
	for i := 0; i < 10; i++ {
		_, _, err := ms.StoreMsg(subj, nil, msg, 0)
		if i < int(toStore) {
			if err != nil {
				t.Fatalf("Error storing msg: %v", err)
			}
		} else if !errors.Is(err, ErrMaxBytes) {
			t.Fatalf("Storing msg should result in: %v", ErrMaxBytes)
		}
	}
	state := ms.State()
	if state.Msgs != toStore {
		t.Fatalf("Expected %d msgs, got %d", toStore, state.Msgs)
	}
	if state.Bytes != storedMsgSize*toStore {
		t.Fatalf("Expected bytes to be %d, got %d", storedMsgSize*toStore, state.Bytes)
	}
}

func TestMemStoreAgeLimit(t *testing.T) {
	maxAge := 10 * time.Millisecond
	ms, err := newMemStore(&StreamConfig{Storage: MemoryStorage, MaxAge: maxAge})
	require_NoError(t, err)
	defer ms.Stop()

	// Store some messages. Does not really matter how many.
	subj, msg := "foo", []byte("Hello World")
	toStore := 100
	for i := 0; i < toStore; i++ {
		ms.StoreMsg(subj, nil, msg, 0)
	}
	state := ms.State()
	if state.Msgs != uint64(toStore) {
		t.Fatalf("Expected %d msgs, got %d", toStore, state.Msgs)
	}
	checkExpired := func(t *testing.T) {
		t.Helper()
		checkFor(t, time.Second, maxAge, func() error {
			state = ms.State()
			if state.Msgs != 0 {
				return fmt.Errorf("Expected no msgs, got %d", state.Msgs)
			}
			if state.Bytes != 0 {
				return fmt.Errorf("Expected no bytes, got %d", state.Bytes)
			}
			return nil
		})
	}
	// Let them expire
	checkExpired(t)
	// Now add some more and make sure that timer will fire again.
	for i := 0; i < toStore; i++ {
		ms.StoreMsg(subj, nil, msg, 0)
	}
	state = ms.State()
	if state.Msgs != uint64(toStore) {
		t.Fatalf("Expected %d msgs, got %d", toStore, state.Msgs)
	}
	checkExpired(t)
}

func TestMemStoreTimeStamps(t *testing.T) {
	ms, err := newMemStore(&StreamConfig{Storage: MemoryStorage})
	require_NoError(t, err)
	defer ms.Stop()

	last := time.Now().UnixNano()
	subj, msg := "foo", []byte("Hello World")
	for i := 0; i < 10; i++ {
		time.Sleep(5 * time.Microsecond)
		ms.StoreMsg(subj, nil, msg, 0)
	}
	var smv StoreMsg
	for seq := uint64(1); seq <= 10; seq++ {
		sm, err := ms.LoadMsg(seq, &smv)
		if err != nil {
			t.Fatalf("Unexpected error looking up msg: %v", err)
		}
		// These should be different
		if sm.ts <= last {
			t.Fatalf("Expected different timestamps, got %v", sm.ts)
		}
		last = sm.ts
	}
}

func TestMemStorePurge(t *testing.T) {
	ms, err := newMemStore(&StreamConfig{Storage: MemoryStorage})
	require_NoError(t, err)
	defer ms.Stop()

	subj, msg := "foo", []byte("Hello World")
	for i := 0; i < 10; i++ {
		ms.StoreMsg(subj, nil, msg, 0)
	}
	if state := ms.State(); state.Msgs != 10 {
		t.Fatalf("Expected 10 msgs, got %d", state.Msgs)
	}
	ms.Purge()
	if state := ms.State(); state.Msgs != 0 {
		t.Fatalf("Expected no msgs, got %d", state.Msgs)
	}
}

func TestMemStoreCompact(t *testing.T) {
	ms, err := newMemStore(&StreamConfig{Storage: MemoryStorage})
	require_NoError(t, err)
	defer ms.Stop()

	subj, msg := "foo", []byte("Hello World")
	for i := 0; i < 10; i++ {
		ms.StoreMsg(subj, nil, msg, 0)
	}
	if state := ms.State(); state.Msgs != 10 {
		t.Fatalf("Expected 10 msgs, got %d", state.Msgs)
	}
	n, err := ms.Compact(6)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("Expected to have purged 5 msgs, got %d", n)
	}
	state := ms.State()
	if state.Msgs != 5 {
		t.Fatalf("Expected 5 msgs, got %d", state.Msgs)
	}
	if state.FirstSeq != 6 {
		t.Fatalf("Expected first seq of 6, got %d", state.FirstSeq)
	}
	// Now test that compact will also reset first if seq > last
	n, err = ms.Compact(100)
	if err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if n != 5 {
		t.Fatalf("Expected to have purged 5 msgs, got %d", n)
	}
	if state = ms.State(); state.FirstSeq != 100 {
		t.Fatalf("Expected first seq of 100, got %d", state.FirstSeq)
	}
}

func TestMemStoreEraseMsg(t *testing.T) {
	ms, err := newMemStore(&StreamConfig{Storage: MemoryStorage})
	require_NoError(t, err)
	defer ms.Stop()

	subj, msg := "foo", []byte("Hello World")
	ms.StoreMsg(subj, nil, msg, 0)
	sm, err := ms.LoadMsg(1, nil)
	if err != nil {
		t.Fatalf("Unexpected error looking up msg: %v", err)
	}
	if !bytes.Equal(msg, sm.msg) {
		t.Fatalf("Expected same msg, got %q vs %q", sm.msg, msg)
	}
	if removed, _ := ms.EraseMsg(1); !removed {
		t.Fatalf("Expected erase msg to return success")
	}
}

func TestMemStoreMsgHeaders(t *testing.T) {
	ms, err := newMemStore(&StreamConfig{Storage: MemoryStorage})
	require_NoError(t, err)
	defer ms.Stop()

	subj, hdr, msg := "foo", []byte("name:derek"), []byte("Hello World")
	if sz := int(memStoreMsgSize(subj, hdr, msg)); sz != (len(subj) + len(hdr) + len(msg) + 16) {
		t.Fatalf("Wrong size for stored msg with header")
	}
	ms.StoreMsg(subj, hdr, msg, 0)
	sm, err := ms.LoadMsg(1, nil)
	if err != nil {
		t.Fatalf("Unexpected error looking up msg: %v", err)
	}
	if !bytes.Equal(msg, sm.msg) {
		t.Fatalf("Expected same msg, got %q vs %q", sm.msg, msg)
	}
	if !bytes.Equal(hdr, sm.hdr) {
		t.Fatalf("Expected same hdr, got %q vs %q", sm.hdr, hdr)
	}
	if removed, _ := ms.EraseMsg(1); !removed {
		t.Fatalf("Expected erase msg to return success")
	}
}

func TestMemStoreStreamStateDeleted(t *testing.T) {
	ms, err := newMemStore(&StreamConfig{Storage: MemoryStorage})
	require_NoError(t, err)
	defer ms.Stop()

	subj, toStore := "foo", uint64(10)
	for i := uint64(1); i <= toStore; i++ {
		msg := []byte(fmt.Sprintf("[%08d] Hello World!", i))
		if _, _, err := ms.StoreMsg(subj, nil, msg, 0); err != nil {
			t.Fatalf("Error storing msg: %v", err)
		}
	}
	state := ms.State()
	if len(state.Deleted) != 0 {
		t.Fatalf("Expected deleted to be empty")
	}
	// Now remove some interior messages.
	var expected []uint64
	for seq := uint64(2); seq < toStore; seq += 2 {
		ms.RemoveMsg(seq)
		expected = append(expected, seq)
	}
	state = ms.State()
	if !reflect.DeepEqual(state.Deleted, expected) {
		t.Fatalf("Expected deleted to be %+v, got %+v\n", expected, state.Deleted)
	}
	// Now fill the gap by deleting 1 and 3
	ms.RemoveMsg(1)
	ms.RemoveMsg(3)
	expected = expected[2:]
	state = ms.State()
	if !reflect.DeepEqual(state.Deleted, expected) {
		t.Fatalf("Expected deleted to be %+v, got %+v\n", expected, state.Deleted)
	}
	if state.FirstSeq != 5 {
		t.Fatalf("Expected first seq to be 5, got %d", state.FirstSeq)
	}
	ms.Purge()
	if state = ms.State(); len(state.Deleted) != 0 {
		t.Fatalf("Expected no deleted after purge, got %+v\n", state.Deleted)
	}
}

func TestMemStoreStreamTruncate(t *testing.T) {
	ms, err := newMemStore(&StreamConfig{Storage: MemoryStorage})
	require_NoError(t, err)
	defer ms.Stop()

	tseq := uint64(50)

	subj, toStore := "foo", uint64(100)
	for i := uint64(1); i < tseq; i++ {
		_, _, err := ms.StoreMsg(subj, nil, []byte("ok"), 0)
		require_NoError(t, err)
	}
	subj = "bar"
	for i := tseq; i <= toStore; i++ {
		_, _, err := ms.StoreMsg(subj, nil, []byte("ok"), 0)
		require_NoError(t, err)
	}

	if state := ms.State(); state.Msgs != toStore {
		t.Fatalf("Expected %d msgs, got %d", toStore, state.Msgs)
	}

	if err := ms.Truncate(tseq); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	if state := ms.State(); state.Msgs != tseq {
		t.Fatalf("Expected %d msgs, got %d", tseq, state.Msgs)
	}

	// Now make sure we report properly if we have some deleted interior messages.
	ms.RemoveMsg(10)
	ms.RemoveMsg(20)
	ms.RemoveMsg(30)
	ms.RemoveMsg(40)

	tseq = uint64(25)
	if err := ms.Truncate(tseq); err != nil {
		t.Fatalf("Unexpected error: %v", err)
	}
	state := ms.State()
	if state.Msgs != tseq-2 {
		t.Fatalf("Expected %d msgs, got %d", tseq-2, state.Msgs)
	}
	if state.NumSubjects != 1 {
		t.Fatalf("Expected only 1 subject, got %d", state.NumSubjects)
	}
	expected := []uint64{10, 20}
	if !reflect.DeepEqual(state.Deleted, expected) {
		t.Fatalf("Expected deleted to be %+v, got %+v\n", expected, state.Deleted)
	}
}

func TestMemStorePurgeExWithSubject(t *testing.T) {
	ms, err := newMemStore(&StreamConfig{Storage: MemoryStorage})
	require_NoError(t, err)
	defer ms.Stop()

	for i := 0; i < 100; i++ {
		_, _, err = ms.StoreMsg("foo", nil, nil, 0)
		require_NoError(t, err)
	}

	// This should purge all.
	ms.PurgeEx("foo", 0, 0)
	require_True(t, ms.State().Msgs == 0)
}

func TestMemStoreUpdateMaxMsgsPerSubject(t *testing.T) {
	cfg := &StreamConfig{
		Name:       "TEST",
		Storage:    MemoryStorage,
		Subjects:   []string{"foo"},
		MaxMsgsPer: 10,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	// Make sure this is honored on an update.
	cfg.MaxMsgsPer = 50
	err = ms.UpdateConfig(cfg)
	require_NoError(t, err)

	numStored := 22
	for i := 0; i < numStored; i++ {
		_, _, err = ms.StoreMsg("foo", nil, nil, 0)
		require_NoError(t, err)
	}

	ss := ms.SubjectsState("foo")["foo"]
	if ss.Msgs != uint64(numStored) {
		t.Fatalf("Expected to have %d stored, got %d", numStored, ss.Msgs)
	}

	// Now make sure we trunk if setting to lower value.
	cfg.MaxMsgsPer = 10
	err = ms.UpdateConfig(cfg)
	require_NoError(t, err)

	ss = ms.SubjectsState("foo")["foo"]
	if ss.Msgs != 10 {
		t.Fatalf("Expected to have %d stored, got %d", 10, ss.Msgs)
	}
}

func TestMemStoreStreamTruncateReset(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "TEST",
		Storage:  MemoryStorage,
		Subjects: []string{"foo"},
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	subj, msg := "foo", []byte("Hello World")
	for i := 0; i < 1000; i++ {
		_, _, err := ms.StoreMsg(subj, nil, msg, 0)
		require_NoError(t, err)
	}

	// Reset everything
	require_NoError(t, ms.Truncate(0))

	state := ms.State()
	require_True(t, state.Msgs == 0)
	require_True(t, state.Bytes == 0)
	require_True(t, state.FirstSeq == 0)
	require_True(t, state.LastSeq == 0)
	require_True(t, state.NumSubjects == 0)
	require_True(t, state.NumDeleted == 0)

	for i := 0; i < 1000; i++ {
		_, _, err := ms.StoreMsg(subj, nil, msg, 0)
		require_NoError(t, err)
	}

	state = ms.State()
	require_True(t, state.Msgs == 1000)
	require_True(t, state.Bytes == 30000)
	require_True(t, state.FirstSeq == 1)
	require_True(t, state.LastSeq == 1000)
	require_True(t, state.NumSubjects == 1)
	require_True(t, state.NumDeleted == 0)
}

func TestMemStoreStreamCompactMultiBlockSubjectInfo(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "TEST",
		Storage:  MemoryStorage,
		Subjects: []string{"foo.*"},
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	for i := 0; i < 1000; i++ {
		subj := fmt.Sprintf("foo.%d", i)
		_, _, err := ms.StoreMsg(subj, nil, []byte("Hello World"), 0)
		require_NoError(t, err)
	}

	// Compact such that we know we throw blocks away from the beginning.
	deleted, err := ms.Compact(501)
	require_NoError(t, err)
	require_True(t, deleted == 500)

	// Make sure we adjusted for subjects etc.
	state := ms.State()
	require_True(t, state.NumSubjects == 500)
}

func TestMemStoreSubjectsTotals(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "TEST",
		Storage:  MemoryStorage,
		Subjects: []string{"*.*"},
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	fmap := make(map[int]int)
	bmap := make(map[int]int)

	var m map[int]int
	var ft string

	for i := 0; i < 10_000; i++ {
		// Flip coin for prefix
		if rand.IntN(2) == 0 {
			ft, m = "foo", fmap
		} else {
			ft, m = "bar", bmap
		}
		dt := rand.IntN(100)
		subj := fmt.Sprintf("%s.%d", ft, dt)
		m[dt]++

		_, _, err := ms.StoreMsg(subj, nil, []byte("Hello World"), 0)
		require_NoError(t, err)
	}

	// Now test SubjectsTotal
	for dt, total := range fmap {
		subj := fmt.Sprintf("foo.%d", dt)
		m := ms.SubjectsTotals(subj)
		if m[subj] != uint64(total) {
			t.Fatalf("Expected %q to have %d total, got %d", subj, total, m[subj])
		}
	}

	// Check fmap.
	if st := ms.SubjectsTotals("foo.*"); len(st) != len(fmap) {
		t.Fatalf("Expected %d subjects for %q, got %d", len(fmap), "foo.*", len(st))
	} else {
		expected := 0
		for _, n := range fmap {
			expected += n
		}
		received := uint64(0)
		for _, n := range st {
			received += n
		}
		if received != uint64(expected) {
			t.Fatalf("Expected %d total but got %d", expected, received)
		}
	}

	// Check bmap.
	if st := ms.SubjectsTotals("bar.*"); len(st) != len(bmap) {
		t.Fatalf("Expected %d subjects for %q, got %d", len(bmap), "bar.*", len(st))
	} else {
		expected := 0
		for _, n := range bmap {
			expected += n
		}
		received := uint64(0)
		for _, n := range st {
			received += n
		}
		if received != uint64(expected) {
			t.Fatalf("Expected %d total but got %d", expected, received)
		}
	}

	// All with pwc match.
	if st, expected := ms.SubjectsTotals("*.*"), len(bmap)+len(fmap); len(st) != expected {
		t.Fatalf("Expected %d subjects for %q, got %d", expected, "*.*", len(st))
	}
}

func TestMemStoreNumPending(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "TEST",
		Storage:  MemoryStorage,
		Subjects: []string{"*.*.*.*"},
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	tokens := []string{"foo", "bar", "baz"}
	genSubj := func() string {
		return fmt.Sprintf("%s.%s.%s.%s",
			tokens[rand.IntN(len(tokens))],
			tokens[rand.IntN(len(tokens))],
			tokens[rand.IntN(len(tokens))],
			tokens[rand.IntN(len(tokens))],
		)
	}

	for i := 0; i < 50_000; i++ {
		subj := genSubj()
		_, _, err := ms.StoreMsg(subj, nil, []byte("Hello World"), 0)
		require_NoError(t, err)
	}

	state := ms.State()

	// Scan one by one for sanity check against other calculations.
	sanityCheck := func(sseq uint64, filter string) SimpleState {
		t.Helper()
		var ss SimpleState
		var smv StoreMsg
		// For here we know 0 is invalid, set to 1.
		if sseq == 0 {
			sseq = 1
		}
		for seq := sseq; seq <= state.LastSeq; seq++ {
			sm, err := ms.LoadMsg(seq, &smv)
			if err != nil {
				t.Logf("Encountered error %v loading sequence: %d", err, seq)
				continue
			}
			if subjectIsSubsetMatch(sm.subj, filter) {
				ss.Msgs++
				ss.Last = seq
				if ss.First == 0 || seq < ss.First {
					ss.First = seq
				}
			}
		}
		return ss
	}

	check := func(sseq uint64, filter string) {
		t.Helper()
		np, lvs, err := ms.NumPending(sseq, filter, false)
		if err != nil {
			t.Fatalf("NumPending error: %v", err)
		}
		ss, err := ms.FilteredState(sseq, filter)
		require_NoError(t, err)
		sss := sanityCheck(sseq, filter)
		if lvs != state.LastSeq {
			t.Fatalf("Expected NumPending to return valid through last of %d but got %d", state.LastSeq, lvs)
		}
		if ss.Msgs != np {
			t.Fatalf("NumPending of %d did not match ss.Msgs of %d", np, ss.Msgs)
		}
		if ss != sss {
			t.Fatalf("Failed sanity check, expected %+v got %+v", sss, ss)
		}
	}

	sanityCheckLastOnly := func(sseq uint64, filter string) SimpleState {
		t.Helper()
		var ss SimpleState
		var smv StoreMsg
		// For here we know 0 is invalid, set to 1.
		if sseq == 0 {
			sseq = 1
		}
		seen := make(map[string]bool)
		for seq := state.LastSeq; seq >= sseq; seq-- {
			sm, err := ms.LoadMsg(seq, &smv)
			if err != nil {
				t.Logf("Encountered error %v loading sequence: %d", err, seq)
				continue
			}
			if !seen[sm.subj] && subjectIsSubsetMatch(sm.subj, filter) {
				ss.Msgs++
				if ss.Last == 0 {
					ss.Last = seq
				}
				if ss.First == 0 || seq < ss.First {
					ss.First = seq
				}
				seen[sm.subj] = true
			}
		}
		return ss
	}

	checkLastOnly := func(sseq uint64, filter string) {
		t.Helper()
		np, lvs, err := ms.NumPending(sseq, filter, true)
		if err != nil {
			t.Fatalf("NumPending error: %v", err)
		}
		ss := sanityCheckLastOnly(sseq, filter)
		if lvs != state.LastSeq {
			t.Fatalf("Expected NumPending to return valid through last of %d but got %d", state.LastSeq, lvs)
		}
		if ss.Msgs != np {
			t.Fatalf("NumPending of %d did not match ss.Msgs of %d", np, ss.Msgs)
		}
	}

	startSeqs := []uint64{0, 1, 2, 200, 444, 555, 2222, 8888, 12_345, 28_222, 33_456, 44_400, 49_999}
	checkSubs := []string{"foo.>", "*.bar.>", "foo.bar.*.baz", "*.bar.>", "*.foo.bar.*", "foo.foo.bar.baz"}

	for _, filter := range checkSubs {
		for _, start := range startSeqs {
			check(start, filter)
			checkLastOnly(start, filter)
		}
	}
}

func TestMemStoreInitialFirstSeq(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Storage:  MemoryStorage,
		FirstSeq: 1000,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	seq, _, err := ms.StoreMsg("A", nil, []byte("OK"), 0)
	require_NoError(t, err)
	if seq != 1000 {
		t.Fatalf("Message should have been sequence 1000 but was %d", seq)
	}

	seq, _, err = ms.StoreMsg("B", nil, []byte("OK"), 0)
	require_NoError(t, err)
	if seq != 1001 {
		t.Fatalf("Message should have been sequence 1001 but was %d", seq)
	}

	var state StreamState
	ms.FastState(&state)
	switch {
	case state.Msgs != 2:
		t.Fatalf("Expected 2 messages, got %d", state.Msgs)
	case state.FirstSeq != 1000:
		t.Fatalf("Expected first seq 1000, got %d", state.FirstSeq)
	case state.LastSeq != 1001:
		t.Fatalf("Expected last seq 1001, got %d", state.LastSeq)
	}
}

func TestMemStoreDeleteBlocks(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"*"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	// Put in 10_000 msgs.
	total := 10_000
	for i := 0; i < total; i++ {
		_, _, err := ms.StoreMsg("A", nil, []byte("OK"), 0)
		require_NoError(t, err)
	}

	// Now pick 5k random sequences.
	delete := 5000
	deleteMap := make(map[int]struct{}, delete)
	for len(deleteMap) < delete {
		deleteMap[rand.IntN(total)+1] = struct{}{}
	}
	// Now remove?
	for seq := range deleteMap {
		ms.RemoveMsg(uint64(seq))
	}

	var state StreamState
	ms.FastState(&state)

	// For now we just track via one dmap.
	ms.mu.RLock()
	dmap := ms.dmap.Clone()
	ms.mu.RUnlock()

	require_True(t, dmap.Size() == state.NumDeleted)
}

// https://github.com/nats-io/nats-server/issues/4850
func TestMemStoreGetSeqFromTimeWithLastDeleted(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"*"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	// Put in 1000 msgs.
	total := 1000
	var st time.Time
	for i := 1; i <= total; i++ {
		_, _, err := ms.StoreMsg("A", nil, []byte("OK"), 0)
		require_NoError(t, err)
		if i == total/2 {
			time.Sleep(100 * time.Millisecond)
			st = time.Now()
		}
	}
	// Delete last 100
	for seq := total - 100; seq <= total; seq++ {
		ms.RemoveMsg(uint64(seq))
	}

	// Make sure this does not panic with last sequence no longer accessible.
	seq := ms.GetSeqFromTime(st)
	// Make sure we get the right value.
	require_Equal(t, seq, 501)
}

func TestMemStoreSkipMsgs(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"*"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	// Test on empty FS first.
	// Make sure wrong starting sequence fails.
	err = ms.SkipMsgs(10, 100)
	require_Error(t, err, ErrSequenceMismatch)

	err = ms.SkipMsgs(1, 100)
	require_NoError(t, err)

	state := ms.State()
	require_Equal(t, state.FirstSeq, 101)
	require_Equal(t, state.LastSeq, 100)

	// Now add alot.
	err = ms.SkipMsgs(101, 100_000)
	require_NoError(t, err)
	state = ms.State()
	require_Equal(t, state.FirstSeq, 100_101)
	require_Equal(t, state.LastSeq, 100_100)

	// Now add in a message, and then skip to check dmap.
	ms, err = newMemStore(cfg)
	require_NoError(t, err)
	ms.StoreMsg("foo", nil, nil, 0)

	err = ms.SkipMsgs(2, 10)
	require_NoError(t, err)
	state = ms.State()
	require_Equal(t, state.FirstSeq, 1)
	require_Equal(t, state.LastSeq, 11)
	require_Equal(t, state.Msgs, 1)
	require_Equal(t, state.NumDeleted, 10)
	require_Equal(t, len(state.Deleted), 10)

	// Check Fast State too.
	state.Deleted = nil
	ms.FastState(&state)
	require_Equal(t, state.FirstSeq, 1)
	require_Equal(t, state.LastSeq, 11)
	require_Equal(t, state.Msgs, 1)
	require_Equal(t, state.NumDeleted, 10)
}

func TestMemStoreMultiLastSeqs(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"foo.*", "bar.*"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	msg := []byte("abc")
	for i := 0; i < 33; i++ {
		ms.StoreMsg("foo.foo", nil, msg, 0)
		ms.StoreMsg("foo.bar", nil, msg, 0)
		ms.StoreMsg("foo.baz", nil, msg, 0)
	}
	for i := 0; i < 33; i++ {
		ms.StoreMsg("bar.foo", nil, msg, 0)
		ms.StoreMsg("bar.bar", nil, msg, 0)
		ms.StoreMsg("bar.baz", nil, msg, 0)
	}

	checkResults := func(seqs, expected []uint64) {
		t.Helper()
		if len(seqs) != len(expected) {
			t.Fatalf("Expected %+v got %+v", expected, seqs)
		}
		for i := range seqs {
			if seqs[i] != expected[i] {
				t.Fatalf("Expected %+v got %+v", expected, seqs)
			}
		}
	}

	// UpTo sequence 3. Tests block split.
	seqs, err := ms.MultiLastSeqs([]string{"foo.*"}, 3, -1)
	require_NoError(t, err)
	checkResults(seqs, []uint64{1, 2, 3})
	// Up to last sequence of the stream.
	seqs, err = ms.MultiLastSeqs([]string{"foo.*"}, 0, -1)
	require_NoError(t, err)
	checkResults(seqs, []uint64{97, 98, 99})
	// Check for bar.* at the end.
	seqs, err = ms.MultiLastSeqs([]string{"bar.*"}, 0, -1)
	require_NoError(t, err)
	checkResults(seqs, []uint64{196, 197, 198})
	// This should find nothing.
	seqs, err = ms.MultiLastSeqs([]string{"bar.*"}, 99, -1)
	require_NoError(t, err)
	checkResults(seqs, nil)

	// Do multiple subjects explicitly.
	seqs, err = ms.MultiLastSeqs([]string{"foo.foo", "foo.bar", "foo.baz"}, 3, -1)
	require_NoError(t, err)
	checkResults(seqs, []uint64{1, 2, 3})
	seqs, err = ms.MultiLastSeqs([]string{"foo.foo", "foo.bar", "foo.baz"}, 0, -1)
	require_NoError(t, err)
	checkResults(seqs, []uint64{97, 98, 99})
	seqs, err = ms.MultiLastSeqs([]string{"bar.foo", "bar.bar", "bar.baz"}, 0, -1)
	require_NoError(t, err)
	checkResults(seqs, []uint64{196, 197, 198})
	seqs, err = ms.MultiLastSeqs([]string{"bar.foo", "bar.bar", "bar.baz"}, 99, -1)
	require_NoError(t, err)
	checkResults(seqs, nil)

	// Check single works
	seqs, err = ms.MultiLastSeqs([]string{"foo.foo"}, 3, -1)
	require_NoError(t, err)
	checkResults(seqs, []uint64{1})

	// Now test that we properly de-duplicate between filters.
	seqs, err = ms.MultiLastSeqs([]string{"foo.*", "foo.bar"}, 3, -1)
	require_NoError(t, err)
	checkResults(seqs, []uint64{1, 2, 3})
	seqs, err = ms.MultiLastSeqs([]string{"bar.>", "bar.bar", "bar.baz"}, 0, -1)
	require_NoError(t, err)
	checkResults(seqs, []uint64{196, 197, 198})

	// All
	seqs, err = ms.MultiLastSeqs([]string{">"}, 0, -1)
	require_NoError(t, err)
	checkResults(seqs, []uint64{97, 98, 99, 196, 197, 198})
	seqs, err = ms.MultiLastSeqs([]string{">"}, 99, -1)
	require_NoError(t, err)
	checkResults(seqs, []uint64{97, 98, 99})
}

func TestMemStoreMultiLastSeqsMaxAllowed(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"foo.*"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	msg := []byte("abc")
	for i := 1; i <= 100; i++ {
		ms.StoreMsg(fmt.Sprintf("foo.%d", i), nil, msg, 0)
	}
	// Test that if we specify maxAllowed that we get the correct error.
	seqs, err := ms.MultiLastSeqs([]string{"foo.*"}, 0, 10)
	require_True(t, seqs == nil)
	require_Error(t, err, ErrTooManyResults)
}

// Bug would cause PurgeEx to fail if it encountered a deleted msg at sequence to delete up to.
func TestMemStorePurgeExWithDeletedMsgs(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"foo"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	msg := []byte("abc")
	for i := 1; i <= 10; i++ {
		ms.StoreMsg("foo", nil, msg, 0)
	}
	ms.RemoveMsg(2)
	ms.RemoveMsg(9) // This was the bug

	n, err := ms.PurgeEx(_EMPTY_, 9, 0)
	require_NoError(t, err)
	require_Equal(t, n, 7)

	var state StreamState
	ms.FastState(&state)
	require_Equal(t, state.FirstSeq, 10)
	require_Equal(t, state.LastSeq, 10)
	require_Equal(t, state.Msgs, 1)
}

// When all messages are deleted we should have a state of first = last + 1.
func TestMemStoreDeleteAllFirstSequenceCheck(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"foo"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	msg := []byte("abc")
	for i := 1; i <= 10; i++ {
		ms.StoreMsg("foo", nil, msg, 0)
	}
	for seq := uint64(1); seq <= 10; seq++ {
		ms.RemoveMsg(seq)
	}
	var state StreamState
	ms.FastState(&state)
	require_Equal(t, state.FirstSeq, 11)
	require_Equal(t, state.LastSeq, 10)
	require_Equal(t, state.Msgs, 0)
}

func TestMemStoreNumPendingMulti(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"ev.*"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	totalMsgs := 100_000
	totalSubjects := 10_000
	numFiltered := 5000
	startSeq := uint64(5_000 + rand.IntN(90_000))

	subjects := make([]string, 0, totalSubjects)
	for i := 0; i < totalSubjects; i++ {
		subjects = append(subjects, fmt.Sprintf("ev.%s", nuid.Next()))
	}

	// Put in 100k msgs with random subjects.
	msg := bytes.Repeat([]byte("ZZZ"), 333)
	for i := 0; i < totalMsgs; i++ {
		_, _, err = ms.StoreMsg(subjects[rand.IntN(totalSubjects)], nil, msg, 0)
		require_NoError(t, err)
	}

	// Now we want to do a calculate NumPendingMulti.
	filters := gsl.NewSublist[struct{}]()
	for filters.Count() < uint32(numFiltered) {
		filter := subjects[rand.IntN(totalSubjects)]
		if !filters.HasInterest(filter) {
			filters.Insert(filter, struct{}{})
		}
	}

	// Use new function.
	total, _, err := ms.NumPendingMulti(startSeq, filters, false)
	require_NoError(t, err)

	// Check our results.
	var checkTotal uint64
	var smv StoreMsg
	for seq := startSeq; seq <= uint64(totalMsgs); seq++ {
		sm, err := ms.LoadMsg(seq, &smv)
		require_NoError(t, err)
		if filters.HasInterest(sm.subj) {
			checkTotal++
		}
	}
	require_Equal(t, total, checkTotal)
}

func TestMemStoreNumPendingBug(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"foo.*"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	// 12 msgs total
	for _, subj := range []string{"foo.foo", "foo.bar", "foo.baz", "foo.zzz"} {
		ms.StoreMsg("foo.aaa", nil, nil, 0)
		ms.StoreMsg(subj, nil, nil, 0)
		ms.StoreMsg(subj, nil, nil, 0)
	}
	total, _, err := ms.NumPending(4, "foo.*", false)
	require_NoError(t, err)

	var checkTotal uint64
	var smv StoreMsg
	for seq := 4; seq <= 12; seq++ {
		sm, err := ms.LoadMsg(uint64(seq), &smv)
		require_NoError(t, err)
		if subjectIsSubsetMatch(sm.subj, "foo.*") {
			checkTotal++
		}
	}
	require_Equal(t, total, checkTotal)
}

func TestMemStorePurgeLeaksDmap(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "TEST",
		Subjects: []string{"foo"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	for i := 0; i < 10; i++ {
		_, _, err = ms.StoreMsg("foo", nil, nil, 0)
		require_NoError(t, err)
	}

	for i := uint64(2); i <= 9; i++ {
		_, err = ms.RemoveMsg(i)
		require_NoError(t, err)
	}
	ms.mu.Lock()
	dmaps := ms.dmap.Size()
	ms.mu.Unlock()
	require_Equal(t, dmaps, 8)

	purged, err := ms.Purge()
	require_NoError(t, err)
	require_Equal(t, purged, 2)

	ms.mu.Lock()
	dmaps = ms.dmap.Size()
	ms.mu.Unlock()
	require_Equal(t, dmaps, 0)
}

func TestMemStoreMessageTTL(t *testing.T) {
	fs, err := newMemStore(
		&StreamConfig{Name: "zzz", Subjects: []string{"test"}, Storage: MemoryStorage, AllowMsgTTL: true},
	)
	require_NoError(t, err)
	defer fs.Stop()

	ttl := int64(1) // 1 second

	for i := 1; i <= 10; i++ {
		_, _, err = fs.StoreMsg("test", nil, nil, ttl)
		require_NoError(t, err)
	}

	var ss StreamState
	fs.FastState(&ss)
	require_Equal(t, ss.FirstSeq, 1)
	require_Equal(t, ss.LastSeq, 10)
	require_Equal(t, ss.Msgs, 10)

	time.Sleep(time.Second * 2)

	fs.FastState(&ss)
	require_Equal(t, ss.FirstSeq, 11)
	require_Equal(t, ss.LastSeq, 10)
	require_Equal(t, ss.Msgs, 0)
}

func TestMemStoreSubjectDeleteMarkers(t *testing.T) {
	fs, err := newMemStore(
		&StreamConfig{
			Name: "zzz", Subjects: []string{"test"}, Storage: MemoryStorage,
			MaxAge: time.Second, AllowMsgTTL: true,
			SubjectDeleteMarkerTTL: time.Second,
		},
	)
	require_NoError(t, err)
	defer fs.Stop()

	// Capture subject delete marker proposals.
	ch := make(chan *inMsg, 1)
	fs.rmcb = func(seq uint64) {
		_, err := fs.RemoveMsg(seq)
		require_NoError(t, err)
	}
	fs.pmsgcb = func(im *inMsg) {
		ch <- im
	}

	// Store three messages that will expire because of MaxAge.
	for i := 0; i < 3; i++ {
		_, _, err = fs.StoreMsg("test", nil, nil, 0)
		require_NoError(t, err)
	}

	// Wait for MaxAge to pass.
	time.Sleep(time.Second + time.Millisecond*500)

	// We should have placed a subject delete marker.
	im := require_ChanRead(t, ch, time.Second*5)
	require_Equal(t, bytesToString(getHeader(JSMarkerReason, im.hdr)), JSMarkerReasonMaxAge)
	require_Equal(t, bytesToString(getHeader(JSMessageTTL, im.hdr)), "1s")
}

func TestMemStoreAllLastSeqs(t *testing.T) {
	cfg := &StreamConfig{
		Name:       "zzz",
		Subjects:   []string{"*.*"},
		MaxMsgsPer: 50,
		Storage:    MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	subjs := []string{"foo.foo", "foo.bar", "foo.baz", "bar.foo", "bar.bar", "bar.baz"}
	msg := []byte("abc")

	for i := 0; i < 100_000; i++ {
		subj := subjs[rand.IntN(len(subjs))]
		ms.StoreMsg(subj, nil, msg, 0)
	}

	expected := make([]uint64, 0, len(subjs))
	var smv StoreMsg
	for _, subj := range subjs {
		sm, err := ms.LoadLastMsg(subj, &smv)
		require_NoError(t, err)
		expected = append(expected, sm.seq)
	}
	slices.Sort(expected)

	seqs, err := ms.AllLastSeqs()
	require_NoError(t, err)
	require_True(t, reflect.DeepEqual(seqs, expected))
}

func TestMemStoreUpdateConfigTTLState(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{">"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()
	require_Equal(t, ms.ttls, nil)

	cfg.AllowMsgTTL = true
	require_NoError(t, ms.UpdateConfig(cfg))
	require_NotEqual(t, ms.ttls, nil)

	cfg.AllowMsgTTL = false
	require_NoError(t, ms.UpdateConfig(cfg))
	require_Equal(t, ms.ttls, nil)
}

func TestMemStoreSubjectForSeq(t *testing.T) {
	cfg := StreamConfig{
		Name:     "foo",
		Subjects: []string{"foo.>"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(&cfg)
	require_NoError(t, err)

	seq, _, err := ms.StoreMsg("foo.bar", nil, nil, 0)
	require_NoError(t, err)
	require_Equal(t, seq, 1)

	_, err = ms.SubjectForSeq(0)
	require_Error(t, err, ErrStoreMsgNotFound)

	subj, err := ms.SubjectForSeq(1)
	require_NoError(t, err)
	require_Equal(t, subj, "foo.bar")

	_, err = ms.SubjectForSeq(2)
	require_Error(t, err, ErrStoreMsgNotFound)
}

func TestMemStoreMessageSchedule(t *testing.T) {
	fs, err := newMemStore(
		&StreamConfig{
			Name: "TEST", Subjects: []string{"foo.*"}, Storage: MemoryStorage,
			AllowMsgSchedules: true,
		},
	)
	require_NoError(t, err)
	defer fs.Stop()

	// Capture message schedule proposals.
	ch := make(chan *inMsg, 1)
	fs.pmsgcb = func(im *inMsg) {
		ch <- im
	}

	// Store a single message schedule.
	schedule := time.Now().Add(time.Second).Format(time.RFC3339Nano)
	hdr := genHeader(nil, JSSchedulePattern, fmt.Sprintf("@at %s", schedule))
	hdr = genHeader(hdr, JSScheduleTarget, "foo.target")
	_, _, err = fs.StoreMsg("foo.schedule", hdr, nil, 0)
	require_NoError(t, err)

	// We should have published a scheduled message.
	im := require_ChanRead(t, ch, time.Second*5)
	require_Equal(t, im.subj, "foo.target")
	require_Equal(t, bytesToString(getHeader(JSScheduler, im.hdr)), "foo.schedule")
	require_Equal(t, bytesToString(getHeader(JSScheduleNext, im.hdr)), JSScheduleNextPurge)
}

func TestMemStoreMessageScheduleEverySubSecondPrecision(t *testing.T) {
	fs, err := newMemStore(
		&StreamConfig{
			Name: "TEST", Subjects: []string{"foo.*"}, Storage: MemoryStorage,
			AllowMsgSchedules: true,
		},
	)
	require_NoError(t, err)
	defer fs.Stop()

	// Capture message schedule proposals.
	ch := make(chan *inMsg, 1)
	fs.pmsgcb = func(im *inMsg) {
		ch <- im
	}

	// Store a repeating message schedule with a sub-second remainder.
	hdr := genHeader(nil, JSSchedulePattern, "@every 1500ms")
	hdr = genHeader(hdr, JSScheduleTarget, "foo.target")
	_, ts, err := fs.StoreMsg("foo.schedule", hdr, nil, 0)
	require_NoError(t, err)

	// We should have published a scheduled message.
	im := require_ChanRead(t, ch, time.Second*3)
	require_Equal(t, im.subj, "foo.target")
	require_Equal(t, bytesToString(getHeader(JSScheduler, im.hdr)), "foo.schedule")

	// The re-arm header is written with RFC3339Nano so the sub-second component
	// of the next fire time survives the round trip through the header. Each
	// fire time anchors on the previous one rounded to the nearest second, plus
	// the interval: the first fire is round(store time) + 1500ms, and the
	// re-arm rounds that again (up, .5s rounds away from zero) before adding
	// another 1500ms.
	const interval = 1500 * time.Millisecond
	first := time.Unix(0, ts).UTC().Round(time.Second).Add(interval)
	expected := first.Round(time.Second).Add(interval)
	scheduleNext := bytesToString(getHeader(JSScheduleNext, im.hdr))
	next, err := time.Parse(time.RFC3339Nano, scheduleNext)
	require_NoError(t, err)
	require_Equal(t, next.UnixNano(), expected.UnixNano())
}

func TestMemStoreNextWildcardMatch(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"foo.>"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	msg := []byte("msg")
	storeN := func(subj string, n int) {
		t.Helper()
		for range n {
			_, _, err := ms.StoreMsg(subj, nil, msg, 0)
			require_NoError(t, err)
		}
	}
	storeN("foo.bar.a", 1)
	storeN("foo.baz.bar", 10)
	storeN("foo.bar.b", 1)
	storeN("foo.baz.bar", 10)
	storeN("foo.baz.bar.no.match", 10)

	ms.mu.Lock()
	defer ms.mu.Unlock()

	first, last, found := ms.nextWildcardMatchLocked("foo.bar.*", 0)
	require_True(t, found)
	require_Equal(t, first, 1)
	require_Equal(t, last, 12)

	first, last, found = ms.nextWildcardMatchLocked("foo.bar.*", 1)
	require_True(t, found)
	require_Equal(t, first, 1)
	require_Equal(t, last, 12)

	first, last, found = ms.nextWildcardMatchLocked("foo.bar.*", 2)
	require_True(t, found)
	require_Equal(t, first, 12)
	require_Equal(t, last, 12)

	_, _, found = ms.nextWildcardMatchLocked("foo.bar.*", first+1)
	require_False(t, found)

	first, last, found = ms.nextWildcardMatchLocked("foo.baz.*", 1)
	require_True(t, found)
	require_Equal(t, first, 2)
	require_Equal(t, last, 22)

	first, last, found = ms.nextWildcardMatchLocked("foo.baz.*", 11)
	require_True(t, found)
	require_Equal(t, first, 11)
	require_Equal(t, last, 22)

	first, last, found = ms.nextWildcardMatchLocked("foo.baz.*", 12)
	require_True(t, found)
	require_Equal(t, first, 12)
	require_Equal(t, last, 22)

	first, last, found = ms.nextWildcardMatchLocked("foo.baz.*", 22)
	require_True(t, found)
	require_Equal(t, first, 22)
	require_Equal(t, last, 22)

	first, last, found = ms.nextWildcardMatchLocked("foo.baz.*", 23)
	require_False(t, found)
	require_Equal(t, first, 0)
	require_Equal(t, last, 0)

	first, last, found = ms.nextWildcardMatchLocked("foo.nope.*", 1)
	require_False(t, found)
	require_Equal(t, first, 0)
	require_Equal(t, last, 0)

	first, last, found = ms.nextWildcardMatchLocked("foo.>", 1)
	require_True(t, found)
	require_Equal(t, first, 1)
	require_Equal(t, last, 32)
}

func TestMemStoreNextLiteralMatch(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"foo.>"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	msg := []byte("msg")
	storeN := func(subj string, n int) {
		t.Helper()
		for range n {
			_, _, err := ms.StoreMsg(subj, nil, msg, 0)
			require_NoError(t, err)
		}
	}
	storeN("foo.bar.a", 1)             // seq 1
	storeN("foo.baz.bar", 10)          // seqs 2-11
	storeN("foo.bar.b", 1)             // seq 12
	storeN("foo.baz.bar", 10)          // seqs 13-22
	storeN("foo.baz.bar.no.match", 10) // seqs 23-32

	ms.mu.Lock()
	defer ms.mu.Unlock()

	first, last, found := ms.nextLiteralMatchLocked("foo.bar.a", 0)
	require_True(t, found)
	require_Equal(t, first, 1)
	require_Equal(t, last, 1)

	_, _, found = ms.nextLiteralMatchLocked("foo.bar.a", 2)
	require_False(t, found)

	first, last, found = ms.nextLiteralMatchLocked("foo.baz.bar", 1)
	require_True(t, found)
	require_Equal(t, first, 2)
	require_Equal(t, last, 22)

	first, last, found = ms.nextLiteralMatchLocked("foo.baz.bar", 11)
	require_True(t, found)
	require_Equal(t, first, 11)
	require_Equal(t, last, 22)

	first, last, found = ms.nextLiteralMatchLocked("foo.baz.bar", 22)
	require_True(t, found)
	require_Equal(t, first, 22)
	require_Equal(t, last, 22)

	first, last, found = ms.nextLiteralMatchLocked("foo.baz.bar", 23)
	require_False(t, found)
	require_Equal(t, first, 0)
	require_Equal(t, last, 0)

	first, last, found = ms.nextLiteralMatchLocked("foo.nope", 1)
	require_False(t, found)
	require_Equal(t, first, 0)
	require_Equal(t, last, 0)

}

func TestMemStoreMultiLastSeqsDoesNotUseStaleLastValue(t *testing.T) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"foo", "bar", "baz"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(t, err)
	defer ms.Stop()

	subjects := []string{"foo", "bar", "foo", " baz", "foo", "foo", "bar", "foo", "bar", "baz"}
	for _, s := range subjects {
		_, _, err := ms.StoreMsg(s, nil, nil, 0)
		require_NoError(t, err)
	}

	// Initially we expect last seq for `foo` to be 8
	seqs, err := ms.MultiLastSeqs([]string{"foo", "bar"}, 0, 0)
	require_NoError(t, err)
	require_Equal(t, len(seqs), 2)
	require_Equal(t, seqs[0], uint64(8))

	// Remove latest foo message
	removed, err := ms.RemoveMsg(8)
	require_NoError(t, err)
	require_True(t, removed)

	// If bug is present: MultiLastSeqs returns last sequence
	// 8 for subject `foo`.
	// After removal, expect last sequence 6 for subject `foo`.
	seqs, err = ms.MultiLastSeqs([]string{"foo", "bar"}, 0, 0)
	require_NoError(t, err)
	require_Equal(t, len(seqs), 2)
	require_Equal(t, seqs[0], uint64(6))
}

///////////////////////////////////////////////////////////////////////////
// Benchmarks
///////////////////////////////////////////////////////////////////////////

func Benchmark_MemStoreNumPendingWithLargeInteriorDeletesScan(b *testing.B) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"foo.*.*"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(b, err)
	defer ms.Stop()

	msg := []byte("abc")
	ms.StoreMsg("foo.bar.baz", nil, msg, 0)
	for i := 1; i <= 1_000_000; i++ {
		ms.SkipMsg(0)
	}
	ms.StoreMsg("foo.bar.baz", nil, msg, 0)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		total, _, err := ms.NumPending(600_000, "foo.*.baz", false)
		require_NoError(b, err)
		if total != 1 {
			b.Fatalf("Expected total of 2 got %d", total)
		}
	}
}

func Benchmark_MemStoreNumPendingWithLargeInteriorDeletesExclude(b *testing.B) {
	cfg := &StreamConfig{
		Name:     "zzz",
		Subjects: []string{"foo.*.*"},
		Storage:  MemoryStorage,
	}
	ms, err := newMemStore(cfg)
	require_NoError(b, err)
	defer ms.Stop()

	msg := []byte("abc")
	ms.StoreMsg("foo.bar.baz", nil, msg, 0)
	for i := 1; i <= 1_000_000; i++ {
		ms.SkipMsg(0)
	}
	ms.StoreMsg("foo.bar.baz", nil, msg, 0)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		total, _, err := ms.NumPending(400_000, "foo.*.baz", false)
		require_NoError(b, err)
		if total != 1 {
			b.Fatalf("Expected total of 2 got %d", total)
		}
	}
}

func Benchmark_MemStoreSubjectStateConsistencyOptimizationPerf(b *testing.B) {
	cfg := &StreamConfig{Name: "TEST", Subjects: []string{"foo.*"}, Storage: MemoryStorage, MaxMsgsPer: 1}
	ms, err := newMemStore(cfg)
	require_NoError(b, err)
	defer ms.Stop()

	// Do R rounds of storing N messages.
	// MaxMsgsPer=1, so every unique subject that's placed only exists in the stream once.
	// If R=2, N=3 that means we'd place foo.0, foo.1, foo.2 in the first round, and the second
	// round we'd place foo.2, foo.1, foo.0, etc. This is intentional so that without any
	// optimizations we'd need to scan either 1 in the optimal case or N in the worst case.
	// Which is way more expensive than always knowing what the sequences are and it being O(1).
	r := max(2, b.N)
	n := 40_000
	b.ResetTimer()
	for i := 0; i < r; i++ {
		for j := 0; j < n; j++ {
			d := j
			if i%2 == 0 {
				d = n - j - 1
			}
			subject := fmt.Sprintf("foo.%d", d)
			_, _, err = ms.StoreMsg(subject, nil, nil, 0)
			require_NoError(b, err)
		}
	}
}

// This benchmark populates a memstore and then measures
// the time it takes to load the entire store using
// LoadNextMsg repeatedly until the store returns ErrStoreEOF.
func Benchmark_MemStoreLoadNextMsgFiltered(b *testing.B) {
	cases := []struct {
		name             string
		msgs             int
		matchingMsgEvery int
		filter           string
		wc               bool
		matchingSubject  func(i int) string
		expectLinear     bool
	}{
		{
			name:             "wildcard_linear_scan",
			msgs:             10_000_000,
			matchingMsgEvery: 10_000,
			filter:           "foo.baz.*",
			wc:               true,
			matchingSubject: func(i int) string {
				return fmt.Sprintf("foo.baz.%d", i)
			},
			expectLinear: true,
		},
		{
			name:             "wildcard_bounded_scan",
			msgs:             10_000_000,
			matchingMsgEvery: 100_000,
			filter:           "foo.baz.*",
			wc:               true,
			matchingSubject: func(i int) string {
				return fmt.Sprintf("foo.baz.%d", i)
			},
			expectLinear: false,
		},
		{
			name:             "literal_bounded_scan",
			msgs:             10_000_000,
			matchingMsgEvery: 100_000,
			filter:           "foo.baz",
			wc:               false,
			matchingSubject: func(i int) string {
				return "foo.baz"
			},
			expectLinear: false,
		},
	}

	for _, tc := range cases {
		b.Run(tc.name, func(b *testing.B) {
			cfg := &StreamConfig{Name: "TEST", Subjects: []string{"foo.>"}, Storage: MemoryStorage}
			ms, err := newMemStore(cfg)
			require_NoError(b, err)
			defer ms.Stop()

			msg := []byte("ok")
			for i := range tc.msgs {
				subject := "foo.bar"
				if i%tc.matchingMsgEvery == 0 {
					subject = tc.matchingSubject(i)
				}
				_, _, err = ms.StoreMsg(subject, nil, msg, 0)
				require_NoError(b, err)
			}

			ms.mu.Lock()
			require_Equal(b, ms.shouldLinearScan(tc.filter, tc.wc, 1), tc.expectLinear)
			ms.mu.Unlock()

			var smv StoreMsg
			expectedMatches := uint64(tc.msgs / tc.matchingMsgEvery)

			b.ResetTimer()
			for b.Loop() {
				var start uint64
				var count uint64
				for {
					_, start, err = ms.LoadNextMsg(tc.filter, tc.wc, start, &smv)
					start++
					if err == ErrStoreEOF {
						require_Equal(b, count, expectedMatches)
						break
					}
					require_NoError(b, err)
					count++
				}
			}
		})
	}
}

func TestMemStoreMultiLastSeqsDoesNotReorderConfigSubjects(t *testing.T) {
	subjects := []string{"orders.*", "billing.*"}
	ms, err := newMemStore(&StreamConfig{Name: "zzz", Storage: MemoryStorage, Subjects: subjects})
	require_NoError(t, err)

	_, _, err = ms.StoreMsg("orders.1", nil, []byte("x"), 0)
	require_NoError(t, err)
	_, _, err = ms.StoreMsg("billing.1", nil, []byte("x"), 0)
	require_NoError(t, err)

	// Filter count == subject count drives the filterIsAll path.
	_, err = ms.MultiLastSeqs([]string{"orders.*", "billing.*"}, 0, 0)
	require_NoError(t, err)

	// The advertised config subjects must keep their original order.
	require_Equal(t, ms.cfg.Subjects[0], "orders.*")
	require_Equal(t, ms.cfg.Subjects[1], "billing.*")
}

func TestMemStoreSourcesAddedSourceKeepsExistingState(t *testing.T) {
	origin1 := &StreamSource{Name: "ORIGIN1"}
	origin2 := &StreamSource{Name: "ORIGIN2"}
	iName1, iName2 := origin1.composeIName(), origin2.composeIName()

	cfg := StreamConfig{
		Name:     "SOURCE",
		Subjects: []string{"foo"},
		Storage:  MemoryStorage,
		Sources:  []*StreamSource{origin1},
	}
	ms, err := newMemStore(&cfg)
	require_NoError(t, err)
	defer ms.Stop()

	for i := range 10 {
		hdr := genHeader(nil, JSStreamSource, fmt.Sprintf("ORIGIN1 %d > > foo", i+1))
		_, _, err = ms.StoreMsg("foo", hdr, nil, 0)
		require_NoError(t, err)
	}
	state := ms.SourcesState()
	require_Len(t, len(state), 1)
	require_Equal(t, state[iName1].Seq, 10)

	// Remove the newest message, a scan would now only be able to derive
	// ORIGIN1 up to sequence 9.
	removed, err := ms.RemoveMsg(10)
	require_NoError(t, err)
	require_True(t, removed)

	// Adding a source must only recover the sequence of the source that was just
	// added. Sources that are already tracked must keep their state, even if a
	// scan derives a lower sequence for them, since that would result in
	// the source consumer re-delivering messages it had already stored.
	ucfg := cfg
	ucfg.Sources = []*StreamSource{origin1, origin2}
	require_NoError(t, ms.UpdateConfig(&ucfg))

	state = ms.SourcesState()
	require_Len(t, len(state), 2)
	// ORIGIN1 must not have moved backward.
	require_Equal(t, state[iName1].Seq, 10)
	// ORIGIN2 is newly seeded and has nothing to recover.
	require_Equal(t, state[iName2].Seq, 0)
}

// Keep this fixture independent of helpers behind skip_js_tests.
func memStoreIntegrationClient(t *testing.T) (*nats.Conn, nats.JetStreamContext) {
	t.Helper()
	opts := DefaultOptions()
	opts.Cluster = ClusterOpts{}
	opts.ServerName = "memstore-integration-" + nuid.Next()
	opts.JetStream = true
	opts.StoreDir = t.TempDir()
	s := RunServer(opts)
	t.Cleanup(s.Shutdown)
	nc, err := nats.Connect(s.ClientURL(), nats.Timeout(2*time.Second))
	require_NoError(t, err)
	t.Cleanup(nc.Close)
	js, err := nc.JetStream(nats.MaxWait(2 * time.Second))
	require_NoError(t, err)
	return nc, js
}

func TestMemStoreIntegrationStorageRoundTrip(t *testing.T) {
	for _, first := range []uint64{1, 1000} {
		t.Run(strconv.FormatUint(first, 10), func(t *testing.T) {
			_, js := memStoreIntegrationClient(t)
			_, err := js.AddStream(&nats.StreamConfig{
				Name: "MEM", Subjects: []string{"foo"}, Storage: nats.MemoryStorage, FirstSeq: first,
			})
			require_NoError(t, err)
			payload := []byte("Hello World")
			msg := &nats.Msg{Subject: "foo", Header: nats.Header{"Trace": {"memstore"}}, Data: payload}
			before := time.Now()
			var previous time.Time
			for i := range 10 {
				ack, err := js.PublishMsg(msg)
				require_NoError(t, err)
				require_Equal(t, ack.Sequence, first+uint64(i))
				stored, err := js.GetMsg("MEM", ack.Sequence)
				require_NoError(t, err)
				require_Equal(t, stored.Subject, "foo")
				require_True(t, bytes.Equal(stored.Data, payload))
				require_True(t, reflect.DeepEqual(stored.Header, msg.Header))
				require_True(t, stored.Time.After(previous))
				require_False(t, stored.Time.Before(before))
				require_False(t, stored.Time.After(time.Now()))
				previous = stored.Time
			}
			info, err := js.StreamInfo("MEM")
			require_NoError(t, err)
			require_Equal(t, info.State.Msgs, 10)
			require_Equal(t, info.State.FirstSeq, first)
			require_Equal(t, info.State.LastSeq, first+9)
			// Wire headers plus subject/payload and the store's documented 16-byte overhead.
			expectedBytes := uint64(10 * (len("foo") + len(payload) + len("NATS/1.0\r\nTrace: memstore\r\n\r\n") + 16))
			require_Equal(t, info.State.Bytes, expectedBytes)
			require_NoError(t, js.SecureDeleteMsg("MEM", first))
			_, err = js.GetMsg("MEM", first)
			require_True(t, errors.Is(err, nats.ErrMsgNotFound))
		})
	}
}

func TestMemStoreIntegrationLimits(t *testing.T) {
	for _, test := range []struct {
		name     string
		cfg      nats.StreamConfig
		subject  string
		payload  []byte
		attempts int
		accepted int
		messages uint64
		first    uint64
		bytes    uint64
	}{
		{name: "messages", cfg: nats.StreamConfig{MaxMsgs: 10}, subject: "foo", payload: []byte("abc"), attempts: 11, accepted: 11, messages: 10, first: 2, bytes: 220},
		{name: "bytes", cfg: nats.StreamConfig{MaxBytes: 531 * 1024}, subject: "foo", payload: make([]byte, 512), attempts: 1034, accepted: 1034, messages: 1024, first: 11, bytes: 531 * 1024},
		{name: "discard-new", cfg: nats.StreamConfig{MaxBytes: 100, Discard: nats.DiscardNew}, subject: "tiny", payload: make([]byte, 7), attempts: 10, accepted: 3, messages: 3, first: 1, bytes: 81},
	} {
		t.Run(test.name, func(t *testing.T) {
			_, js := memStoreIntegrationClient(t)
			test.cfg.Name, test.cfg.Storage, test.cfg.Subjects = "MEM", nats.MemoryStorage, []string{test.subject}
			_, err := js.AddStream(&test.cfg)
			require_NoError(t, err)
			for i := range test.attempts {
				ack, err := js.Publish(test.subject, test.payload)
				if i < test.accepted {
					require_NoError(t, err)
					require_Equal(t, ack.Sequence, uint64(i+1))
				} else {
					apiErr, ok := errors.AsType[*nats.APIError](err)
					require_True(t, ok)
					require_Equal(t, apiErr.ErrorCode, 10077)
					require_Equal(t, apiErr.Description, "maximum bytes exceeded")
				}
			}
			info, err := js.StreamInfo("MEM")
			require_NoError(t, err)
			require_Equal(t, info.State.Msgs, test.messages)
			require_Equal(t, info.State.FirstSeq, test.first)
			require_Equal(t, info.State.LastSeq, uint64(test.accepted))
			require_Equal(t, info.State.Bytes, test.bytes)
			if test.first > 1 {
				_, err = js.GetMsg("MEM", 1)
				require_True(t, errors.Is(err, nats.ErrMsgNotFound))
			}
		})
	}
}

func TestMemStoreIntegrationPurgeAndDeletes(t *testing.T) {
	for _, mode := range []string{"purge", "compact", "holes", "purge-before-hole", "delete-all", "subject"} {
		t.Run(mode, func(t *testing.T) {
			_, js := memStoreIntegrationClient(t)
			_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: []string{"foo", "bar"}, Storage: nats.MemoryStorage})
			require_NoError(t, err)
			count := 10
			if mode == "subject" {
				count = 100
			}
			for range count {
				_, err := js.Publish("foo", []byte("abc"))
				require_NoError(t, err)
			}
			state := func() nats.StreamState {
				t.Helper()
				info, err := js.StreamInfo("MEM", &nats.StreamInfoRequest{DeletedDetails: true, SubjectsFilter: ">"})
				require_NoError(t, err)
				return info.State
			}
			checkEmpty := func(first uint64) {
				t.Helper()
				ss := state()
				require_Equal(t, ss.Msgs, 0)
				require_Equal(t, ss.Bytes, 0)
				require_Equal(t, ss.FirstSeq, first)
				require_Equal(t, ss.LastSeq, first-1)
				require_Equal(t, ss.NumDeleted, 0)
				require_Equal(t, len(ss.Deleted), 0)
				require_Equal(t, ss.NumSubjects, 0)
			}
			switch mode {
			case "purge":
				for seq := uint64(2); seq <= 9; seq++ {
					require_NoError(t, js.DeleteMsg("MEM", seq))
				}
				require_Equal(t, state().NumDeleted, 8)
				require_NoError(t, js.PurgeStream("MEM"))
				checkEmpty(11)
			case "compact":
				require_NoError(t, js.PurgeStream("MEM", &nats.StreamPurgeRequest{Sequence: 6}))
				ss := state()
				require_Equal(t, ss.Msgs, 5)
				require_Equal(t, ss.FirstSeq, 6)
				require_Equal(t, ss.LastSeq, 10)
				require_NoError(t, js.PurgeStream("MEM", &nats.StreamPurgeRequest{Sequence: 100}))
				checkEmpty(100)
			case "holes":
				for _, seq := range []uint64{2, 4, 6, 8} {
					require_NoError(t, js.DeleteMsg("MEM", seq))
				}
				require_True(t, slices.Equal(state().Deleted, []uint64{2, 4, 6, 8}))
				for _, seq := range []uint64{1, 3} {
					require_NoError(t, js.DeleteMsg("MEM", seq))
				}
				ss := state()
				require_Equal(t, ss.FirstSeq, 5)
				require_Equal(t, ss.NumDeleted, 2)
				require_True(t, slices.Equal(ss.Deleted, []uint64{6, 8}))
				require_NoError(t, js.PurgeStream("MEM"))
				checkEmpty(11)
			case "purge-before-hole":
				require_NoError(t, js.DeleteMsg("MEM", 2))
				require_NoError(t, js.DeleteMsg("MEM", 9))
				require_NoError(t, js.PurgeStream("MEM", &nats.StreamPurgeRequest{Sequence: 9}))
				ss := state()
				require_Equal(t, ss.Msgs, 1)
				require_Equal(t, ss.FirstSeq, 10)
				require_Equal(t, ss.LastSeq, 10)
				require_Equal(t, ss.NumDeleted, 0)
				stored, err := js.GetMsg("MEM", 10)
				require_NoError(t, err)
				require_Equal(t, string(stored.Data), "abc")
			case "delete-all":
				for seq := uint64(1); seq <= 10; seq++ {
					require_NoError(t, js.DeleteMsg("MEM", seq))
				}
				checkEmpty(11)
			case "subject":
				_, err := js.Publish("bar", []byte("keep"))
				require_NoError(t, err)
				require_NoError(t, js.PurgeStream("MEM", &nats.StreamPurgeRequest{Subject: "foo"}))
				ss := state()
				require_Equal(t, ss.Msgs, 1)
				require_Equal(t, ss.FirstSeq, 101)
				require_Equal(t, ss.NumSubjects, 1)
				require_Equal(t, ss.Subjects["bar"], 1)
				require_Equal(t, ss.Subjects["foo"], 0)
			}
		})
	}
}

func TestMemStoreIntegrationSubjectState(t *testing.T) {
	t.Run("totals", func(t *testing.T) {
		_, js := memStoreIntegrationClient(t)
		_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: []string{"foo.*", "bar.*"}, Storage: nats.MemoryStorage})
		require_NoError(t, err)
		totals := make(map[string]uint64)
		rng := rand.New(rand.NewPCG(1, 2))
		for range 10000 {
			prefix := "foo"
			if rng.IntN(2) == 1 {
				prefix = "bar"
			}
			subject := fmt.Sprintf("%s.%d", prefix, rng.IntN(100))
			_, err := js.Publish(subject, nil)
			require_NoError(t, err)
			totals[subject]++
		}
		for _, filter := range []string{"foo.*", "bar.*", "*.*"} {
			expected := make(map[string]uint64)
			for subject, count := range totals {
				if filter == "*.*" || subject[:3] == filter[:3] {
					expected[subject] = count
				}
			}
			info, err := js.StreamInfo("MEM", &nats.StreamInfoRequest{SubjectsFilter: filter})
			require_NoError(t, err)
			require_True(t, reflect.DeepEqual(info.State.Subjects, expected))
			require_Equal(t, info.State.NumSubjects, uint64(len(totals)))
		}
	})
	t.Run("update-limit", func(t *testing.T) {
		_, js := memStoreIntegrationClient(t)
		cfg := &nats.StreamConfig{Name: "MEM", Subjects: []string{"foo"}, Storage: nats.MemoryStorage, MaxMsgsPerSubject: 10}
		_, err := js.AddStream(cfg)
		require_NoError(t, err)
		cfg.MaxMsgsPerSubject = 50
		_, err = js.UpdateStream(cfg)
		require_NoError(t, err)
		for range 22 {
			_, err := js.Publish("foo", nil)
			require_NoError(t, err)
		}
		info, err := js.StreamInfo("MEM", &nats.StreamInfoRequest{SubjectsFilter: "foo"})
		require_NoError(t, err)
		require_Equal(t, info.State.Subjects["foo"], 22)
		cfg.MaxMsgsPerSubject = 10
		_, err = js.UpdateStream(cfg)
		require_NoError(t, err)
		info, err = js.StreamInfo("MEM", &nats.StreamInfoRequest{SubjectsFilter: "foo"})
		require_NoError(t, err)
		require_Equal(t, info.State.Subjects["foo"], 10)
		require_Equal(t, info.State.FirstSeq, 13)
	})
	t.Run("compact-subjects", func(t *testing.T) {
		_, js := memStoreIntegrationClient(t)
		_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: []string{"foo.*"}, Storage: nats.MemoryStorage})
		require_NoError(t, err)
		for i := range 1000 {
			_, err := js.Publish(fmt.Sprintf("foo.%d", i), nil)
			require_NoError(t, err)
		}
		require_NoError(t, js.PurgeStream("MEM", &nats.StreamPurgeRequest{Sequence: 501}))
		info, err := js.StreamInfo("MEM", &nats.StreamInfoRequest{SubjectsFilter: ">"})
		require_NoError(t, err)
		require_Equal(t, info.State.Msgs, 500)
		require_Equal(t, info.State.FirstSeq, 501)
		require_Equal(t, info.State.NumSubjects, 500)
		for i := range 1000 {
			expected := uint64(0)
			if i >= 500 {
				expected = 1
			}
			require_Equal(t, info.State.Subjects[fmt.Sprintf("foo.%d", i)], expected)
		}
	})
}

func TestMemStoreIntegrationDeleteStress(t *testing.T) {
	_, js := memStoreIntegrationClient(t)
	_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: []string{"foo"}, Storage: nats.MemoryStorage})
	require_NoError(t, err)
	for range 10000 {
		_, err := js.PublishAsync("foo", []byte("abc"))
		require_NoError(t, err)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(30 * time.Second):
		t.Fatal("10000 publications did not complete")
	}
	deleted := make([]uint64, 5000)
	rng := rand.New(rand.NewPCG(3, 4))
	for i, offset := range rng.Perm(9998)[:5000] {
		deleted[i] = uint64(offset + 2)
		require_NoError(t, js.DeleteMsg("MEM", deleted[i]))
	}
	slices.Sort(deleted)
	info, err := js.StreamInfo("MEM", &nats.StreamInfoRequest{DeletedDetails: true})
	require_NoError(t, err)
	require_Equal(t, info.State.Msgs, 5000)
	require_Equal(t, info.State.FirstSeq, 1)
	require_Equal(t, info.State.LastSeq, 10000)
	require_Equal(t, info.State.NumDeleted, 5000)
	require_True(t, slices.Equal(info.State.Deleted, deleted))
	for _, seq := range []uint64{1, 10000, deleted[0], deleted[len(deleted)-1]} {
		stored, err := js.GetMsg("MEM", seq)
		if slices.Contains(deleted, seq) {
			require_True(t, errors.Is(err, nats.ErrMsgNotFound))
		} else {
			require_NoError(t, err)
			require_Equal(t, string(stored.Data), "abc")
		}
	}
}

func TestMemStoreIntegrationExpiry(t *testing.T) {
	for _, perMessage := range []bool{false, true} {
		t.Run(fmt.Sprintf("per-message=%t", perMessage), func(t *testing.T) {
			_, js := memStoreIntegrationClient(t)
			cfg := &nats.StreamConfig{Name: "MEM", Subjects: []string{"foo"}, Storage: nats.MemoryStorage}
			count, batches := 100, 2
			if perMessage {
				cfg.AllowMsgTTL = true
				count, batches = 10, 1
			} else {
				cfg.MaxAge = 2 * time.Second
			}
			_, err := js.AddStream(cfg)
			require_NoError(t, err)
			for batch := range batches {
				for range count {
					msg := nats.NewMsg("foo")
					msg.Data = []byte("expires")
					if perMessage {
						msg.Header.Set("Nats-TTL", "1s")
					}
					_, err := js.PublishMsg(msg)
					require_NoError(t, err)
				}
				info, err := js.StreamInfo("MEM")
				require_NoError(t, err)
				require_Equal(t, info.State.Msgs, uint64(count))
				last := uint64((batch + 1) * count)
				checkFor(t, 5*time.Second, 20*time.Millisecond, func() error {
					info, err := js.StreamInfo("MEM")
					if err != nil {
						return err
					}
					ss := info.State
					if ss.Msgs != 0 || ss.Bytes != 0 || ss.FirstSeq != last+1 || ss.LastSeq != last {
						return fmt.Errorf("waiting for expiry: %+v", ss)
					}
					return nil
				})
			}
		})
	}
}

func TestMemStoreIntegrationDeleteMarker(t *testing.T) {
	_, js := memStoreIntegrationClient(t)
	_, err := js.AddStream(&nats.StreamConfig{
		Name: "MEM", Subjects: []string{"foo"}, Storage: nats.MemoryStorage,
		MaxAge: time.Second, AllowMsgTTL: true, SubjectDeleteMarkerTTL: time.Second,
	})
	require_NoError(t, err)
	sub, err := js.SubscribeSync("foo", nats.ManualAck())
	require_NoError(t, err)
	for range 3 {
		_, err := js.Publish("foo", []byte("expires"))
		require_NoError(t, err)
	}
	for range 3 {
		msg, err := sub.NextMsg(time.Second)
		require_NoError(t, err)
		require_NoError(t, msg.AckSync())
	}
	marker, err := sub.NextMsg(5 * time.Second)
	require_NoError(t, err)
	require_Equal(t, marker.Subject, "foo")
	require_Equal(t, marker.Header.Get("Nats-Marker-Reason"), "MaxAge")
	require_Equal(t, marker.Header.Get("Nats-TTL"), "1s")
	require_NoError(t, marker.AckSync())
}

func memStoreIntegrationMultiLast(t *testing.T, nc *nats.Conn, req JSApiMsgGetRequest) []*nats.Msg {
	t.Helper()
	body, err := json.Marshal(req)
	require_NoError(t, err)
	reply := nats.NewInbox()
	sub, err := nc.SubscribeSync(reply)
	require_NoError(t, err)
	defer sub.Unsubscribe()
	require_NoError(t, nc.PublishRequest("$JS.API.DIRECT.GET.MEM", reply, body))
	var messages []*nats.Msg
	for {
		msg, err := sub.NextMsg(2 * time.Second)
		require_NoError(t, err)
		switch status := msg.Header.Get("Status"); status {
		case "":
			require_Equal(t, msg.Header.Get("Nats-Stream"), "MEM")
			messages = append(messages, msg)
		case "204":
			require_Equal(t, msg.Header.Get("Description"), "EOB")
			require_Equal(t, msg.Header.Get("Nats-Num-Pending"), "0")
			for i, stored := range messages {
				require_Equal(t, stored.Header.Get("Nats-Num-Pending"), strconv.Itoa(len(messages)-i-1))
				last := "0"
				if i > 0 {
					last = messages[i-1].Header.Get("Nats-Sequence")
				}
				require_Equal(t, stored.Header.Get("Nats-Last-Sequence"), last)
			}
			if len(messages) > 0 {
				require_Equal(t, msg.Header.Get("Nats-Last-Sequence"), messages[len(messages)-1].Header.Get("Nats-Sequence"))
			}
			return messages
		case "404":
			require_Equal(t, msg.Header.Get("Description"), "No Results")
			require_Equal(t, len(messages), 0)
			return nil
		default:
			t.Fatalf("unexpected direct-get status %s: %s", status, msg.Header.Get("Description"))
		}
	}
}

func TestMemStoreIntegrationMultiLast(t *testing.T) {
	t.Run("filters-and-ceilings", func(t *testing.T) {
		nc, js := memStoreIntegrationClient(t)
		_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: []string{"foo.*", "bar.*"}, Storage: nats.MemoryStorage, AllowDirect: true})
		require_NoError(t, err)
		for _, prefix := range []string{"foo", "bar"} {
			for range 33 {
				for _, suffix := range []string{"foo", "bar", "baz"} {
					_, err := js.Publish(prefix+"."+suffix, []byte("abc"))
					require_NoError(t, err)
				}
			}
		}
		for _, test := range []struct {
			filters  []string
			ceiling  uint64
			expected []uint64
		}{
			{[]string{"foo.*"}, 3, []uint64{1, 2, 3}},
			{[]string{"foo.*"}, 0, []uint64{97, 98, 99}},
			{[]string{"bar.*"}, 0, []uint64{196, 197, 198}},
			{[]string{"bar.*"}, 99, nil},
			{[]string{"foo.foo", "foo.bar", "foo.baz"}, 3, []uint64{1, 2, 3}},
			{[]string{"foo.foo", "foo.bar", "foo.baz"}, 0, []uint64{97, 98, 99}},
			{[]string{"bar.foo", "bar.bar", "bar.baz"}, 0, []uint64{196, 197, 198}},
			{[]string{"bar.foo", "bar.bar", "bar.baz"}, 99, nil},
			{[]string{"foo.foo"}, 3, []uint64{1}},
			{[]string{"foo.*", "foo.bar"}, 3, []uint64{1, 2, 3}},
			{[]string{"bar.>", "bar.bar", "bar.baz"}, 0, []uint64{196, 197, 198}},
			{[]string{">"}, 0, []uint64{97, 98, 99, 196, 197, 198}},
			{[]string{">"}, 99, []uint64{97, 98, 99}},
		} {
			messages := memStoreIntegrationMultiLast(t, nc, JSApiMsgGetRequest{MultiLastFor: test.filters, UpToSeq: test.ceiling})
			require_Equal(t, len(messages), len(test.expected))
			for i, msg := range messages {
				require_Equal(t, msg.Header.Get("Nats-Sequence"), strconv.FormatUint(test.expected[i], 10))
				require_Equal(t, string(msg.Data), "abc")
				expectedSubject := []string{"foo.foo", "foo.bar", "foo.baz", "bar.foo", "bar.bar", "bar.baz"}[(test.expected[i]-1)/99*3+(test.expected[i]-1)%3]
				require_Equal(t, msg.Header.Get("Nats-Subject"), expectedSubject)
			}
		}
	})
	t.Run("deleted-latest", func(t *testing.T) {
		nc, js := memStoreIntegrationClient(t)
		_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: []string{"foo", "bar", "baz"}, Storage: nats.MemoryStorage, AllowDirect: true})
		require_NoError(t, err)
		// Sequence4 uses valid baz in place of the original fixture's invalid leading space.
		for _, subject := range []string{"foo", "bar", "foo", "baz", "foo", "foo", "bar", "foo", "bar", "baz"} {
			_, err := js.Publish(subject, nil)
			require_NoError(t, err)
		}
		for _, expected := range [][]uint64{{8, 9}, {6, 9}} {
			messages := memStoreIntegrationMultiLast(t, nc, JSApiMsgGetRequest{MultiLastFor: []string{"foo", "bar"}})
			require_Equal(t, len(messages), 2)
			for i, msg := range messages {
				require_Equal(t, msg.Header.Get("Nats-Sequence"), strconv.FormatUint(expected[i], 10))
			}
			if expected[0] == 8 {
				require_NoError(t, js.DeleteMsg("MEM", 8))
			}
		}
	})
	t.Run("config-subject-order", func(t *testing.T) {
		nc, js := memStoreIntegrationClient(t)
		order := []string{"orders.*", "billing.*"}
		_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: order, Storage: nats.MemoryStorage, AllowDirect: true})
		require_NoError(t, err)
		for _, subject := range []string{"orders.a", "billing.a"} {
			_, err := js.Publish(subject, nil)
			require_NoError(t, err)
		}
		before, err := js.StreamInfo("MEM")
		require_NoError(t, err)
		require_Equal(t, len(memStoreIntegrationMultiLast(t, nc, JSApiMsgGetRequest{MultiLastFor: []string{">"}})), 2)
		after, err := js.StreamInfo("MEM")
		require_NoError(t, err)
		require_True(t, slices.Equal(before.Config.Subjects, order))
		require_True(t, slices.Equal(after.Config.Subjects, order))
	})
}

func TestMemStoreIntegrationMultiLastLimit(t *testing.T) {
	nc, js := memStoreIntegrationClient(t)
	_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: []string{"foo.*"}, Storage: nats.MemoryStorage, AllowDirect: true})
	require_NoError(t, err)
	for i := range 1025 {
		_, err := js.PublishAsync(fmt.Sprintf("foo.%d", i), []byte("abc"))
		require_NoError(t, err)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(10 * time.Second):
		t.Fatal("1025 publications did not complete")
	}
	info, err := js.StreamInfo("MEM")
	require_NoError(t, err)
	require_Equal(t, info.State.Msgs, 1025)
	body, err := json.Marshal(JSApiMsgGetRequest{MultiLastFor: []string{"foo.*"}})
	require_NoError(t, err)
	msg, err := nc.Request("$JS.API.DIRECT.GET.MEM", body, time.Second)
	require_NoError(t, err)
	require_Equal(t, len(msg.Data), 0)
	require_Equal(t, msg.Header.Get("Status"), "413")
	require_Equal(t, msg.Header.Get("Description"), "Too Many Results")
}

func TestMemStoreIntegrationFilteredDelivery(t *testing.T) {
	_, js := memStoreIntegrationClient(t)
	_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: []string{"foo.>"}, Storage: nats.MemoryStorage})
	require_NoError(t, err)
	var subjects []string
	for _, group := range []struct {
		subject string
		count   int
	}{{"foo.bar.a", 1}, {"foo.baz.bar", 10}, {"foo.bar.b", 1}, {"foo.baz.bar", 10}, {"foo.baz.bar.no.match", 10}} {
		for range group.count {
			subjects = append(subjects, group.subject)
			_, err := js.Publish(group.subject, []byte(group.subject))
			require_NoError(t, err)
		}
	}
	for _, filter := range []string{"foo.bar.*", "foo.baz.*", "foo.nope.*", "foo.>", "foo.bar.a", "foo.baz.bar", "foo.missing"} {
		for _, start := range []uint64{1, 2, 11, 12, 22, 23, 33} {
			t.Run(fmt.Sprintf("%s/%d", filter, start), func(t *testing.T) {
				var expected []uint64
				for i, subject := range subjects {
					seq := uint64(i + 1)
					matches := subject == filter || filter == "foo.>" ||
						(filter == "foo.bar.*" && (subject == "foo.bar.a" || subject == "foo.bar.b")) ||
						(filter == "foo.baz.*" && subject == "foo.baz.bar")
					if seq >= start && matches {
						expected = append(expected, seq)
					}
				}
				name := "C" + nuid.Next()
				info, err := js.AddConsumer("MEM", &nats.ConsumerConfig{
					Durable: name, FilterSubject: filter, AckPolicy: nats.AckExplicitPolicy,
					DeliverPolicy: nats.DeliverByStartSequencePolicy, OptStartSeq: start,
				})
				require_NoError(t, err)
				defer js.DeleteConsumer("MEM", name)
				require_Equal(t, info.NumPending, uint64(len(expected)))
				if len(expected) == 0 {
					return
				}
				sub, err := js.PullSubscribe(filter, name, nats.Bind("MEM", name))
				require_NoError(t, err)
				defer sub.Unsubscribe()
				messages, err := sub.Fetch(len(expected), nats.MaxWait(time.Second))
				require_NoError(t, err)
				require_Equal(t, len(messages), len(expected))
				for i, msg := range messages {
					meta, err := msg.Metadata()
					require_NoError(t, err)
					require_Equal(t, meta.Sequence.Stream, expected[i])
					require_Equal(t, msg.Subject, subjects[expected[i]-1])
					require_Equal(t, string(msg.Data), msg.Subject)
					require_NoError(t, msg.AckSync())
				}
				info, err = js.ConsumerInfo("MEM", name)
				require_NoError(t, err)
				require_Equal(t, info.NumPending, 0)
				require_Equal(t, info.NumAckPending, 0)
				require_Equal(t, info.AckFloor.Stream, expected[len(expected)-1])
			})
		}
	}
}

func TestMemStoreIntegrationPendingBug(t *testing.T) {
	_, js := memStoreIntegrationClient(t)
	_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: []string{"foo.*"}, Storage: nats.MemoryStorage})
	require_NoError(t, err)
	for _, subject := range []string{"foo.foo", "foo.bar", "foo.baz", "foo.zzz"} {
		for _, fixture := range []string{"foo.aaa", subject, subject} {
			_, err := js.Publish(fixture, nil)
			require_NoError(t, err)
		}
	}
	info, err := js.AddConsumer("MEM", &nats.ConsumerConfig{
		Durable: "PENDING", FilterSubject: "foo.*", AckPolicy: nats.AckExplicitPolicy,
		DeliverPolicy: nats.DeliverByStartSequencePolicy, OptStartSeq: 4,
	})
	require_NoError(t, err)
	require_Equal(t, info.NumPending, 9)
	sub, err := js.PullSubscribe("foo.*", "PENDING", nats.Bind("MEM", "PENDING"))
	require_NoError(t, err)
	messages, err := sub.Fetch(9, nats.MaxWait(time.Second))
	require_NoError(t, err)
	require_Equal(t, len(messages), 9)
	for i, msg := range messages {
		meta, err := msg.Metadata()
		require_NoError(t, err)
		require_Equal(t, meta.Sequence.Stream, uint64(i+4))
		require_NoError(t, msg.AckSync())
	}
}

func TestMemStoreIntegrationTimeLookup(t *testing.T) {
	_, js := memStoreIntegrationClient(t)
	_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: []string{"foo"}, Storage: nats.MemoryStorage})
	require_NoError(t, err)
	for range 1000 {
		_, err := js.Publish("foo", nil)
		require_NoError(t, err)
	}
	before, err := js.GetMsg("MEM", 500)
	require_NoError(t, err)
	after, err := js.GetMsg("MEM", 501)
	require_NoError(t, err)
	require_True(t, after.Time.After(before.Time))
	start := before.Time.Add(after.Time.Sub(before.Time)/2 + 1)
	for seq := uint64(900); seq <= 1000; seq++ {
		require_NoError(t, js.DeleteMsg("MEM", seq))
	}
	info, err := js.AddConsumer("MEM", &nats.ConsumerConfig{
		Durable: "BYTIME", AckPolicy: nats.AckExplicitPolicy,
		DeliverPolicy: nats.DeliverByStartTimePolicy, OptStartTime: &start,
	})
	require_NoError(t, err)
	require_Equal(t, info.NumPending, 399)
	sub, err := js.PullSubscribe("", "BYTIME", nats.Bind("MEM", "BYTIME"))
	require_NoError(t, err)
	messages, err := sub.Fetch(1, nats.MaxWait(time.Second))
	require_NoError(t, err)
	require_Equal(t, len(messages), 1)
	meta, err := messages[0].Metadata()
	require_NoError(t, err)
	require_Equal(t, meta.Sequence.Stream, 501)
	require_NoError(t, messages[0].AckSync())
}

func TestMemStoreIntegrationSchedules(t *testing.T) {
	for _, pattern := range []string{"once", "every"} {
		t.Run(pattern, func(t *testing.T) {
			nc, js := memStoreIntegrationClient(t)
			body, err := json.Marshal(StreamConfig{
				Name: "MEM", Subjects: []string{"foo.*"}, Storage: MemoryStorage, AllowMsgSchedules: true,
			})
			require_NoError(t, err)
			response, err := nc.Request("$JS.API.STREAM.CREATE.MEM", body, time.Second)
			require_NoError(t, err)
			var created JSApiStreamCreateResponse
			require_NoError(t, json.Unmarshal(response.Data, &created))
			require_True(t, created.Error == nil)
			sub, err := js.SubscribeSync("foo.target", nats.BindStream("MEM"), nats.ManualAck())
			require_NoError(t, err)
			require_NoError(t, nc.FlushTimeout(time.Second))
			msg := nats.NewMsg("foo.schedule")
			msg.Data = []byte("scheduled")
			msg.Header.Set("Nats-Schedule-Target", "foo.target")
			if pattern == "once" {
				msg.Header.Set("Nats-Schedule", "@at "+time.Now().Add(time.Second).Format(time.RFC3339Nano))
			} else {
				msg.Header.Set("Nats-Schedule", "@every 1500ms")
			}
			ack, err := js.PublishMsg(msg)
			require_NoError(t, err)
			stored, err := js.GetMsg("MEM", ack.Sequence)
			require_NoError(t, err)
			delivered, err := sub.NextMsg(5 * time.Second)
			require_NoError(t, err)
			require_Equal(t, delivered.Subject, "foo.target")
			require_Equal(t, string(delivered.Data), "scheduled")
			require_Equal(t, delivered.Header.Get("Nats-Scheduler"), "foo.schedule")
			if pattern == "once" {
				require_Equal(t, delivered.Header.Get("Nats-Schedule-Next"), "purge")
			} else {
				next, err := time.Parse(time.RFC3339Nano, delivered.Header.Get("Nats-Schedule-Next"))
				require_NoError(t, err)
				const interval = 1500 * time.Millisecond
				first := stored.Time.UTC().Round(time.Second).Add(interval)
				expected := first.Round(time.Second).Add(interval)
				require_Equal(t, next.UnixNano(), expected.UnixNano())
			}
		})
	}
}

func TestMemStoreIntegrationSources(t *testing.T) {
	_, js := memStoreIntegrationClient(t)
	for _, name := range []string{"ORIGIN1", "ORIGIN2"} {
		_, err := js.AddStream(&nats.StreamConfig{Name: name, Subjects: []string{name}, Storage: nats.MemoryStorage})
		require_NoError(t, err)
	}
	for i := range 10 {
		_, err := js.Publish("ORIGIN1", []byte(fmt.Sprintf("origin1-%d", i+1)))
		require_NoError(t, err)
	}
	cfg := &nats.StreamConfig{Name: "MEM", Storage: nats.MemoryStorage, Sources: []*nats.StreamSource{{Name: "ORIGIN1"}}}
	_, err := js.AddStream(cfg)
	require_NoError(t, err)
	waitState := func(messages, last uint64) {
		t.Helper()
		checkFor(t, 5*time.Second, 10*time.Millisecond, func() error {
			info, err := js.StreamInfo("MEM")
			if err != nil {
				return err
			}
			if info.State.Msgs != messages || info.State.LastSeq != last {
				return fmt.Errorf("source state: %+v", info.State)
			}
			return nil
		})
	}
	waitState(10, 10)
	require_NoError(t, js.DeleteMsg("MEM", 10))
	cfg.Sources = append(cfg.Sources, &nats.StreamSource{Name: "ORIGIN2"})
	_, err = js.UpdateStream(cfg)
	require_NoError(t, err)
	waitState(9, 10)
	_, err = js.Publish("ORIGIN1", []byte("origin1-11"))
	require_NoError(t, err)
	_, err = js.Publish("ORIGIN2", []byte("origin2-1"))
	require_NoError(t, err)
	waitState(11, 12)
	counts := make(map[string]int)
	for seq := uint64(1); seq <= 12; seq++ {
		msg, err := js.GetMsg("MEM", seq)
		if seq == 10 {
			require_True(t, errors.Is(err, nats.ErrMsgNotFound))
			continue
		}
		require_NoError(t, err)
		counts[string(msg.Data)]++
	}
	for i := range 11 {
		expected := 1
		if i == 9 {
			expected = 0
		}
		require_Equal(t, counts[fmt.Sprintf("origin1-%d", i+1)], expected)
	}
	require_Equal(t, counts["origin2-1"], 1)
	require_Equal(t, len(counts), 11)
}

func TestMemStoreIntegrationMirrorGaps(t *testing.T) {
	_, js := memStoreIntegrationClient(t)
	_, err := js.AddStream(&nats.StreamConfig{Name: "ORIGIN", Subjects: []string{"foo"}, Storage: nats.MemoryStorage})
	require_NoError(t, err)
	for i := range 11 {
		_, err := js.Publish("foo", []byte(strconv.Itoa(i+1)))
		require_NoError(t, err)
	}
	for seq := uint64(2); seq <= 11; seq++ {
		require_NoError(t, js.DeleteMsg("ORIGIN", seq))
	}
	_, err = js.AddStream(&nats.StreamConfig{Name: "MEM", Storage: nats.MemoryStorage, Mirror: &nats.StreamSource{Name: "ORIGIN"}})
	require_NoError(t, err)
	checkFor(t, 5*time.Second, 10*time.Millisecond, func() error {
		info, err := js.StreamInfo("MEM")
		if err != nil {
			return err
		}
		if info.State.Msgs != 1 || info.State.FirstSeq != 1 {
			return fmt.Errorf("mirror waiting for first message: %+v", info.State)
		}
		return nil
	})
	ack, err := js.Publish("foo", []byte("12"))
	require_NoError(t, err)
	require_Equal(t, ack.Sequence, 12)
	checkFor(t, 5*time.Second, 10*time.Millisecond, func() error {
		info, err := js.StreamInfo("MEM", &nats.StreamInfoRequest{DeletedDetails: true})
		if err != nil {
			return err
		}
		ss := info.State
		if ss.Msgs != 2 || ss.FirstSeq != 1 || ss.LastSeq != 12 || ss.NumDeleted != 10 {
			return fmt.Errorf("mirror gaps not synchronized: %+v", ss)
		}
		if !slices.Equal(ss.Deleted, []uint64{2, 3, 4, 5, 6, 7, 8, 9, 10, 11}) {
			return fmt.Errorf("mirror deleted sequences: %v", ss.Deleted)
		}
		return nil
	})
	for _, seq := range []uint64{1, 12} {
		stored, err := js.GetMsg("MEM", seq)
		require_NoError(t, err)
		require_Equal(t, string(stored.Data), strconv.FormatUint(seq, 10))
	}
	_, err = js.GetMsg("MEM", 5)
	require_True(t, errors.Is(err, nats.ErrMsgNotFound))
}

func TestMemStoreIntegrationPending(t *testing.T) {
	nc, js := memStoreIntegrationClient(t)
	_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: []string{"*.*.*.*"}, Storage: nats.MemoryStorage, AllowDirect: true})
	require_NoError(t, err)
	tokens := []string{"foo", "bar", "baz"}
	rng := rand.New(rand.NewPCG(5, 6))
	fixture := make([][4]string, 50000)
	for i := range fixture {
		for j := range fixture[i] {
			fixture[i][j] = tokens[rng.IntN(len(tokens))]
		}
		x := fixture[i]
		_, err := js.PublishAsync(fmt.Sprintf("%s.%s.%s.%s", x[0], x[1], x[2], x[3]), []byte("Hello World"))
		require_NoError(t, err)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(30 * time.Second):
		t.Fatal("50000 publications did not complete")
	}
	stream, err := js.StreamInfo("MEM")
	require_NoError(t, err)
	require_Equal(t, stream.State.Msgs, 50000)
	require_Equal(t, stream.State.LastSeq, 50000)
	for _, filter := range []string{"foo.>", "*.bar.>", "foo.bar.*.baz", "*.bar.>", "*.foo.bar.*", "foo.foo.bar.baz"} {
		for _, start := range []uint64{0, 1, 2, 200, 444, 555, 2222, 8888, 12345, 28222, 33456, 44400, 49999} {
			t.Run(fmt.Sprintf("%s/%d", filter, start), func(t *testing.T) {
				var expected uint64
				latest := make(map[[4]string]uint64)
				for i, subject := range fixture {
					seq := uint64(i + 1)
					if seq < max(start, 1) {
						continue
					}
					var matches bool
					switch filter {
					case "foo.>":
						matches = subject[0] == "foo"
					case "*.bar.>":
						matches = subject[1] == "bar"
					case "foo.bar.*.baz":
						matches = subject[0] == "foo" && subject[1] == "bar" && subject[3] == "baz"
					case "*.foo.bar.*":
						matches = subject[1] == "foo" && subject[2] == "bar"
					case "foo.foo.bar.baz":
						matches = subject == [4]string{"foo", "foo", "bar", "baz"}
					}
					if matches {
						expected++
						latest[subject] = seq
					}
				}
				consumer, err := js.AddConsumer("MEM", &nats.ConsumerConfig{
					Durable: "PENDING", FilterSubject: filter, AckPolicy: nats.AckExplicitPolicy,
					DeliverPolicy: nats.DeliverByStartSequencePolicy, OptStartSeq: max(start, 1),
				})
				require_NoError(t, err)
				require_Equal(t, consumer.NumPending, expected)
				require_NoError(t, js.DeleteConsumer("MEM", "PENDING"))
				expectedLast := slices.Sorted(maps.Values(latest))
				messages := memStoreIntegrationMultiLast(t, nc, JSApiMsgGetRequest{Seq: max(start, 1), MultiLastFor: []string{filter}})
				require_Equal(t, len(messages), len(expectedLast))
				for i, msg := range messages {
					require_Equal(t, msg.Header.Get("Nats-Sequence"), strconv.FormatUint(expectedLast[i], 10))
				}
			})
		}
	}
}

func TestMemStoreIntegrationPendingMulti(t *testing.T) {
	_, js := memStoreIntegrationClient(t)
	_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: []string{"ev.*"}, Storage: nats.MemoryStorage})
	require_NoError(t, err)
	rng := rand.New(rand.NewPCG(7, 8))
	subjects := make([]string, 10000)
	for i := range subjects {
		subjects[i] = "ev." + nuid.Next()
	}
	fixture := make([]int, 100000)
	payload := bytes.Repeat([]byte("ZZZ"), 333)
	for i := range fixture {
		fixture[i] = rng.IntN(len(subjects))
		_, err := js.PublishAsync(subjects[fixture[i]], payload)
		require_NoError(t, err)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(30 * time.Second):
		t.Fatal("100000 publications did not complete")
	}
	stream, err := js.StreamInfo("MEM")
	require_NoError(t, err)
	require_Equal(t, stream.State.Msgs, 100000)
	require_Equal(t, stream.State.LastSeq, 100000)
	selected := make(map[int]bool, 5000)
	filters := make([]string, 0, 5000)
	for _, index := range rng.Perm(len(subjects))[:5000] {
		selected[index] = true
		filters = append(filters, subjects[index])
	}
	start := uint64(5000 + rng.IntN(90000))
	var expected []uint64
	for i, index := range fixture {
		if seq := uint64(i + 1); seq >= start && selected[index] {
			expected = append(expected, seq)
		}
	}
	info, err := js.AddConsumer("MEM", &nats.ConsumerConfig{
		Durable: "MULTI", FilterSubjects: filters, AckPolicy: nats.AckExplicitPolicy,
		DeliverPolicy: nats.DeliverByStartSequencePolicy, OptStartSeq: start,
	})
	require_NoError(t, err)
	require_Equal(t, info.NumPending, uint64(len(expected)))
	sub, err := js.PullSubscribe("", "MULTI", nats.Bind("MEM", "MULTI"))
	require_NoError(t, err)
	messages, err := sub.Fetch(64, nats.MaxWait(2*time.Second))
	require_NoError(t, err)
	require_Equal(t, len(messages), 64)
	for i, msg := range messages {
		meta, err := msg.Metadata()
		require_NoError(t, err)
		require_Equal(t, meta.Sequence.Stream, expected[i])
		require_Equal(t, msg.Subject, subjects[fixture[expected[i]-1]])
		require_True(t, bytes.Equal(msg.Data, payload))
		require_NoError(t, msg.AckSync())
	}
	info, err = js.ConsumerInfo("MEM", "MULTI")
	require_NoError(t, err)
	require_Equal(t, info.NumPending, uint64(len(expected)-64))
	require_Equal(t, info.NumAckPending, 0)
}

func TestMemStoreIntegrationAllLastStress(t *testing.T) {
	nc, js := memStoreIntegrationClient(t)
	_, err := js.AddStream(&nats.StreamConfig{Name: "MEM", Subjects: []string{"foo.*", "bar.*"}, Storage: nats.MemoryStorage, AllowDirect: true, MaxMsgsPerSubject: 50})
	require_NoError(t, err)
	subjects := []string{"foo.foo", "foo.bar", "foo.baz", "bar.foo", "bar.bar", "bar.baz"}
	rng := rand.New(rand.NewPCG(9, 10))
	latest := make(map[string]uint64)
	for i := range 100000 {
		subject := subjects[rng.IntN(len(subjects))]
		_, err := js.PublishAsync(subject, []byte("abc"))
		require_NoError(t, err)
		latest[subject] = uint64(i + 1)
	}
	select {
	case <-js.PublishAsyncComplete():
	case <-time.After(30 * time.Second):
		t.Fatal("100000 publications did not complete")
	}
	info, err := js.StreamInfo("MEM")
	require_NoError(t, err)
	require_Equal(t, info.State.Msgs, 300)
	require_Equal(t, info.State.LastSeq, 100000)
	require_Equal(t, info.State.NumSubjects, 6)
	var expected []uint64
	for subject, seq := range latest {
		stored, err := js.GetLastMsg("MEM", subject)
		require_NoError(t, err)
		require_Equal(t, stored.Sequence, seq)
		expected = append(expected, seq)
	}
	slices.Sort(expected)
	messages := memStoreIntegrationMultiLast(t, nc, JSApiMsgGetRequest{MultiLastFor: []string{">"}})
	require_Equal(t, len(messages), 6)
	for i, msg := range messages {
		require_Equal(t, msg.Header.Get("Nats-Sequence"), strconv.FormatUint(expected[i], 10))
		require_Equal(t, latest[msg.Header.Get("Nats-Subject")], expected[i])
	}
}

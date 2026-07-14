package pcapparser

// Test points for trigram.go, derived from tools/test_points/pcapparser.md
// (components T1-T6 + T-RT). REAL tests exercising the TrigramIndex directly.

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
)

// --- T1: NewTrigramIndex ---

func TestNewTrigramIndex_Empty(t *testing.T) {
	idx := NewTrigramIndex()
	if idx.Postings == nil {
		t.Error("Postings nil, want non-nil empty map")
	}
	if len(idx.Postings) != 0 {
		t.Errorf("Postings len = %d, want 0", len(idx.Postings))
	}
	if idx.Segments != nil {
		t.Errorf("Segments = %v, want nil", idx.Segments)
	}
	if idx.SegmentCount() != 0 {
		t.Errorf("SegmentCount = %d, want 0", idx.SegmentCount())
	}
}

// --- T2: AddSegment ---

func TestAddSegment_ShortData(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("ab"))
	if idx.SegmentCount() != 1 {
		t.Errorf("SegmentCount = %d, want 1 (segment stored despite <3 bytes)", idx.SegmentCount())
	}
	if len(idx.Postings) != 0 {
		t.Errorf("Postings len = %d, want 0 (no trigrams from 2 bytes)", len(idx.Postings))
	}
	// linearSearch still finds the short pattern.
	m := idx.Search([]byte("ab"))
	if len(m) != 1 {
		t.Errorf("linearSearch 'ab' = %d matches, want 1", len(m))
	}
}

func TestAddSegment_Exactly3Bytes(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("abc"))
	if len(idx.Postings) != 1 {
		t.Errorf("Postings len = %d, want 1 (one trigram 'abc')", len(idx.Postings))
	}
}

func TestAddSegment_DuplicateTrigrams(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("aaaa"))
	var key [3]byte
	copy(key[:], []byte("aaa"))
	postings := idx.Postings[key]
	if len(postings) != 2 {
		t.Errorf("'aaa' postings = %d, want 2 (offsets 0 and 1)", len(postings))
	}
}

// --- T3: Search ---

func TestSearch_RarestTrigramZeroPostings(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("hello world"))
	// Pattern contains a trigram not present in any segment -> nil.
	m := idx.Search([]byte("hexxxxx"))
	if m != nil {
		t.Errorf("search with absent trigram = %v, want nil", m)
	}
}

func TestSearch_TrigramHitNoMatch(t *testing.T) {
	idx := NewTrigramIndex()
	// Segment contains every trigram of "foobaz" but not "foobaz" itself.
	idx.AddSegment("f1", "c2s", []byte("foobarbaz"))
	m := idx.Search([]byte("foobaz"))
	if len(m) != 0 {
		t.Errorf("trigram hit but no full match = %v, want empty (false-positive filtered)", m)
	}
}

func TestSearch_LaterTrigramRarest(t *testing.T) {
	idx := NewTrigramIndex()
	// "abc" appears once; "zzz" appears once but only in a different segment.
	idx.AddSegment("f1", "c2s", []byte("abc common abc common"))
	idx.AddSegment("f2", "c2s", []byte("zzz abc"))
	// Pattern "zzz abc": trigrams "zzz"(rarest, 1 posting) and "abc"(many).
	// The rarest-trigram selection must still find the match in f2.
	m := idx.Search([]byte("zzz abc"))
	if len(m) != 1 || m[0].FlowID != "f2" {
		t.Errorf("later-trigram-rarest search = %v, want 1 match in f2", m)
	}
}

func TestSearch_FoundInMultipleSegments(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("the quick brown"))
	idx.AddSegment("f2", "s2c", []byte("the lazy dog"))
	m := idx.Search([]byte("the"))
	// "the" is 3 bytes -> trigram path. Both segments contain "the".
	if len(m) != 2 {
		t.Errorf("'the' matches = %d, want 2 (one per segment)", len(m))
	}
}

// --- T4: linearSearch ---

func TestLinearSearch_NoSegments(t *testing.T) {
	idx := NewTrigramIndex()
	m := idx.linearSearch([]byte("ab"))
	if m != nil {
		t.Errorf("linearSearch empty index = %v, want nil", m)
	}
}

func TestLinearSearch_NotFound(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("hello world"))
	m := idx.linearSearch([]byte("ab"))
	if len(m) != 0 {
		t.Errorf("linearSearch not-found = %v, want empty", m)
	}
}

func TestLinearSearch_MultipleOccurrences(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("abXabYab"))
	m := idx.linearSearch([]byte("ab"))
	if len(m) != 3 {
		t.Errorf("linearSearch multiple 'ab' = %d matches, want 3", len(m))
	}
}

// --- T5: WriteToFile ---

func TestTrigramWriteToFile_CreateFail(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("hello"))
	n, err := idx.WriteToFile("/no/such/dir/x.trigram")
	if err == nil {
		t.Error("WriteFile to bad dir: expected error, got nil")
	}
	if n != 0 {
		t.Errorf("n = %d, want 0 on error", n)
	}
}

func TestTrigramWriteToFile_Success(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("hello world"))
	path := filepath.Join(t.TempDir(), "out.trigram")
	n, err := idx.WriteToFile(path)
	if err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
	if n <= 0 {
		t.Errorf("n = %d, want > 0", n)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("file not written: %v", err)
	}
}

// --- T6: LoadFromFile ---

func TestTrigramLoadFromFile_OpenFail(t *testing.T) {
	idx, err := LoadFromFile("/nonexistent/path/x.trigram")
	if err == nil {
		t.Error("LoadFromFile nonexistent: expected error, got nil")
	}
	if idx != nil {
		t.Errorf("idx = %v, want nil on open fail", idx)
	}
}

func TestTrigramLoadFromFile_DecodeFail(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.trigram")
	if err := os.WriteFile(path, []byte("not gob encoded content"), 0644); err != nil {
		t.Fatalf("write bad file: %v", err)
	}
	idx, err := LoadFromFile(path)
	if err == nil {
		t.Error("LoadFromFile non-gob: expected error, got nil")
	}
	if idx != nil {
		t.Errorf("idx = %v, want nil on decode fail", idx)
	}
}

func TestTrigramLoadFromFile_Success(t *testing.T) {
	idx := NewTrigramIndex()
	idx.AddSegment("f1", "c2s", []byte("hello world"))
	idx.AddSegment("f2", "s2c", []byte("another segment"))
	path := filepath.Join(t.TempDir(), "ok.trigram")
	if _, err := idx.WriteToFile(path); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
	loaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if loaded.SegmentCount() != 2 {
		t.Errorf("loaded SegmentCount = %d, want 2", loaded.SegmentCount())
	}
	m := loaded.Search([]byte("hello"))
	if len(m) != 1 {
		t.Errorf("loaded search 'hello' = %d, want 1", len(m))
	}
}

// --- T-RT: WriteLoadRoundTrip (required: persistence round-trip consistent) ---

func TestTrigramIndex_WriteLoadRoundTrip(t *testing.T) {
	orig := NewTrigramIndex()
	orig.AddSegment("f1", "c2s", []byte("GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n"))
	orig.AddSegment("f1", "s2c", []byte("HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\nbody"))
	orig.AddSegment("f2", "c2s", []byte("password=secret&token=xyz"))
	orig.AddSegment("f3", "s2c", []byte("aaaaaaa")) // duplicate trigrams

	path := filepath.Join(t.TempDir(), "roundtrip.trigram")
	if _, err := orig.WriteToFile(path); err != nil {
		t.Fatalf("WriteToFile: %v", err)
	}
	loaded, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if loaded.SegmentCount() != orig.SegmentCount() {
		t.Fatalf("SegmentCount %d vs %d", loaded.SegmentCount(), orig.SegmentCount())
	}
	// Sorted trigrams must match exactly.
	origTrigs := orig.SortedTrigrams()
	loadedTrigs := loaded.SortedTrigrams()
	if len(origTrigs) != len(loadedTrigs) {
		t.Fatalf("trigram count %d vs %d", len(origTrigs), len(loadedTrigs))
	}
	for i := range origTrigs {
		if origTrigs[i] != loadedTrigs[i] {
			t.Errorf("trigram[%d] %v vs %v", i, origTrigs[i], loadedTrigs[i])
		}
	}
	// Search results must match exactly for several patterns.
	patterns := [][]byte{
		[]byte("/index.html"),
		[]byte("Host"),
		[]byte("password"),
		[]byte("secret"),
		[]byte("aaaa"),
		[]byte("missing-pattern"),
	}
	for _, p := range patterns {
		o := orig.Search(p)
		l := loaded.Search(p)
		if len(o) != len(l) {
			t.Errorf("pattern %q: %d vs %d matches", p, len(o), len(l))
			continue
		}
		// Sort both by (FlowID, Dir, Offset) for stable comparison.
		sortMatches := func(m []TrigramMatch) []TrigramMatch {
			out := make([]TrigramMatch, len(m))
			copy(out, m)
			sort.Slice(out, func(i, j int) bool {
				if out[i].FlowID != out[j].FlowID {
					return out[i].FlowID < out[j].FlowID
				}
				if out[i].Dir != out[j].Dir {
					return out[i].Dir < out[j].Dir
				}
				return out[i].Offset < out[j].Offset
			})
			return out
		}
		oSorted := sortMatches(o)
		lSorted := sortMatches(l)
		for i := range oSorted {
			if !reflect.DeepEqual(oSorted[i], lSorted[i]) {
				t.Errorf("pattern %q match[%d]: orig %+v vs loaded %+v", p, i, oSorted[i], lSorted[i])
			}
		}
	}
	// Segments (FlowID/Dir/Data) must round-trip.
	for i := range orig.Segments {
		if orig.Segments[i].FlowID != loaded.Segments[i].FlowID {
			t.Errorf("seg[%d].FlowID %q vs %q", i, orig.Segments[i].FlowID, loaded.Segments[i].FlowID)
		}
		if orig.Segments[i].Dir != loaded.Segments[i].Dir {
			t.Errorf("seg[%d].Dir %q vs %q", i, orig.Segments[i].Dir, loaded.Segments[i].Dir)
		}
		if !bytes.Equal(orig.Segments[i].Data, loaded.Segments[i].Data) {
			t.Errorf("seg[%d].Data mismatch", i)
		}
	}
}

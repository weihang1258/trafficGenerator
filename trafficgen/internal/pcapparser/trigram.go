package pcapparser

import (
	"bytes"
	"encoding/gob"
	"os"
	"sort"
)

// TrigramIndex is a 3-byte inverted index over payload segments (§11), enabling
// arbitrary substring search (text + binary). A segment is either a TCP
// reassembled L7 stream (one per direction) or a single UDP packet's payload.
//
// v1 holds segment bytes in memory for O(1) verification during search. The
// design's .trigram file (delta+varint postings) is a serialization of this
// structure for persistence; v1 builds it fresh per Parse (persistence is added
// with the asset layer in P9).
type TrigramIndex struct {
	// Segments[i] is the i-th payload segment; postings reference segments by ID.
	Segments []trigramSegment
	// Postings maps a 3-byte trigram to the segments that contain it, each with
	// the offset(s) where the trigram occurs.
	Postings map[[3]byte][]trigramPosting
}

type trigramSegment struct {
	FlowID string
	Dir    string // c2s|s2c
	Data   []byte
}

type trigramPosting struct {
	SegmentID int
	Offset    int // byte offset of the trigram within the segment
}

// NewTrigramIndex creates an empty index.
func NewTrigramIndex() *TrigramIndex {
	return &TrigramIndex{Postings: map[[3]byte][]trigramPosting{}}
}

// AddSegment indexes a payload segment: it stores the bytes and adds every
// trigram occurrence to the postings. Segments < 3 bytes are stored (for linear
// search of short patterns) but contribute no trigrams.
func (idx *TrigramIndex) AddSegment(flowID, dir string, data []byte) int {
	// Copy so the caller's slice can be reused/freed.
	d := make([]byte, len(data))
	copy(d, data)
	segID := len(idx.Segments)
	idx.Segments = append(idx.Segments, trigramSegment{FlowID: flowID, Dir: dir, Data: d})
	for i := 0; i+3 <= len(d); i++ {
		var t [3]byte
		copy(t[:], d[i:i+3])
		idx.Postings[t] = append(idx.Postings[t], trigramPosting{SegmentID: segID, Offset: i})
	}
	return segID
}

// TrigramMatch is a search hit: the pattern occurs at Offset within a segment
// belonging to FlowID/Dir.
type TrigramMatch struct {
	FlowID   string
	Dir      string
	Offset   int // byte offset within the segment
	SegLen   int // segment length (for range queries)
}

// Search finds all occurrences of pattern in indexed segments (§11). For
// patterns >= 3 bytes it uses the trigram index: it picks the RAREST trigram in
// the pattern (smallest postings list) to minimize candidates, then verifies
// each. For shorter patterns it linear-scans every segment.
func (idx *TrigramIndex) Search(pattern []byte) []TrigramMatch {
	if len(pattern) == 0 {
		return nil
	}
	if len(pattern) < 3 {
		return idx.linearSearch(pattern)
	}
	// Pick the rarest trigram: the one with the fewest postings. This shrinks
	// the candidate set before verification (§11: "取交集"). Correctness is
	// unchanged because every match must contain every trigram; starting from
	// the rarest just minimizes false-candidate verification work.
	var bestPostings []trigramPosting
	bestCount := -1
	for i := 0; i+3 <= len(pattern); i++ {
		var t [3]byte
		copy(t[:], pattern[i:i+3])
		p := idx.Postings[t]
		if bestCount < 0 || len(p) < bestCount {
			bestCount = len(p)
			bestPostings = p
			if bestCount == 0 {
				break // no occurrences of this trigram -> no matches possible
			}
		}
	}
	var matches []TrigramMatch
	for _, p := range bestPostings {
		seg := idx.Segments[p.SegmentID]
		// The rarest trigram occurs at p.Offset, but the match (if any) starts
		// at a position where pattern[0] aligns. Since the trigram may be any
		// position in the pattern, we can't use p.Offset directly as the match
		// start. Instead scan the segment for the full pattern (the rarest-
		// trigram postings only tell us WHICH segments to scan, narrowing the
		// work vs. scanning every segment).
		start := 0
		for {
			i := bytes.Index(seg.Data[start:], pattern)
			if i < 0 {
				break
			}
			matches = append(matches, TrigramMatch{
				FlowID: seg.FlowID, Dir: seg.Dir, Offset: start + i, SegLen: len(seg.Data),
			})
			start += i + 1
		}
	}
	return matches
}

// linearSearch scans every segment for a sub-3-byte pattern (no trigrams to
// index on).
func (idx *TrigramIndex) linearSearch(pattern []byte) []TrigramMatch {
	var matches []TrigramMatch
	for _, seg := range idx.Segments {
		start := 0
		for {
			i := bytes.Index(seg.Data[start:], pattern)
			if i < 0 {
				break
			}
			matches = append(matches, TrigramMatch{
				FlowID: seg.FlowID, Dir: seg.Dir, Offset: start + i, SegLen: len(seg.Data),
			})
			start += i + 1
		}
	}
	return matches
}

// SegmentCount returns the number of indexed segments.
func (idx *TrigramIndex) SegmentCount() int { return len(idx.Segments) }

// SortedTrigrams returns the trigram keys in sorted order (for deterministic
// serialization in a future .trigram file).
func (idx *TrigramIndex) SortedTrigrams() [][3]byte {
	keys := make([][3]byte, 0, len(idx.Postings))
	for k := range idx.Postings {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		return bytes.Compare(keys[i][:], keys[j][:]) < 0
	})
	return keys
}

// trigramFile is the serializable structure for on-disk persistence (§11).
// Gob-encoded to the .trigram file; loaded on demand for search.
type trigramFile struct {
	Segments []trigramSegment
	Postings map[[3]byte][]trigramPosting
}

// WriteToFile serializes the index to path using gob encoding. Overwrites any
// existing file. Returns the number of bytes written.
func (idx *TrigramIndex) WriteToFile(path string) (int64, error) {
	f, err := os.Create(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	tf := trigramFile{Segments: idx.Segments, Postings: idx.Postings}
	if err := gob.NewEncoder(f).Encode(tf); err != nil {
		return 0, err
	}
	info, _ := f.Stat()
	return info.Size(), nil
}

// LoadFromFile deserializes an index from a gob-encoded .trigram file.
func LoadFromFile(path string) (*TrigramIndex, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var tf trigramFile
	if err := gob.NewDecoder(f).Decode(&tf); err != nil {
		return nil, err
	}
	return &TrigramIndex{Segments: tf.Segments, Postings: tf.Postings}, nil
}

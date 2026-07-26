package filesystem_test

import (
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// TestFileSource_Validate_NegativeFillBytes verifies Fill.Bytes < 0 is
// rejected. Before Validate, this would silently pass through and panic
// make([]byte, n) on 64-bit platforms (huge alloc) or wrap to a large
// positive on 32-bit.
func TestFileSource_Validate_NegativeFillBytes(t *testing.T) {
	src := &filesystem.FileSource{Fill: &filesystem.Fill{Byte: 'A', Bytes: -1}}
	if err := src.Validate(); err == nil {
		t.Fatal("Validate accepted Fill.Bytes=-1, want error")
	}
}

// TestFileSource_Validate_FillByteTruncation verifies that Fill.Byte, while
// type-safe (byte is 0-255), is documented but not rejected — the JSON
// decoder truncates silently. Validate cannot recover the original value
// (it's already truncated before reaching us), so we only document the
// limitation here. The plan task 3 user-visible behavior is rejection of
// out-of-range values at the JSON layer via a custom UnmarshalJSON, but
// that's out of scope for this Validate-only fix.
func TestFileSource_Validate_FillByteTruncation(t *testing.T) {
	// 300 as a byte literal would be a compile error. JSON would silently
	// truncate to 44. Validate sees byte=44 and accepts — this is the
	// known limitation documented in validate.go. We assert that
	// Fill.Byte within range passes.
	src := &filesystem.FileSource{Fill: &filesystem.Fill{Byte: 0x41, Bytes: 100}}
	if err := src.Validate(); err != nil {
		t.Fatalf("Validate rejected valid Fill: %v", err)
	}
}

// TestFileSource_Validate_RandomMinGtMax verifies MinBytes > MaxBytes is
// rejected — this would produce empty output and confuse callers.
func TestFileSource_Validate_RandomMinGtMax(t *testing.T) {
	src := &filesystem.FileSource{
		Random: &filesystem.Random{MinBytes: 200, MaxBytes: 100, Seed: 1},
	}
	if err := src.Validate(); err == nil {
		t.Fatal("Validate accepted MinBytes>MaxBytes, want error")
	}
}

// TestFileSource_Validate_NegativeRandomBytes verifies negative Min/Max
// is rejected.
func TestFileSource_Validate_NegativeRandomBytes(t *testing.T) {
	src := &filesystem.FileSource{
		Random: &filesystem.Random{MinBytes: -1, MaxBytes: 10, Seed: 1},
	}
	if err := src.Validate(); err == nil {
		t.Fatal("Validate accepted negative MinBytes, want error")
	}
}

// TestFileSource_Validate_NilReceiver verifies nil receiver is safe —
// callers in strategy_convert.go call src.Validate() on a nil *FileSource
// (parseFileSource returns nil when absent). A nil-deref panic here
// would break every existing config.
func TestFileSource_Validate_NilReceiver(t *testing.T) {
	var src *filesystem.FileSource
	if err := src.Validate(); err != nil {
		t.Fatalf("nil receiver Validate: got %v, want nil", err)
	}
}

// TestFileSource_Validate_EmptySource verifies an empty FileSource (no
// source set) is valid — the "no source" case is the default for all
// existing configs that don't use file_source.
func TestFileSource_Validate_EmptySource(t *testing.T) {
	src := &filesystem.FileSource{}
	if err := src.Validate(); err != nil {
		t.Fatalf("empty FileSource Validate: got %v, want nil", err)
	}
}

// TestFileSource_Validate_ValidSources verifies each individual source
// kind in isolation is accepted. Multiple sources set at once is also
// accepted — silent precedence (File > Literal > Fill > Random) is the
// plan contract, see payloadcache.resolveBytes.
func TestFileSource_Validate_ValidSources(t *testing.T) {
	cases := []struct {
		name string
		src  *filesystem.FileSource
	}{
		{"file", &filesystem.FileSource{File: "docs/a.txt"}},
		{"literal", &filesystem.FileSource{Literal: "hello"}},
		{"fill", &filesystem.FileSource{Fill: &filesystem.Fill{Byte: 'A', Bytes: 100}}},
		{"seeded_random", &filesystem.FileSource{Random: &filesystem.Random{MinBytes: 10, MaxBytes: 100, Seed: 42}}},
		{"unseeded_random", &filesystem.FileSource{Random: &filesystem.Random{MinBytes: 10, MaxBytes: 100, Seed: 0}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if err := tc.src.Validate(); err != nil {
				t.Fatalf("%s: Validate err %v", tc.name, err)
			}
		})
	}
}

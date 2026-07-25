package filesystem_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// TestUpload_Fill_Success covers the src.Fill branch: a Fill{Byte: 'A', Bytes: 5}
// source produces "AAAAA".
func TestUpload_Fill_Success(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Fill: &filesystem.Fill{Byte: 'A', Bytes: 5}}
	if err := fs.Upload(ctx, "fill.txt", src); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	got, err := fs.Read(ctx, "fill.txt")
	if err != nil {
		t.Fatalf("Read err=%v", err)
	}
	if string(got) != "AAAAA" {
		t.Fatalf("Read got %q, want %q", string(got), "AAAAA")
	}
}

// TestUpload_Fill_NegativeBytes covers the src.Fill rejection branch.
func TestUpload_Fill_NegativeBytes(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Fill: &filesystem.Fill{Byte: 'A', Bytes: -1}}
	if err := fs.Upload(ctx, "fill.txt", src); err == nil {
		t.Fatal("Upload with Fill.Bytes=-1 should return error")
	}
}

// TestUpload_Random_Seeded_Reproducible verifies that two Upload calls with
// the same Random seed produce byte-for-byte identical content.
func TestUpload_Random_Seeded_Reproducible(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	rng := &filesystem.Random{MinBytes: 16, MaxBytes: 16, Seed: 42}
	if err := fs.Upload(ctx, "r1.bin", filesystem.FileSource{Random: rng}); err != nil {
		t.Fatalf("Upload r1 err=%v", err)
	}
	if err := fs.Upload(ctx, "r2.bin", filesystem.FileSource{Random: rng}); err != nil {
		t.Fatalf("Upload r2 err=%v", err)
	}
	a, err := fs.Read(ctx, "r1.bin")
	if err != nil {
		t.Fatalf("Read r1 err=%v", err)
	}
	b, err := fs.Read(ctx, "r2.bin")
	if err != nil {
		t.Fatalf("Read r2 err=%v", err)
	}
	if !bytes.Equal(a, b) {
		t.Fatalf("seeded Random not reproducible: len(a)=%d len(b)=%d", len(a), len(b))
	}
	if len(a) != 16 {
		t.Fatalf("len=%d, want 16", len(a))
	}
}

// TestUpload_Random_Unseeded_LengthInRange verifies that unseeded Random
// produces bytes whose length is within [MinBytes, MaxBytes].
func TestUpload_Random_Unseeded_LengthInRange(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	rng := &filesystem.Random{MinBytes: 8, MaxBytes: 32}
	if err := fs.Upload(ctx, "r.bin", filesystem.FileSource{Random: rng}); err != nil {
		t.Fatalf("Upload err=%v", err)
	}
	got, err := fs.Read(ctx, "r.bin")
	if err != nil {
		t.Fatalf("Read err=%v", err)
	}
	if len(got) < 8 || len(got) > 32 {
		t.Fatalf("len=%d, want in [8,32]", len(got))
	}
}

// TestUpload_Random_InvalidRange covers both MinBytes<0 and MaxBytes<MinBytes
// rejection branches.
func TestUpload_Random_InvalidRange(t *testing.T) {
	ctx := context.Background()
	cases := []struct {
		name string
		r    *filesystem.Random
	}{
		{"MinBytes negative", &filesystem.Random{MinBytes: -1, MaxBytes: 4}},
		{"MaxBytes less than MinBytes", &filesystem.Random{MinBytes: 10, MaxBytes: 5}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fs := newFS(t)
			err := fs.Upload(ctx, "r.bin", filesystem.FileSource{Random: c.r})
			if err == nil {
				t.Fatalf("Upload should return error for %s", c.name)
			}
		})
	}
}

// TestUpload_EmptySource covers the default branch: all FileSource fields
// zero -> error.
func TestUpload_EmptySource(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	if err := fs.Upload(ctx, "x.txt", filesystem.FileSource{}); err == nil {
		t.Fatal("Upload with empty FileSource should return error")
	}
}

// TestUpload_CleanRelPath_Rejections covers cleanRelPath rejection branches:
// empty path, absolute path, and ".." escape.
func TestUpload_CleanRelPath_Rejections(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	src := filesystem.FileSource{Literal: "x"}
	cases := []struct {
		name string
		path string
	}{
		{"empty", ""},
		{"absolute", "/etc/foo"},
		{"dotdot escape", "../foo"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := fs.Upload(ctx, c.path, src)
			if err == nil {
				t.Fatalf("Upload(%q) should return error", c.path)
			}
		})
	}
}

// TestRead_MissingPath returns ErrNotFound.
func TestRead_MissingPath(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	_, err := fs.Read(ctx, "nope.txt")
	if !errors.Is(err, filesystem.ErrNotFound) {
		t.Fatalf("Read missing path err=%v, want ErrNotFound", err)
	}
}

// TestUpload_SourceFile_NoDeadlock is a regression test for C1: uploading a
// FileSource{File: ...} must not self-deadlock. We seed base.txt with Literal,
// then Upload copy.txt referring to base.txt. We run the second Upload in a
// goroutine with a timeout; if it deadlocks, the test fails.
func TestUpload_SourceFile_NoDeadlock(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	base := "base.txt"
	if err := fs.Upload(ctx, base, filesystem.FileSource{Literal: "base content"}); err != nil {
		t.Fatalf("seed base err=%v", err)
	}
	type res struct {
		err error
	}
	done := make(chan res, 1)
	go func() {
		done <- res{err: fs.Upload(ctx, "copy.txt", filesystem.FileSource{File: base})}
	}()
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatalf("Upload copy err=%v", r.err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Upload FileSource{File:...} deadlocked (timeout)")
	}
	gotCopy, err := fs.Read(ctx, "copy.txt")
	if err != nil {
		t.Fatalf("Read copy err=%v", err)
	}
	gotBase, err := fs.Read(ctx, base)
	if err != nil {
		t.Fatalf("Read base err=%v", err)
	}
	if !bytes.Equal(gotCopy, gotBase) {
		t.Fatalf("copy=%q, base=%q (should match)", string(gotCopy), string(gotBase))
	}
}

// TestUpload_DotPath_Rejected covers M2: "." is rejected by cleanRelPath.
func TestUpload_DotPath_Rejected(t *testing.T) {
	fs := newFS(t)
	ctx := context.Background()
	err := fs.Upload(ctx, ".", filesystem.FileSource{Literal: "x"})
	if err == nil {
		t.Fatal("Upload(\".\") should return error")
	}
	if !strings.Contains(err.Error(), "'.'") {
		t.Fatalf("err=%v, want message mentioning '.'", err)
	}
}

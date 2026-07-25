package filesystem_test

import (
	"testing"

	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

func TestFileSource_ZeroValue(t *testing.T) {
	var fs filesystem.FileSource
	if fs.File != "" || fs.Literal != "" || fs.Fill != nil || fs.Random != nil {
		t.Fatalf("zero FileSource should have all zero values: %+v", fs)
	}
}

func TestNew_EmptyRoot(t *testing.T) {
	_, err := filesystem.New("")
	if err == nil {
		t.Fatal("New(\"\") should return error on empty root")
	}
}

func TestNew_CreatesDir(t *testing.T) {
	dir := t.TempDir()
	fs, err := filesystem.New(dir)
	if err != nil {
		t.Fatalf("New(%q) err=%v", dir, err)
	}
	if fs == nil {
		t.Fatal("New returned nil Filesystem")
	}
}

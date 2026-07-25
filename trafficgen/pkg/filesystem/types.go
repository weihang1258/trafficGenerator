// Package filesystem implements a content-addressed filesystem with hash
// dedup. Multiple file names can map to the same backing blob (SHA-256
// keyed); deleting a name only deletes the blob when the last name is
// removed. The filesystem is independent of traffic generation — the
// traffic generator only calls Read(relPath). All mutations (Upload,
// Delete, Mkdir, Rmdir) come from the standalone CLI, REST API, or MCP
// tool entry points.
package filesystem

import (
	"errors"
	"sync"
	"time"
)

// FileSource describes how to obtain bytes for a file. Exactly one source
// should be set. Priority: File > Literal > Fill > Random.
type FileSource struct {
	File    string  `json:"file,omitempty"`    // filesystem relative path (recursive Read)
	Literal string  `json:"literal,omitempty"` // inline text bytes
	Fill    *Fill   `json:"fill,omitempty"`     // single-byte pattern
	Random  *Random `json:"random,omitempty"`   // random content, length range
}

// Fill describes a single-byte pattern repeated Bytes times.
type Fill struct {
	Byte  byte `json:"byte"`
	Bytes int  `json:"bytes"`
}

// Random describes random bytes with length in [MinBytes, MaxBytes]. When
// Seed is non-zero, output is reproducible per (Seed, MinBytes, MaxBytes).
// When Seed is zero, output is fresh crypto-random on every call.
type Random struct {
	MinBytes int   `json:"min_bytes"`
	MaxBytes int   `json:"max_bytes"`
	Seed     int64 `json:"seed,omitempty"`
}

// FileInfo is metadata for a file or directory entry.
type FileInfo struct {
	Name    string    `json:"name"`
	IsDir   bool      `json:"is_dir"`
	Size    int64     `json:"size"`
	ModTime time.Time `json:"mod_time"`
	SHA256  string    `json:"sha256,omitempty"` // empty for directories
}

// RmdirOptions controls directory deletion.
type RmdirOptions struct {
	Recursive bool `json:"recursive"` // false = reject if non-empty
}

var (
	ErrNotFound     = errors.New("filesystem: path not found")
	ErrExists       = errors.New("filesystem: path already exists")
	ErrNotEmpty     = errors.New("filesystem: directory not empty")
	ErrNotADirectory = errors.New("filesystem: not a directory")
)

// Filesystem is the standalone content-addressed filesystem.
type Filesystem struct {
	root string
	mu   sync.RWMutex
}

// New creates a Filesystem rooted at root. The root and its required
// subdirectories (.meta/files, blobs) are created if missing.
func New(root string) (*Filesystem, error) {
	if root == "" {
		return nil, errors.New("filesystem: root must not be empty")
	}
	fs := &Filesystem{root: root}
	if err := fs.initDirs(); err != nil {
		return nil, err
	}
	return fs, nil
}

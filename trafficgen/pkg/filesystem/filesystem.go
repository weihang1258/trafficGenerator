package filesystem

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// initDirs creates the root, .meta/files, and blobs/ subdirectories.
func (fs *Filesystem) initDirs() error {
	for _, sub := range []string{".meta/files", "blobs"} {
		if err := os.MkdirAll(filepath.Join(fs.root, filepath.FromSlash(sub)), 0755); err != nil {
			return err
		}
	}
	return nil
}

// Root returns the absolute root directory.
func (fs *Filesystem) Root() string { return fs.root }

// Upload writes the bytes from src to relPath in the filesystem. The bytes
// are content-addressed: if an identical blob (by SHA-256) is already
// present, no new blob is written. If relPath already exists, the old
// blob's ref is removed first (which may delete the old blob if it was
// the last reference).
//
// relPath must be a relative path (no leading slash). Path components are
// cleaned and validated for directory traversal escape.
func (fs *Filesystem) Upload(ctx context.Context, relPath string, src FileSource) error {
	cleanRel, err := fs.cleanRelPath(relPath)
	if err != nil {
		return err
	}
	// Resolve bytes BEFORE locking; src.File recurses into Read which needs RLock.
	b, err := fs.resolveBytes(src)
	if err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	hash := hashStr(b)

	// If relPath already references a different blob, remove the old ref
	// (and delete the old blob if refs become empty).
	if existingHash, err := fs.lookupHashForPath(cleanRel); err == nil && existingHash != hash {
		if err := fs.removeRefLocked(existingHash, cleanRel); err != nil {
			return err
		}
	}

	// Write the blob if missing (hash dedup: skip write if already exists).
	blobPath := fs.blobPath(hash)
	if _, err := os.Stat(blobPath); os.IsNotExist(err) {
		if err := os.WriteFile(blobPath, b, 0644); err != nil {
			return err
		}
	}

	// Update meta: add cleanRel to refs[].
	meta, err := fs.loadMeta(hash)
	if err != nil && !errors.Is(err, ErrNotFound) {
		return err
	}
	if meta == nil {
		meta = &fileMeta{Hash: hash, Size: int64(len(b)), Created: time.Now().UnixNano()}
	}
	if !containsStr(meta.Refs, cleanRel) {
		meta.Refs = append(meta.Refs, cleanRel)
	}
	return fs.saveMeta(hash, meta)
}

// Read returns the bytes at relPath. Returns ErrNotFound if relPath is
// not registered.
func (fs *Filesystem) Read(ctx context.Context, relPath string) ([]byte, error) {
	cleanRel, err := fs.cleanRelPath(relPath)
	if err != nil {
		return nil, err
	}
	fs.mu.RLock()
	hash, err := fs.lookupHashForPath(cleanRel)
	fs.mu.RUnlock()
	if err != nil {
		return nil, err
	}
	return os.ReadFile(fs.blobPath(hash))
}

// lookupHashForPath scans all meta files for one whose refs[] contains
// relPath. Returns ErrNotFound if no match.
func (fs *Filesystem) lookupHashForPath(relPath string) (string, error) {
	entries, err := os.ReadDir(filepath.Join(fs.root, ".meta", "files"))
	if err != nil {
		return "", ErrNotFound
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		hash := strings.TrimSuffix(e.Name(), ".json")
		meta, err := fs.loadMeta(hash)
		if err != nil {
			continue
		}
		if containsStr(meta.Refs, relPath) {
			return meta.Hash, nil
		}
	}
	return "", ErrNotFound
}

// removeRefLocked removes relPath from hash's meta. If refs becomes empty,
// deletes the blob and meta file. Caller must hold fs.mu.
func (fs *Filesystem) removeRefLocked(hash, relPath string) error {
	meta, err := fs.loadMeta(hash)
	if err != nil {
		return err
	}
	meta.Refs = removeStr(meta.Refs, relPath)
	if len(meta.Refs) == 0 {
		if err := os.Remove(fs.blobPath(hash)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return fs.deleteMeta(hash)
	}
	return fs.saveMeta(hash, meta)
}

// cleanRelPath validates and cleans a relative path. Rejects empty paths,
// absolute paths, and directory traversal escape.
func (fs *Filesystem) cleanRelPath(relPath string) (string, error) {
	if relPath == "" {
		return "", errors.New("filesystem: path must not be empty")
	}
	if filepath.IsAbs(relPath) {
		return "", errors.New("filesystem: path must be relative")
	}
	clean := filepath.Clean(filepath.FromSlash(relPath))
	if clean == "." {
		return "", errors.New("filesystem: path must not be '.'")
	}
	// Reject ".." that escapes root.
	rel := filepath.Clean(filepath.Join(fs.root, clean))
	if !strings.HasPrefix(rel, fs.root+string(filepath.Separator)) && rel != fs.root {
		return "", errors.New("filesystem: path escapes root")
	}
	return filepath.ToSlash(clean), nil
}

// containsStr reports whether s contains v.
func containsStr(s []string, v string) bool {
	for _, x := range s {
		if x == v {
			return true
		}
	}
	return false
}

// removeStr returns s with the first occurrence of v removed.
func removeStr(s []string, v string) []string {
	for i, x := range s {
		if x == v {
			return append(s[:i], s[i+1:]...)
		}
	}
	return s
}

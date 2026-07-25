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

	// Materialize the file on disk at relPath so it is visible to List,
	// Query, and external tools. Use a hardlink to the blob when the OS
	// supports it; fall back to a copy otherwise.
	absRel := filepath.Join(fs.root, filepath.FromSlash(cleanRel))
	if err := os.MkdirAll(filepath.Dir(absRel), 0755); err != nil {
		return err
	}
	// If an entry already exists at absRel, it must be a stale hardlink to
	// an old blob (Upload is overwriting a previously uploaded file). A
	// directory at absRel is a programming error — refuse to silently
	// replace it with a hardlink, which would hide the dir behind a file.
	if st, err := os.Lstat(absRel); err == nil {
		if st.IsDir() {
			return errors.New("filesystem: path is a directory")
		}
		// Remove the stale hardlink so the new hardlink can take its place.
		// Surface the remove error rather than letting the subsequent
		// os.Link fail with a confusing "file exists".
		if err := os.Remove(absRel); err != nil {
			return err
		}
	}
	if err := os.Link(blobPath, absRel); err != nil {
		// Fall back to a copy if hardlink fails (e.g., cross-device).
		if err := os.WriteFile(absRel, b, 0644); err != nil {
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
		// Remove the materialized file at relPath (hardlink or copy).
		if err := os.Remove(filepath.Join(fs.root, filepath.FromSlash(relPath))); err != nil && !os.IsNotExist(err) {
			return err
		}
		if err := os.Remove(fs.blobPath(hash)); err != nil && !os.IsNotExist(err) {
			return err
		}
		return fs.deleteMeta(hash)
	}
	// Other refs remain: remove this name's materialized file but keep blob.
	if err := os.Remove(filepath.Join(fs.root, filepath.FromSlash(relPath))); err != nil && !os.IsNotExist(err) {
		return err
	}
	return fs.saveMeta(hash, meta)
}

// Delete removes relPath from the filesystem. If the path's blob has no
// remaining refs, the blob is deleted too. Returns ErrNotFound if relPath
// is not registered.
func (fs *Filesystem) Delete(ctx context.Context, relPath string) error {
	cleanRel, err := fs.cleanRelPath(relPath)
	if err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	hash, err := fs.lookupHashForPath(cleanRel)
	if err != nil {
		return err
	}
	return fs.removeRefLocked(hash, cleanRel)
}

// Query returns metadata for relPath. Returns ErrNotFound if not registered.
// Directories (present on disk under fs.root) are reported with IsDir=true.
func (fs *Filesystem) Query(ctx context.Context, relPath string) (FileInfo, error) {
	cleanRel, err := fs.cleanRelPath(relPath)
	if err != nil {
		return FileInfo{}, err
	}
	fs.mu.RLock()
	defer fs.mu.RUnlock()

	// Check directory first.
	abs := filepath.Join(fs.root, filepath.FromSlash(cleanRel))
	st, err := os.Stat(abs)
	if err == nil && st.IsDir() {
		return FileInfo{Name: cleanRel, IsDir: true, Size: 0, ModTime: st.ModTime()}, nil
	}

	hash, err := fs.lookupHashForPath(cleanRel)
	if err != nil {
		return FileInfo{}, err
	}
	meta, err := fs.loadMeta(hash)
	if err != nil {
		return FileInfo{}, err
	}
	blobStat, err := os.Stat(fs.blobPath(hash))
	if err != nil {
		return FileInfo{}, err
	}
	return FileInfo{
		Name:    cleanRel,
		IsDir:   false,
		Size:    meta.Size,
		ModTime: blobStat.ModTime(),
		SHA256:  hash,
	}, nil
}

// List returns entries in dirPath. Directories are listed as such. Files
// are listed with size and mtime. Internal entries (.meta, blobs) are
// skipped. Returns ErrNotFound if dirPath does not exist; other os.ReadDir
// errors (e.g., permission denied) are returned as-is. A dirPath of "."
// lists the filesystem root.
//
// Note on foreign files: files that exist on disk under fs.root but were
// not registered via Upload (e.g., dropped in by an external tool) appear
// in the listing with Size: 0 and SHA256: "" because no metadata record
// references them. By contrast, Query on such a foreign file returns
// ErrNotFound (Query looks up by registered ref, not by disk presence).
func (fs *Filesystem) List(ctx context.Context, dirPath string) ([]FileInfo, error) {
	// "." is a valid alias for the root directory; cleanRelPath would
	// otherwise reject it. Normalize early.
	if dirPath == "" || dirPath == "." {
		dirPath = "."
	} else {
		clean, err := fs.cleanRelPath(dirPath)
		if err != nil {
			return nil, err
		}
		dirPath = clean
	}
	cleanDir := dirPath

	fs.mu.RLock()
	defer fs.mu.RUnlock()

	absDir := filepath.Join(fs.root, filepath.FromSlash(cleanDir))
	entries, err := os.ReadDir(absDir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrNotFound
		}
		return nil, err
	}
	out := make([]FileInfo, 0, len(entries))
	for _, e := range entries {
		// Skip internal .meta and blobs — those are the metadata store.
		if e.Name() == ".meta" || e.Name() == "blobs" {
			continue
		}
		abs := filepath.Join(absDir, e.Name())
		st, err := os.Stat(abs)
		if err != nil {
			continue
		}
		entryPath := filepath.Join(cleanDir, e.Name())
		entryPath = filepath.ToSlash(entryPath)
		entryPath = strings.TrimPrefix(entryPath, "./")
		fi := FileInfo{Name: entryPath, IsDir: st.IsDir(), ModTime: st.ModTime()}
		if !st.IsDir() {
			// Find hash for this file.
			if hash, err := fs.lookupHashForPath(entryPath); err == nil {
				if meta, err := fs.loadMeta(hash); err == nil {
					fi.Size = meta.Size
					fi.SHA256 = hash
				}
			}
		}
		out = append(out, fi)
	}
	return out, nil
}

// Mkdir creates a directory at relPath (including parents). Stub form —
// full implementation (refcount tracking, Rmdir integration) lands in Task 5.
func (fs *Filesystem) Mkdir(ctx context.Context, relPath string) error {
	cleanRel, err := fs.cleanRelPath(relPath)
	if err != nil {
		return err
	}
	fs.mu.Lock()
	defer fs.mu.Unlock()
	abs := filepath.Join(fs.root, filepath.FromSlash(cleanRel))
	return os.MkdirAll(abs, 0755)
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

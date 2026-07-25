package filesystem

import (
	"context"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	mathrand "math/rand/v2"
	"os"
	"path/filepath"
)

// fileMeta is the on-disk metadata for a blob: which names reference it.
type fileMeta struct {
	Hash    string   `json:"hash"`
	Size    int64    `json:"size"`
	Refs    []string `json:"refs"`    // relPaths that reference this blob
	Created int64    `json:"created"` // unix nano
}

// resolveBytes returns the bytes for the given source. Used by Upload.
// Precedence: File > Literal > Fill > Random.
func (fs *Filesystem) resolveBytes(src FileSource) ([]byte, error) {
	switch {
	case src.File != "":
		return fs.Read(context.Background(), src.File)
	case src.Literal != "":
		return []byte(src.Literal), nil
	case src.Fill != nil:
		if src.Fill.Bytes < 0 {
			return nil, errors.New("filesystem: Fill.Bytes must not be negative")
		}
		buf := make([]byte, src.Fill.Bytes)
		for i := range buf {
			buf[i] = src.Fill.Byte
		}
		return buf, nil
	case src.Random != nil:
		return generateRandomBytes(src.Random)
	default:
		return nil, errors.New("filesystem: FileSource has no source set")
	}
}

// generateRandomBytes produces random bytes. When Seed is non-zero, output
// is reproducible per (Seed, MinBytes, MaxBytes). When Seed is zero,
// output is crypto-random fresh on every call.
func generateRandomBytes(r *Random) ([]byte, error) {
	if r.MinBytes < 0 || r.MaxBytes < r.MinBytes {
		return nil, errors.New("filesystem: invalid Random byte range")
	}
	size := r.MinBytes
	if r.MaxBytes > r.MinBytes {
		span := r.MaxBytes - r.MinBytes
		if r.Seed != 0 {
			// Deterministic size from seeded source.
			rng := mathrand.New(mathrand.NewPCG(uint64(r.Seed), uint64(r.Seed)^0x9E3779B97F4A7C15))
			size = r.MinBytes + int(rng.IntN(span+1))
		} else {
			size = r.MinBytes + int(mathrand.IntN(span+1))
		}
	}
	buf := make([]byte, size)
	if r.Seed != 0 {
		// Seeded random for reproducibility.
		rng := mathrand.New(mathrand.NewPCG(uint64(r.Seed), uint64(r.Seed)^0x9E3779B97F4A7C15))
		for i := range buf {
			buf[i] = byte(rng.IntN(256))
		}
	} else {
		if _, err := cryptorand.Read(buf); err != nil {
			return nil, err
		}
	}
	return buf, nil
}

// hashStr returns the lowercase hex SHA-256 of b.
func hashStr(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// metaPath returns the absolute path to .meta/files/<hash>.json.
func (fs *Filesystem) metaPath(hash string) string {
	return filepath.Join(fs.root, ".meta", "files", hash+".json")
}

// blobPath returns the absolute path to blobs/<hash>.
func (fs *Filesystem) blobPath(hash string) string {
	return filepath.Join(fs.root, "blobs", hash)
}

// loadMeta reads the metadata JSON for hash. Returns ErrNotFound if missing.
func (fs *Filesystem) loadMeta(hash string) (*fileMeta, error) {
	data, err := os.ReadFile(fs.metaPath(hash))
	if os.IsNotExist(err) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	var m fileMeta
	if err := json.Unmarshal(data, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// saveMeta writes metadata JSON atomically.
func (fs *Filesystem) saveMeta(hash string, m *fileMeta) error {
	data, err := json.Marshal(m)
	if err != nil {
		return err
	}
	tmp := fs.metaPath(hash) + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return err
	}
	return os.Rename(tmp, fs.metaPath(hash))
}

// deleteMeta removes the metadata JSON. Idempotent: no error if missing.
func (fs *Filesystem) deleteMeta(hash string) error {
	err := os.Remove(fs.metaPath(hash))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}

// BlobPathForContent is a test helper that returns the absolute blob path
// for the given content. It does NOT write anything.
func (fs *Filesystem) BlobPathForContent(_ context.Context, content []byte) (string, error) {
	return fs.blobPath(hashStr(content)), nil
}

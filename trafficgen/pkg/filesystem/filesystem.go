package filesystem

import (
	"os"
	"path/filepath"
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

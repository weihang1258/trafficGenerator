package rest

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/pkg/filesystem"
)

// FilesystemHandler exposes the content-addressed filesystem over REST.
// All paths are relative to the filesystem root; the filesystem package
// validates and cleans each path (rejecting absolute paths and traversal
// escape), so the handler does not duplicate that logic.
type FilesystemHandler struct {
	fs *filesystem.Filesystem
}

// NewFilesystemHandler creates a handler bound to the given filesystem.
// fs must be non-nil; callers should not register routes when fs is nil
// (the Server guards this in setupRoutes).
func NewFilesystemHandler(fs *filesystem.Filesystem) *FilesystemHandler {
	return &FilesystemHandler{fs: fs}
}

// trimPathParam normalizes the gin wildcard param: gin's *path captures
// the leading slash, so "/docs/a.txt" becomes "docs/a.txt". The
// filesystem layer expects relative paths.
func trimPathParam(p string) string { return strings.TrimPrefix(p, "/") }

// respondFsError maps a filesystem error to the standard Response
// envelope with the appropriate HTTP status code:
//   - ErrNotFound -> 404 NotFound
//   - ErrExists / ErrNotEmpty / ErrNotADirectory -> 409 Conflict
//   - everything else -> 500 InternalError
//
// Callers that receive a non-fs error (e.g. unknown query value) should
// use BadRequest directly rather than routing through this helper.
func respondFsError(c *gin.Context, err error) {
	switch {
	case errors.Is(err, filesystem.ErrNotFound):
		NotFound(c, err.Error())
	case errors.Is(err, filesystem.ErrExists),
		errors.Is(err, filesystem.ErrNotEmpty),
		errors.Is(err, filesystem.ErrNotADirectory):
		Conflict(c, err.Error())
	default:
		InternalError(c, err.Error())
	}
}

// Upload writes a file from a JSON-described FileSource.
// POST /api/v1/fs/files/*path
// Body: filesystem.FileSource JSON (one of file/literal/fill/random).
func (h *FilesystemHandler) Upload(c *gin.Context) {
	relPath := trimPathParam(c.Param("path"))
	var src filesystem.FileSource
	if err := c.ShouldBindJSON(&src); err != nil {
		BadRequest(c, err.Error())
		return
	}
	if err := h.fs.Upload(c.Request.Context(), relPath, src); err != nil {
		respondFsError(c, err)
		return
	}
	c.Status(http.StatusCreated)
}

// Download returns the raw bytes at relPath.
// GET /api/v1/fs/files/*path?op=download
func (h *FilesystemHandler) Download(c *gin.Context) {
	relPath := trimPathParam(c.Param("path"))
	b, err := h.fs.Read(c.Request.Context(), relPath)
	if err != nil {
		respondFsError(c, err)
		return
	}
	c.Data(http.StatusOK, "application/octet-stream", b)
}

// Info returns metadata for relPath (file or directory).
// GET /api/v1/fs/files/*path?op=info
func (h *FilesystemHandler) Info(c *gin.Context) {
	relPath := trimPathParam(c.Param("path"))
	info, err := h.fs.Query(c.Request.Context(), relPath)
	if err != nil {
		respondFsError(c, err)
		return
	}
	Success(c, info)
}

// DeleteFile removes relPath from the filesystem (decreasing the blob
// refcount; the blob is deleted when no refs remain).
// DELETE /api/v1/fs/files/*path
func (h *FilesystemHandler) DeleteFile(c *gin.Context) {
	relPath := trimPathParam(c.Param("path"))
	if err := h.fs.Delete(c.Request.Context(), relPath); err != nil {
		respondFsError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// Mkdir creates a directory at relPath (including parents). Idempotent
// for existing directories; returns 409 if a file already occupies the
// path.
// POST /api/v1/fs/dirs/*path
func (h *FilesystemHandler) Mkdir(c *gin.Context) {
	relPath := trimPathParam(c.Param("path"))
	if err := h.fs.Mkdir(c.Request.Context(), relPath); err != nil {
		respondFsError(c, err)
		return
	}
	c.Status(http.StatusCreated)
}

// Rmdir deletes a directory. Without ?recursive=true, returns 409 if
// the directory is non-empty. With ?recursive=true, walks the tree and
// deletes all files and sub-directories.
// DELETE /api/v1/fs/dirs/*path?recursive=true|false
func (h *FilesystemHandler) Rmdir(c *gin.Context) {
	relPath := trimPathParam(c.Param("path"))
	recursive := c.Query("recursive") == "true"
	if err := h.fs.Rmdir(c.Request.Context(), relPath, filesystem.RmdirOptions{Recursive: recursive}); err != nil {
		respondFsError(c, err)
		return
	}
	c.Status(http.StatusNoContent)
}

// List returns entries in the directory named by ?path=. An empty or
// "." path lists the filesystem root. Internal entries (.meta, blobs)
// are filtered out by the filesystem layer.
// GET /api/v1/fs/list?path=<dir>
func (h *FilesystemHandler) List(c *gin.Context) {
	dir := c.Query("path")
	if dir == "" {
		dir = "."
	}
	entries, err := h.fs.List(c.Request.Context(), dir)
	if err != nil {
		respondFsError(c, err)
		return
	}
	Success(c, entries)
}

// Package rest provides REST API handlers.
package rest

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// Response represents a standard API response.
type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Error codes.
const (
	CodeSuccess         = 0
	CodeInvalidParam    = 400
	CodeUnauthorized    = 401
	CodeForbidden       = 403
	CodeNotFound        = 404
	CodeConflict        = 409
	CodeRateLimitExceed = 429
	CodeInternal        = 500
)

// Success returns a success response.
func Success(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: "success",
		Data:    data,
	})
}

// SuccessWithMessage returns a success response with a custom message.
func SuccessWithMessage(c *gin.Context, message string, data interface{}) {
	c.JSON(http.StatusOK, Response{
		Code:    CodeSuccess,
		Message: message,
		Data:    data,
	})
}

// Created returns a created response.
func Created(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, Response{
		Code:    CodeSuccess,
		Message: "created",
		Data:    data,
	})
}

// BadRequest returns a bad request error.
func BadRequest(c *gin.Context, message string) {
	c.JSON(http.StatusBadRequest, Response{
		Code:    CodeInvalidParam,
		Message: message,
	})
}

// Unauthorized returns an unauthorized error.
func Unauthorized(c *gin.Context, message string) {
	c.JSON(http.StatusUnauthorized, Response{
		Code:    CodeUnauthorized,
		Message: message,
	})
}

// Forbidden returns a forbidden error.
func Forbidden(c *gin.Context, message string) {
	c.JSON(http.StatusForbidden, Response{
		Code:    CodeForbidden,
		Message: message,
	})
}

// NotFound returns a not found error.
func NotFound(c *gin.Context, message string) {
	c.JSON(http.StatusNotFound, Response{
		Code:    CodeNotFound,
		Message: message,
	})
}

// Conflict returns a conflict error.
func Conflict(c *gin.Context, message string) {
	c.JSON(http.StatusConflict, Response{
		Code:    CodeConflict,
		Message: message,
	})
}

// InternalError returns an internal server error.
func InternalError(c *gin.Context, message string) {
	c.JSON(http.StatusInternalServerError, Response{
		Code:    CodeInternal,
		Message: message,
	})
}

// Error returns an error response with a custom code.
func Error(c *gin.Context, code int, message string) {
	c.JSON(http.StatusOK, Response{
		Code:    code,
		Message: message,
	})
}

// pageParams is the parsed pagination of one request.
type pageParams struct {
	Page int
	Size int // 0 = 全量（不加 LIMIT）；响应回显请走 pageEchoSize
}

// parsePageParams parses page/size for a list endpoint.
//
// 契约（客户端 2026-11-23 问题 3，全 rest 列表端点统一口径）：
//   - page 缺省/非数字/非正数 → 1
//   - size 缺省/非数字/负数 → defaultSize（垃圾输入回默认，不得静默变"全量"）
//   - size == 0 → 全量（不加 LIMIT，用户裁定 2026-10-04）
//   - size > maxSize → 收敛到 maxSize（不静默回默认）
//
// 各端点只在 defaultSize / maxSize 上不同（assets 20/200、flows 50/500、
// packets 50/500、tasks 20/100）。
func parsePageParams(c *gin.Context, defaultSize, maxSize int) pageParams {
	p := pageParams{Page: 1, Size: defaultSize}
	if v, err := strconv.Atoi(c.Query("page")); err == nil && v > 0 {
		p.Page = v
	}
	if raw := c.Query("size"); raw != "" {
		v, err := strconv.Atoi(raw)
		switch {
		case err != nil, v < 0:
			p.Size = defaultSize
		case v > maxSize:
			p.Size = maxSize
		default:
			p.Size = v // 0 = 全量
		}
	}
	return p
}

// pageEchoSize reports the `size` a paginated response should echo. size==0 is
// the request-side "everything" sentinel; echoing it alongside N items makes
// {"items":[N items],"size":0} self-contradictory, so callers that treat size
// as the page length see an empty page. Echo the actual returned count instead.
func pageEchoSize(p pageParams, returned int) int {
	if p.Size == 0 {
		return returned
	}
	return p.Size
}

// pageOffset returns (page-1)*size for a SQL OFFSET. The clamp lives in
// storage.PageOffset so the hand-built REST queries and the repository
// queries cannot drift apart.
func pageOffset(p pageParams) int {
	return storage.PageOffset(p.Page, p.Size)
}

// pageBody builds the {items,total,page,size} envelope shared by every list
// endpoint.
func pageBody(items interface{}, total int64, p pageParams, returned int) gin.H {
	return gin.H{
		"items": items,
		"total": total,
		"page":  p.Page,
		"size":  pageEchoSize(p, returned),
	}
}

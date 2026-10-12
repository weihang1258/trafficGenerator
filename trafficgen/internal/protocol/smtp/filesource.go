package smtp

import (
	"context"

	"go.uber.org/zap"

	"github.com/trafficgen/trafficgen/internal/core"
)

// applyFileSource resolves cfg.FileSource into the MIME attachment
// (D-FILE-1：smtp 文件源 = DATA 阶段附件来自文件；RFC 2045 §6.8 base64
// 由既有 Email 装配路径承担）。Email 缺省时补一封单附件邮件；有附件时
// 覆盖第一个附件的 Data（DataB64 清零——Data 优先契约）。解析失败静默
// 忽略（http.go:247 家族同款）。
func applyFileSource(ctx context.Context, cfg *core.SMTPConfig) {
	if cfg == nil || cfg.FileSource == nil {
		return
	}
	pc := core.PayloadCacheFrom(ctx)
	if pc == nil {
		return
	}
	b, err := pc.GetOrLoad(ctx, *cfg.FileSource)
	if err != nil {
		zap.L().Warn("file_source resolve failed; payload silently skipped (family contract)", zap.Error(err))
		return
	}
	if cfg.Email == nil {
		cfg.Email = &core.SMTPEmail{}
	}
	if len(cfg.Email.Attachments) == 0 {
		cfg.Email.Attachments = []core.SMTPAttachment{{}}
	}
	cfg.Email.Attachments[0] = core.SMTPAttachment{
		Filename:    "attachment.bin",
		ContentType: "application/octet-stream",
		Data:        b,
	}
}

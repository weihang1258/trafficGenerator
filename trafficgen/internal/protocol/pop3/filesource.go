package pop3

import (
	"context"

	"github.com/trafficgen/trafficgen/internal/core"
)

// applyFileSource resolves cfg.FileSource into the mailbox message body
// (D-FILE-1：pop3 文件源 = RETR 邮件体来自文件；命令序列仍由用户配置，
// emit_mail_drop 触发投递)。Mailbox 缺省时补一条单消息信箱。
// 解析失败静默忽略（与 http.go:247 家族同款——无缓存/加载失败不致命）。
func applyFileSource(ctx context.Context, cfg *core.POP3Config) {
	if cfg == nil || cfg.FileSource == nil {
		return
	}
	pc := core.PayloadCacheFrom(ctx)
	if pc == nil {
		return
	}
	b, err := pc.GetOrLoad(ctx, *cfg.FileSource)
	if err != nil {
		return
	}
	if cfg.Mailbox == nil {
		cfg.Mailbox = &core.POP3Mailbox{}
	}
	if len(cfg.Mailbox.Messages) == 0 {
		cfg.Mailbox.Messages = []core.POP3Message{{}}
	}
	cfg.Mailbox.Messages[0].Body = string(b)
	cfg.Mailbox.Messages[0].Size = 0 // planner 按头+体重算
}

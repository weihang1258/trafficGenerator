package smb

import (
	"context"

	"github.com/trafficgen/trafficgen/internal/core"
)

// applyFileSource resolves cfg.FileSource into a WRITE operation's data
// (D-FILE-1：smb 文件源 = 文件内容随 WRITE 操作落网；会话建立与
// TREE_CONNECT 等由既有状态机承担）。无 write 操作时补一条
// {op_type:"write", file_name:"file.bin"}（validate 默认 read 后追加，
// ops=[read, write]）。有 write 操作时覆盖第一个的 Data（DataB64 清零，
// Data 优先契约）。解析失败静默忽略（http.go:247 家族同款）。
func applyFileSource(ctx context.Context, cfg *SMBConfig) {
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
	for i := range cfg.Operations {
		if cfg.Operations[i].OpType == "write" {
			cfg.Operations[i].Data = b
			cfg.Operations[i].DataB64 = ""
			return
		}
	}
	cfg.Operations = append(cfg.Operations, SMBOperation{
		OpType:   "write",
		FileName: "file.bin",
		Data:     b,
	})
}

package nfs

import (
	"context"

	"github.com/trafficgen/trafficgen/internal/core"
)

// applyFileSource resolves cfg.FileSource into a WRITE operation's data
// (D-FILE-1：nfs 文件源 = 文件内容随 WRITE 落网；会话/挂载由既有流程承担)。
// v3：第一个 Procedure==NFS3ProcWRITE 的 op 覆盖 Data，无则追加
// {Procedure: WRITE, Filename: "file.bin"}。v4：Ops 内第一个携带
// OP_WRITE compound op 的覆盖其 Data。解析失败静默忽略（http.go:247 家族同款）。
func applyFileSource(ctx context.Context, cfg *NFSConfig) {
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
	for i := range cfg.Ops {
		if cfg.Ops[i].Procedure == NFS3ProcWRITE {
			cfg.Ops[i].Data = b
			return
		}
		for j := range cfg.Ops[i].CompoundOps {
			if cfg.Ops[i].CompoundOps[j].Opcode == OP_WRITE {
				cfg.Ops[i].CompoundOps[j].Data = b
				return
			}
		}
	}
	// 追加面幂等（Plan 可重入/多流共享配置：已有 file.bin write op 只改
	// Data 不重复追加）。
	for i := range cfg.Ops {
		if cfg.Ops[i].Procedure == NFS3ProcWRITE && cfg.Ops[i].Filename == "file.bin" {
			cfg.Ops[i].Data = b
			return
		}
	}
	cfg.Ops = append(cfg.Ops, NFSOp{Procedure: NFS3ProcWRITE, Filename: "file.bin", Data: b})
}

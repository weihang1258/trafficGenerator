# pkg/filesystem

独立的内容寻址文件系统（content-addressed filesystem），用于存储造流量所需的文件数据。**与造流量业务隔离**，不依赖 trafficgen 的 internal 包。

## 设计

- **去重**：相同 SHA-256 的文件只存一份（`blobs/<sha256>`）
- **多文件名映射**：`.meta/files/<sha256>.json` 的 `refs[]` 数组记录所有引用此 blob 的相对路径
- **删除语义**：删除一个文件名只删 refs[] 里的对应条目；当 refs[] 空时才删 blob
- **目录递归删除**：`Rmdir(recursive=true)` 按文件删除规则级联处理，deduped blob 在有其他 refs 时不会被删

## API

```go
fs, err := filesystem.New("/data/filesystem")

// 上传
err = fs.Upload(ctx, "docs/readme.txt", filesystem.FileSource{Literal: "hello"})

// 读取（造流量系统唯一会调的接口）
bytes, err := fs.Read(ctx, "docs/readme.txt")

// 删除
err = fs.Delete(ctx, "docs/readme.txt")

// 查询元数据
info, err := fs.Query(ctx, "docs/readme.txt")

// 列目录
entries, err := fs.List(ctx, "docs")

// 目录操作
err = fs.Mkdir(ctx, "docs/sub")
err = fs.Rmdir(ctx, "docs/sub", filesystem.RmdirOptions{Recursive: true})
```

## FileSource 数据源

| 字段 | 说明 | 缓存策略 |
|------|------|---------|
| `File` | 文件系统相对路径或绝对磁盘路径 | 缓存（按 hash dedup） |
| `Literal` | 字面字符串 | 缓存 |
| `Fill` | 单字节填充 N 字节 | 缓存 |
| `Random` (有 Seed) | 可复现的伪随机 | 缓存 |
| `Random` (无 Seed) | 真随机，每次调用不同 | 不缓存（PayloadCache 直接绕过） |

## 与造流量系统的关系

造流量侧通过 `internal/core/payloadcache.go` 调 `fs.Read(relPath)`，**只读**。协议流量中的 `FTP DELE`、`HTTP DELETE` 等命令只生成"删除命令的包"，不调 `fs.Delete`。文件系统状态由独立的 CLI/REST/MCP 入口维护。

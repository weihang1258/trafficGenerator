<!-- Generated from trafficgen/schemas/v1 by web schemagen. DO NOT EDIT. -->
<!-- Single truth: schemas/v1/*.json. This index links shapes to owners; -->
<!-- it copies no contract text. Shape conflict: schema wins. -->

# 配置 Schema 索引（生成）

唯一真相：`trafficgen/schemas/v1/`。Go 校验（`internal/core/schema/`）、
MCP 描述（`internal/mcp/schemagen` → `schema_descriptions_generated.go`）、
前端类型（`web/src/api/schema-types.ts`）都从这里派生。
本文件只做索引，不复制契约文字；形状冲突以 schema 为准。

## 文件

| 文件 | 内容 | 派生 |
|------|------|------|
| `defs.json` | flow_control / output_config / dynamic_value / tuple_config / group_id | MCP 小输入描述、前端 FlowControl/OutputConfig |
| `strategy.json` | 策略形状（synth/replay，config 平铺字段 + layers + 子配置） | REST strategy create/update 入口、MCP Config 描述 |
| `task.json` | 任务形状（strategy_ids XOR batch，任务级 flow_control 上限） | REST task create/batch/start 入口 |
| `batch.json` | 批量形状（classes[]，逐类速率/元组/回放/绑定） | REST create_batch 入口、前端 BatchSpec |

## 关键规则

- strategy 是单协议模板，自带 flow_control；task 是多策略合并，task 的 flow_control 只做总上限，不改写策略包络。
- mode=replay 时 config 只收 pcap_asset_id/speed/direction/checksum_mode，不收 layers；flow_control 只收 time。
- direction/checksum_mode 空值走引擎缺省（single/recompute），非法值由 ValidateReplaySpec 按历史文案拒绝。
- flow_control 类型只有 flows/bps/time（cps/ratio 已下线，前端选项同步移除）。
- layers 出现即走层链校验，protocol 可空由推断回填；层字段以 `flowb_query_layers` 运行时视图为准（`layers.json` 生成表待建）。


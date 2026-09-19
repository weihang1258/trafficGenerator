#!/bin/bash
# P-PIPE 提交门检查脚本（三道硬门之门 2）。
# 用法：trafficgen/tools/pipe_gate.sh <proto> [server-binary]
# 四项：1) 顶层旧键零残留 2) 用例文件全量绿由调用方另跑（本脚本只查静态形状） 3) 二进制与 HEAD 同代 4) 覆盖反查（P5R，已登记协议才查）
# 返回：全绿 exit 0，任一红 exit 1 并打印原因。
set -u
PROTO="${1:?用法: pipe_gate.sh <proto> [server-binary]}"
SERVER_BIN="${2:-/tmp/tg-http-p5-server}"
CASES="trafficgen/test/protocol_pcap/cases/${PROTO}.json"

fail=0
echo "== 门2-1 顶层旧键零残留: $CASES"
if [ ! -f "$CASES" ]; then
  echo "  红: 用例文件不存在"; fail=1
else
  # 顶层 src_ip/dst_ip/src_port/dst_port/count 任一出现即红
  hits=$(python3 - "$CASES" <<'PYEOF'
import json,sys
d = json.load(open(sys.argv[1]))
bad = []
for c in d:
    sj = c.get("spec_json", {}) or {}
    # 故意的扁平负例（expect_error + 锚词含 flat）是门 2-2 的断言对象，不算残留
    exp = c.get("expect", {}) or {}
    if exp.get("expect_error") and "flat" in str(exp.get("error_contains", "")):
        continue
    for k in ("src_ip","dst_ip","src_port","dst_port","count","src_mac","dst_mac","ttl"):
        if k in sj and sj[k] is not None:
            bad.append(c["id"] + ":" + k)
print("\n".join(bad))
PYEOF
)
  if [ -n "$hits" ]; then
    echo "  红: 顶层旧键残留:"; echo "$hits" | sed 's/^/    /'; fail=1
  else
    echo "  绿: 无顶层旧键"
  fi
  # 顶层协议子映射（如 "http" 与 layers 并存）必须登记过渡，否则红
  sub=$(python3 - "$CASES" <<'PYEOF'
import json,sys
d = json.load(open(sys.argv[1]))
bad = []
for c in d:
    sj = c.get("spec_json", {}) or {}
    if "layers" in sj:
        for k in list(sj.keys()):
            if k not in ("layers","strategy_fc","ttl","flow_control","output","output_config") and isinstance(sj[k], dict):
                bad.append(c["id"] + ":顶层子映射+" + k)
                break
print("\n".join(sorted(set(bad))))
PYEOF
)
  if [ -n "$sub" ]; then
    echo "  黄: 顶层协议子映射与 layers 并存（须在 D-条目登记过渡计划，否则红）："; echo "$sub" | sed 's/^/    /'
  else
    echo "  绿: 无顶层协议子映射并存"
  fi
  # http 族 9 协议顶层 http presence 红线（D-HTTP-1 步骤 3 + T-HTTP-72）：
  # 迁入完成后，layers 与顶层 http 子映射共存即红；唯一的例外是 presence
  # 负例本身（expect_error + error_contains 含 top-level），它是执法对象。
  # dns/mqtt/smtp/pop3/imap/mcp 单协议 presence 红线（各 D-条目 P4 判死分支同款）：
  # 口径与 http 族一致——presence 负例豁免，其余共存即红。
  case "$PROTO" in
    http|http_flv|hls|hds|gbt|getwork|cwmp|doh|onvif)
      _pres_key="http"
      ;;
    dns|mqtt|smtp|pop3|imap|mcp|srv6|fins|goose|sv)
      _pres_key="$PROTO"
      ;;
  esac
  if [ -n "${_pres_key:-}" ]; then
      pres=$(python3 - "$CASES" "$_pres_key" <<'PYEOF'
import json,sys
d = json.load(open(sys.argv[1]))
key = sys.argv[2]
bad = []
for c in d:
    sj = c.get("spec_json", {}) or {}
    if "layers" not in sj or not isinstance(sj.get(key), dict):
        continue
    exp = c.get("expect", {}) or {}
    if exp.get("expect_error") and "top-level" in str(exp.get("error_contains", "")):
        continue
    bad.append(c["id"] + ":顶层" + key + " presence")
print("\n".join(sorted(set(bad))))
PYEOF
)
      if [ -n "$pres" ]; then
        echo "  红: 顶层 ${_pres_key} presence 残留:"; echo "$pres" | sed 's/^/    /'; fail=1
      else
        echo "  绿: 无顶层 ${_pres_key} presence 残留（presence 负例豁免）"
      fi
      unset _pres_key
  fi
fi

echo "== 门2-3 二进制与 HEAD 同代"
if [ ! -x "$SERVER_BIN" ]; then
  echo "  黄: 服务二进制不存在($SERVER_BIN)，跳过（调用方须确认服务与 HEAD 同代）"
else
  newer=$(find trafficgen -name '*.go' -newer "$SERVER_BIN" 2>/dev/null | head -5)
  if [ -n "$newer" ]; then
    echo "  红: 有 .go 比服务二进制新，先重编重跑:"; echo "$newer" | sed 's/^/    /'; fail=1
  else
    echo "  绿: 二进制与 HEAD 同代"
  fi
fi

echo "== 门2-2 用例全量绿: 本脚本不跑suite（调用方跑 CASE_PROTO=$PROTO 全量，贴 RESULT 行）"
echo "== 门2-4 覆盖反查: coverage_gate.py（已登记协议才查，未登记判黄不挡路）"
if [ -f "trafficgen/tools/coverage_gate.py" ]; then
  python3 trafficgen/tools/coverage_gate.py "$PROTO" 2>&1 | tail -8
  rc=${PIPESTATUS[0]}
  if [ "$rc" -eq 0 ]; then
    echo "  绿: 覆盖反查通过"
  elif [ "$rc" -eq 2 ]; then
    echo "  黄: 该协议检查表未登记，不挡路"
  else
    echo "  红: 覆盖反查有缺口，停"; fail=1
  fi
else
  echo "  黄: coverage_gate.py 不存在，跳过"
fi
if [ "$fail" -eq 0 ]; then echo "静态四项全绿"; else echo "有红项，停"; fi
exit "$fail"

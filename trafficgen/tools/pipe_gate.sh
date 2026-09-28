#!/bin/bash
# P-PIPE 提交门检查脚本（三道硬门之门 2）。
# 用法：trafficgen/tools/pipe_gate.sh <proto> [server-binary]
# 四项：1) 顶层旧键零残留 2) 用例文件全量绿由调用方另跑（本脚本只查静态形状） 3) 二进制与 HEAD 同代 4) 覆盖反查（P5R，已登记协议才查）
# 返回：全绿 exit 0，任一红 exit 1 并打印原因。
set -u
PROTO="${1:?用法: pipe_gate.sh <proto> [server-binary]}"
# 二进制路径：位置参数 2 > 环境变量 TG_SERVER_BIN > 缺省 /tmp/tg-sv-p4-server
# （修轮残项2：原缺省 /tmp/tg-http-p5-server 是 http 时代遗留陈旧二进制，
# 不带参调用即假红门2-3——收官复验实证 EXIT=1）。
SERVER_BIN="${2:-${TG_SERVER_BIN:-/tmp/tg-sv-p4-server}}"
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
    exp = c.get("expect", {}) or {}
    anchor = str(exp.get("error_contains", ""))
    # 故意的规范负例（expect_error + 锚词含 flat / 点名该键）是门 2-2 的断言
    # 对象，不算残留。D-NFS-1 P6 修轮：ttl 越界走 ValidateConfigRanges shape
    # 门（锚词 "ttl 300 invalid..."，不含 flat），按"锚词点名键名"逐键豁免。
    for k in ("src_ip","dst_ip","src_port","dst_port","count","src_mac","dst_mac","ttl"):
        if k in sj and sj[k] is not None:
            if exp.get("expect_error") and ("flat" in anchor or k in anchor):
                continue
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
            # group_id 是框架级流绑定键（非协议旧扁平键；smb_tpos16x/
            # gbt_t117 先例），D-NFS-1/D-SMB-1 P6 修轮登记在案，不算并存残留。
            if k not in ("layers","strategy_fc","ttl","flow_control","output","output_config","group_id") and isinstance(sj[k], dict):
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
    http|http_flv|hls|hds|gbt|getwork|doh|onvif)
      _pres_key="http"
      ;;
    # D-CWMP-1：cwmp 配置已迁层（B6 注入形退役），presence 红线切自键
    # （dns/mqtt/smtp 先例；presence 负例豁免，其余顶层 cwmp 共存即红）。
    cwmp)
      _pres_key="cwmp"
      ;;
    # D-KINGBASE-1 裁定1/裁定3：协议身份退役（唯一形态=postgresql 层
    # dialect=kingbase，cases 自带 proto=postgresql）——无自键 presence 门
    # （白名单即 400，CheckProtoFlat 创建路径不可达）；游离顶层键由上方
    # 通用"顶层子映射并存"黄线覆盖，立项缺口已登记 D-条目 G5。
    kingbase)
      _pres_key=""
      ;;
    # D-MEGACO-1：megaco 配置迁层（B6 顶层注入形退役），presence 红线切自键
    # （cwmp 先例；presence 负例豁免，其余顶层 megaco 共存即红）。
    # D-NFS-1：nfs 配置迁层（顶层 nfs 交 CheckProtoFlat 判死），presence
    # 红线切自键（megaco 先例；presence 负例豁免，其余顶层 nfs 共存即红）。
    # D-TFTP-1：tftp 配置迁层（顶层 tftp 交 CheckProtoFlat 判死），presence
    # 红线切自键（nfs 先例；presence 负例豁免，其余顶层 tftp 共存即红）。
    # D-SMB-1：smb 配置迁层（顶层 smb 交 CheckProtoFlat 判死），presence
    # 红线切自键（nfs 先例；presence 负例豁免，其余顶层 smb 共存即红）。
    # D-ENIP-1：enip 配置迁层（顶层 enip 交 CheckProtoFlat 判死），presence
    # 红线切自键（megaco 先例；presence 负例豁免，其余顶层 enip 共存即红）。
    # D-BGP-1 G-BGP-6：bgp 配置迁层（顶层 bgp 交 CheckProtoFlat 判死），
    # presence 红线切自键（enip 先例；presence 负例豁免，其余顶层 bgp 共存即红）。
    # D-S7-85：s7 配置迁层（顶层 s7 交 CheckProtoFlat 判死），presence
    # 红线切自键（enip 先例；presence 负例豁免，其余顶层 s7 共存即红）。
    # D-CQL-1（G-CQL-1）：cql 配置迁层（顶层 cql 交 CheckProtoFlat 判死），
    # presence 红线切自键（enip 先例；presence 负例豁免，其余顶层 cql 共存即红）。
    # D-DOIP-1：doip 配置迁层（顶层 doip 交 CheckProtoFlat 判死），presence
    # 红线切自键（enip 先例；presence 负例豁免，其余顶层 doip 共存即红）。
    # D-DAMENG-1：dameng 配置迁层（顶层 dameng 交 CheckProtoFlat 判死），presence
    # 红线切自键（enip 先例；presence 负例豁免，其余顶层 dameng 共存即红）。
    # D-GBT32960 P4：gbt32960 配置迁层（顶层 gbt32960 交 CheckProtoFlat
    # 判死），presence 红线切自键（enip 先例；presence 负例豁免，其余顶层
    # gbt32960 共存即红）。
    # D-CFLOW-1：cflow 配置迁层（顶层 cflow 交 CheckProtoFlat 判死），presence
    # 红线切自键（enip 先例；presence 负例豁免，其余顶层 cflow 共存即红）。
    # D-IGMP-1（G-IGMP-1）：igmp 配置迁层（顶层 igmp 交 CheckProtoFlat 判死），
    # presence 红线切自键（enip 先例；presence 负例豁免，其余顶层 igmp 共存即红）。
    # D-RTMFP-1：rtmfp 配置迁层（顶层 rtmfp 交 CheckProtoFlat 判死），presence
    # 红线切自键（enip 先例；presence 负例豁免，其余顶层 rtmfp 共存即红）。
    # D-DRDA-1：drda 配置迁层（顶层 drda 交 CheckProtoFlat 判死），presence
    # 红线切自键（enip 先例；presence 负例豁免，其余顶层 drda 共存即红）。
    # D-MMS-2（G-MMS-1）：mms 配置迁层（顶层 mms 交 CheckProtoFlat 判死），
    # presence 红线切自键（enip 先例；presence 负例豁免，其余顶层 mms 共存即红）。
    # D-COAP-1（G-COAP-1②）：coap 配置迁层（顶层 coap 交 CheckProtoFlat 判死），
    # presence 红线切自键（enip 先例；presence 负例豁免，其余顶层 coap 共存即红）。
    # D-STRATUM-1（G-ST-4）：stratum 配置迁层（顶层 stratum 交 CheckProtoFlat
    # 判死），presence 红线切自键（mms 先例；presence 负例豁免，其余顶层
    # stratum 共存即红）。
    dns|mqtt|smtp|pop3|imap|mcp|srv6|fins|goose|sv|icmpv6|h323|mpls|ngap|telnet|sip|radius|pppoe|ldap|rtmp|rtsp|pptp|vnc|xmpp|sctp|jt808|jt809|jtt905|arp|icmp|megaco|hl7|mmse|nfs|tftp|smb|enip|bgp|s7|cql|doip|dameng|gbt32960|cflow|igmp|rtmfp|drda|mms|isis|coap|stratum)
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
  newer=$(find trafficgen -name '*.go' ! -name '*_test.go' -newer "$SERVER_BIN" 2>/dev/null | head -5)
  if [ -n "$newer" ]; then
    echo "  红: 有 .go 比服务二进制新，先重编重跑:"; echo "$newer" | sed 's/^/    /'; fail=1
  else
    echo "  绿: 二进制与 HEAD 同代"
  fi
fi

if [ "$PROTO" = "kingbase" ]; then
  echo "== 门2-2 用例全量绿: 本脚本不跑suite（退役口径：调用方跑 CASE_PROTO=postgresql 全量——kingbase.json 15 例自带 proto=postgresql，贴 RESULT 行）"
else
  echo "== 门2-2 用例全量绿: 本脚本不跑suite（调用方跑 CASE_PROTO=$PROTO 全量，贴 RESULT 行）"
fi
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

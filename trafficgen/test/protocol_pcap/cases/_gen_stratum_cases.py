#!/usr/bin/env python3
"""D-STRATUM-1 G-ST-1 用例整形（40 例，形状 only——行式 JSON 载荷字节不动）。

每例：顶层 4 扁平键（src_ip/dst_ip/src_port/dst_port）搬入 layers[ip]/layers[tcp]，
顶层 stratum 子映射搬入 layers[] stratum 条目；29 正例补 flow_control.flows=1
（负例不补，保持 expect 纯净）。业务 sessions[]/events[] 逐字保留（载荷字节
不动 → G-ST-7 en1 区分度与 §3 订阅对标 pending-suite，不在此改值）。

两处形状例外（设计 §7 表 + G-ST-2/G-ST-6）：
  - stratum_rst_pool_kick：stratum 级 termination:"rst" 为死键（struct 无此键，
    严格解码后即拒）→ 删；终止行为由 tcp 层 rst:true 承载（契约 §2.3）。
  - stratum_neg_carrier：[ip,stratum] 缺 tcp → 删 wire_fault 注入，改由
    G-ST-6 链面自然守卫拒（锚词 carrier 同字面）。
"""
import json
import collections

SRC = "test/protocol_pcap/cases/stratum.json"
NEG_CARRIER = "stratum_neg_carrier"
RST_CASE = "stratum_rst_pool_kick"


def ordered(items=None):
    """稳定键序 dict（json.dump 保插入序）。"""
    return collections.OrderedDict(items) if items is not None else collections.OrderedDict()


def transform(case):
    sj = case["spec_json"]
    # 幂等护栏：已整形（纯 layers 形，无顶层扁平键/顶层 stratum 子映射）时
    # 原样返回——否则二次运行会把层内 stratum 配置读成 {} 而抹掉业务载荷。
    if set(sj.keys()) <= {"layers", "flow_control"}:
        return case
    old_layers = sj.get("layers", [])
    top_stratum = sj.get("stratum") or {}
    src_ip, dst_ip = sj.get("src_ip"), sj.get("dst_ip")
    src_port, dst_port = sj.get("src_port"), sj.get("dst_port")

    # 既有层条目（ip 可能已显式写 v6 / tcp 可能带 concurrent|rst|dst_port）。
    ip_cfg = {}
    tcp_cfg = {}
    other = []
    for item in old_layers:
        if "ip" in item:
            ip_cfg = dict(item["ip"])
        elif "tcp" in item:
            tcp_cfg = dict(item["tcp"])
        elif "stratum" in item:
            pass  # 空条目丢弃，重建
        else:
            other.append(item)

    # ip：显式层值优先，缺席回填扁平地址（G-ST-1 去向表）。
    if src_ip is not None and "src" not in ip_cfg:
        ip_cfg = ordered([("src", src_ip)] + list(ip_cfg.items()))
    if dst_ip is not None and "dst" not in ip_cfg:
        ip_cfg["dst"] = dst_ip
    ip_cfg = ordered([(k, ip_cfg[k]) for k in ("src", "dst") if k in ip_cfg]
                     + [(k, v) for k, v in ip_cfg.items() if k not in ("src", "dst")])

    # tcp：端口真相进层（扁平 src_port/dst_port 搬入；既有层值优先）。
    new_tcp = ordered()
    if src_port is not None and "src_port" not in tcp_cfg:
        new_tcp["src_port"] = src_port
    if dst_port is not None and "dst_port" not in tcp_cfg:
        new_tcp["dst_port"] = dst_port
    for k in ("src_port", "dst_port", "concurrent", "rst"):
        if k in tcp_cfg:
            new_tcp[k] = tcp_cfg[k]
    for k, v in tcp_cfg.items():
        if k not in new_tcp:
            new_tcp[k] = v

    # stratum 条目：业务配置整体搬入；死键 termination 删（G-ST-2）。
    st = ordered([(k, v) for k, v in top_stratum.items() if k != "termination"])

    layers = [ordered([("ip", ip_cfg)]), ordered([("tcp", new_tcp)])] + other
    layers.append(ordered([("stratum", st)]))

    new_sj = ordered([("layers", layers)])

    # 载体负例：删 wire_fault，改由链面自然守卫（G-ST-6）。
    if case["id"] == NEG_CARRIER:
        new_sj = ordered([("layers", [
            ordered([("ip", ip_cfg)]),
            ordered([("stratum", ordered({}))]),
        ])])

    is_neg = bool((case.get("expect") or {}).get("expect_error"))
    if not is_neg:
        new_sj["flow_control"] = ordered([("flows", 1)])

    out = ordered()
    for k in ("id", "proto", "summary", "spec_json", "expect", "notes"):
        if k in case:
            out[k] = new_sj if k == "spec_json" else case[k]
    return out


def main():
    with open(SRC) as f:
        cases = json.load(f, object_pairs_hook=collections.OrderedDict)
    assert len(cases) == 40, len(cases)
    out = [transform(c) for c in cases]
    with open(SRC, "w") as f:
        json.dump(out, f, indent=1, ensure_ascii=False)
        f.write("\n")
    # 收官自查：非负例顶层键 = {layers, flow_control}。
    bad = [(c["id"], sorted(c["spec_json"].keys())) for c in out
           if not (c.get("expect") or {}).get("expect_error")
           and set(c["spec_json"].keys()) != {"layers", "flow_control"}]
    print("非负例顶层键违规:", bad or "零违规")
    neg_bad = [(c["id"], sorted(c["spec_json"].keys())) for c in out
               if (c.get("expect") or {}).get("expect_error")
               and set(c["spec_json"].keys()) != {"layers"}]
    print("负例顶层键违规:", neg_bad or "零违规")
    for c in out:
        if c["id"] == RST_CASE:
            print("RST 例 stratum 键:", sorted(c["spec_json"]["layers"][2]["stratum"].keys()))
        if c["id"] == NEG_CARRIER:
            print("载体负例 layers:", [list(l.keys())[0] for l in c["spec_json"]["layers"]])


if __name__ == "__main__":
    main()

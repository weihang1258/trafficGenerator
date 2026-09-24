package dcerpc

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

// 用例生成器（一次性，D-DCERPC-1 P5）：按用例文档 §2 权威序产出 80 例
// （48 正 + 32 负）。正例帧断言取自全链真实回放（BuildLayersPlanner→Plan，
// 与套件同路径——单权威，无重复编码）。先跑后钉：tshark dcerpc 字段渲染
// 若与实测不符，P5 round-1 校准本文件并重跑生成。EPM 接口用真 epm_Lookup
// stub（inq/max/NULL tower/entry_handle），tshark epm 子分refresh器可解。

type fld struct {
	Packet   int
	Field    string
	Value    string
	Same     int
	Distinct []string
	Exclude  []string
}

func (f fld) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "field": f.Field}
	if f.Value != "" {
		m["value"] = f.Value
	}
	if f.Same > 0 {
		m["same_as_packet"] = f.Same
	}
	if len(f.Distinct) > 0 {
		m["distinct_values"] = f.Distinct
	}
	if len(f.Exclude) > 0 {
		m["distinct_exclude"] = f.Exclude
	}
	return m
}

type fr struct {
	Packet int
	Offset int
	Hex    string
}

func (f fr) m() map[string]interface{} {
	m := map[string]interface{}{"packet": f.Packet, "hex": f.Hex}
	if f.Offset != 0 {
		m["offset"] = f.Offset
	}
	return m
}

type posCase struct {
	id       string
	summary  string
	layers   []interface{}
	count    int
	fields   []fld
	frames   []fr
	decodeAs []string
}

type negCase struct {
	id      string
	summary string
	layers  []interface{}
	anchor  string
}

const (
	dceCli   = "192.0.2.63"
	dceSrv   = "198.51.100.63"
	dceCli6  = "2001:db8::63"
	dceSrv6  = "2001:db8:ffff::63"
	epmUUID  = "e1af8308-5d1f-11c9-91a4-08002b14a0fa" // EPM v3.0
	ndrUUID  = "8a885d04-1ceb-11c9-9fe8-08002b104860" // NDR v2.0
	genAUUID = "5ca1ab1e-dead-beef-0000-000000000001" // 未注册接口（stub opaque；勿用 12345678-… 真实 SPOOLSS UUID）
	genBUUID = "0a0b0c0d-0e0f-1112-1314-15161718191a" // 第二接口
	rawUUID  = "01020304-0506-0708-090a-0b0c0d0e0f10" // 编码权威例
	sport    = 40063
)

func ipLayer(src, dst string) map[string]interface{} {
	return map[string]interface{}{"ip": map[string]interface{}{"src": src, "dst": dst}}
}
func tcpLayer(dport int) map[string]interface{} {
	return map[string]interface{}{"tcp": map[string]interface{}{"src_port": sport, "dst_port": dport}}
}
func dceLayer(cfg map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"dcerpc": cfg}
}

func ctx(id int, abs string, avMaj int, syn string) map[string]interface{} {
	return map[string]interface{}{
		"context_id":       id,
		"abstract":         abs,
		"abstract_version": []interface{}{avMaj, 0},
		"syntaxes": []interface{}{map[string]interface{}{
			"uuid": syn, "version": []interface{}{2, 0}}},
	}
}

// epmCtx EPM 接口 context（abstract_version 3.0）。
func epmCtx(id int) map[string]interface{} { return ctx(id, epmUUID, 3, ndrUUID) }

func bindEv(ctxs ...map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"kind": "bind", "contexts": toIface(ctxs)}
}
func toIface(ms []map[string]interface{}) []interface{} {
	out := make([]interface{}, len(ms))
	for i, m := range ms {
		out[i] = m
	}
	return out
}

func ackRespond(sec string, results ...map[string]interface{}) map[string]interface{} {
	r := map[string]interface{}{"ack": "bind_ack"}
	if sec != "" {
		r["secondary"] = sec
	}
	r["results"] = toIface(results)
	return r
}
func ackResult(ctxID, res int) map[string]interface{} {
	return map[string]interface{}{"context_id": ctxID, "result": res, "reason": 0,
		"uuid": ndrUUID, "version": []interface{}{2, 0}}
}

// epmLookupStub epm_Lookup(opnum 2) 请求 stub（wireshark epm 分解序实证）：
// inq_type(4)+object unique ptr(4)+interface unique ptr(4)+version_option(4)
// +entry_handle 上下文句柄(20B)——全 NULL/零 = 36B 全零。
const epmLookupStub = "0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000" // 40B：inq4+obj ptr4+iface ptr4+veropt4+handle20+max_towers4

// epmTowerlessStub lookup 应答（无 tower 形态）：entry_handle(20B) +
// num_towers(4)=0 + 数组一致性 max_count(4)=0。
const epmTowerlessStub = "0000000000000000000000000000000000000000" +
	"00000000" + "000000000000000000000000" + "00000000" // handle20+num0+ucarray(max,off,act)+rc4

// sess 单会话（可覆盖 prebound/dst_port）。
func sess(events ...interface{}) map[string]interface{} {
	return map[string]interface{}{"events": events}
}
func preSess(events ...interface{}) map[string]interface{} {
	return map[string]interface{}{"prebound": true, "events": events}
}

func chain(cfg map[string]interface{}) []interface{} {
	return []interface{}{ipLayer(dceCli, dceSrv), tcpLayer(135), dceLayer(cfg)}
}
func chain6(cfg map[string]interface{}) []interface{} {
	return []interface{}{ipLayer(dceCli6, dceSrv6), tcpLayer(135), dceLayer(cfg)}
}
func chainPort(port int, cfg map[string]interface{}) []interface{} {
	return []interface{}{ipLayer(dceCli, dceSrv), tcpLayer(port), dceLayer(cfg)}
}

func planChain(t *testing.T, layersArr []interface{}) []core.PacketConfig {
	t.Helper()
	raw, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := layers.BuildLayersPlanner("dcerpc", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: dceCli, DstIP: dceSrv, SrcPort: sport, DstPort: 135}
	if len(layersArr) > 0 {
		if ip, ok := layersArr[0].(map[string]interface{})["ip"].(map[string]interface{}); ok {
			spec.SrcIP, spec.DstIP = ip["src"].(string), ip["dst"].(string)
		}
	}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts
}

// TCP 载体帧计数公式：3 握手 + 数据帧 + 4 挥手（每会话）。
func frameAsserts(t *testing.T, pkts []core.PacketConfig, specs []fr) []fr {
	t.Helper()
	out := make([]fr, 0, len(specs))
	for _, sp := range specs {
		if sp.Packet > len(pkts) {
			t.Fatalf("frame %d out of range (%d packets)", sp.Packet, len(pkts))
		}
		payload := pkts[sp.Packet-1].Payload
		// Offset = pcap 帧内绝对偏移（IPv4 TCP 载体起点 54）；0 = payload 前缀。
		idx := 0
		if sp.Offset > 54 {
			idx = sp.Offset - 54
		}
		ln := len(sp.Hex) / 2
		if idx+ln > len(payload) {
			t.Fatalf("frame %d: pin at %d+%d exceeds payload %d", sp.Packet, idx, ln, len(payload))
		}
		h := strings.ToUpper(hex.EncodeToString(payload[idx : idx+ln]))
		if h != sp.Hex {
			t.Fatalf("frame %d@%d: wire %s does not match pin %s", sp.Packet, idx, h, sp.Hex)
		}
		out = append(out, fr{Packet: sp.Packet, Offset: sp.Offset, Hex: sp.Hex})
	}
	return out
}

func TestGenerateDCERPCCases(t *testing.T) {
	var positives []posCase

	add := func(id, summary string, layersArr []interface{}, count int, fields []fld, framePins []fr, decodeAs ...string) {
		pkts := planChain(t, layersArr)
		if len(pkts) != count {
			t.Fatalf("%s: rendered %d packets, contract pins %d", id, len(pkts), count)
		}
		frames := frameAsserts(t, pkts, framePins)
		positives = append(positives, posCase{id: id, summary: summary, layers: layersArr, count: count, fields: fields, frames: frames, decodeAs: decodeAs})
	}

	// request 便捷构造。
	reqResp := func(extra map[string]interface{}, respStub string) []interface{} {
		m := map[string]interface{}{"kind": "request", "context_id": 0, "opnum": 0}
		for k, v := range extra {
			m[k] = v
		}
		m["respond"] = map[string]interface{}{"ack": "response", "stub": respStub}
		return []interface{}{m}
	}

	// —— 簇①：双 profile×地址族（1-4）——
	epmBind := func() []interface{} {
		return []interface{}{map[string]interface{}{
			"kind": "bind", "contexts": toIface([]map[string]interface{}{epmCtx(0)}),
			"respond": ackRespond("135", ackResult(0, 0))}}
	}
	epmLookup := func(respStub string) interface{} {
		return map[string]interface{}{"kind": "request", "context_id": 0, "opnum": 2,
			"stub":    epmLookupStub,
			"respond": map[string]interface{}{"ack": "response", "stub": respStub}}
	}
	add("dcerpc_epm_ipv4_bind_lookup", "TCP/135 EPM bind→lookup→response 基线（IPv4）",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(append(epmBind(), epmLookup(epmTowerlessStub))...)}}), 11,
		[]fld{
			{4, "dcerpc.pkt_type", "11", 0, nil, nil},
			{4, "dcerpc.cn_bind_to_uuid", epmUUID, 0, nil, nil},
			{5, "dcerpc.pkt_type", "12", 0, nil, nil},
			{5, "dcerpc.cn_sec_addr", "135", 0, nil, nil},
			{6, "dcerpc.pkt_type", "0", 0, nil, nil},
			{6, "dcerpc.opnum", "2", 0, nil, nil},
			{7, "dcerpc.pkt_type", "2", 0, nil, nil},
			{6, "dcerpc.cn_call_id", "2", 0, nil, nil},
		},
		[]fr{{4, 54, "05000B0310000000"}})

	add("dcerpc_epm_ipv6_bind_lookup", "IPv6 独立 EPM session（ipv6.nxt=6）",
		chain6(map[string]interface{}{"sessions": []interface{}{
			sess(append(epmBind(), epmLookup(epmTowerlessStub))...)}}), 11,
		[]fld{
			{1, "ipv6.nxt", "6", 0, nil, nil},
			{4, "dcerpc.pkt_type", "11", 0, nil, nil},
			{6, "dcerpc.opnum", "2", 0, nil, nil},
			{7, "dcerpc.pkt_type", "2", 0, nil, nil},
		},
		nil)

	// dynamic：sess2 显式 4135 prebound 调用（genA 接口 stub opaque）。
	dynamic2 := func() map[string]interface{} {
		return map[string]interface{}{"sessions": []interface{}{
			sess(append(epmBind(), epmLookup(epmTowerlessStub))...),
			map[string]interface{}{"dst_port": 4135, "prebound": true,
				"events": reqResp(map[string]interface{}{"opnum": 0, "stub": "0102"}, "0102")}},
		}
	}
	add("dcerpc_dynamic_ipv4_profile", "EPM 查询→动态端口（4135 显式）独立 session 调用",
		chain(dynamic2()), 20,
		[]fld{
			{4, "dcerpc.pkt_type", "11", 0, nil, nil},
			{6, "dcerpc.opnum", "2", 0, nil, nil},
			{11, "dcerpc.pkt_type", "0", 0, nil, nil},
			{12, "dcerpc.pkt_type", "2", 0, nil, nil},
			{4, "tcp.dstport", "135", 0, nil, nil},
			{11, "tcp.dstport", "4135", 0, nil, nil},
		},
		nil, "tcp.port==4135,dcerpc")

	add("dcerpc_dynamic_ipv6_profile", "同上 IPv6",
		[]interface{}{ipLayer(dceCli6, dceSrv6), tcpLayer(135), dceLayer(dynamic2())}, 20,
		[]fld{
			{1, "ipv6.nxt", "6", 0, nil, nil},
			{11, "dcerpc.pkt_type", "0", 0, nil, nil},
			{12, "dcerpc.pkt_type", "2", 0, nil, nil},
		},
		nil, "tcp.port==4135,dcerpc")

	// —— 簇②：common header 七型混排（5）——
	add("dcerpc_common_header_fields", "七型 PDU 混排：ver/type/flags/drep/frag/call_id 逐字段",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(
				map[string]interface{}{
					"kind":     "bind",
					"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)}),
					"respond":  ackRespond("", ackResult(0, 0))},
				map[string]interface{}{
					"kind":     "alter_ctx",
					"contexts": toIface([]map[string]interface{}{ctx(1, genBUUID, 1, ndrUUID)}),
					"respond": map[string]interface{}{"ack": "alter_ctx_resp",
						"results": toIface([]map[string]interface{}{ackResult(1, 0)})}},
				map[string]interface{}{"kind": "request", "context_id": 0, "opnum": 1,
					"respond": map[string]interface{}{"ack": "response"}},
				map[string]interface{}{"kind": "request", "context_id": 0, "opnum": 2,
					"respond": map[string]interface{}{"ack": "fault", "status": 5}},
			)}}), 15,
		[]fld{
			{4, "dcerpc.ver", "5", 0, nil, nil},
			{4, "dcerpc.ver_minor", "0", 0, nil, nil},
			{4, "dcerpc.pkt_type", "11", 0, nil, nil},
			{4, "dcerpc.drep.byteorder", "1", 0, nil, nil},
			{4, "dcerpc.cn_flags.first_frag", "1", 0, nil, nil},
			{5, "dcerpc.pkt_type", "12", 0, nil, nil},
			{6, "dcerpc.pkt_type", "14", 0, nil, nil},
			{7, "dcerpc.pkt_type", "15", 0, nil, nil},
			{8, "dcerpc.pkt_type", "0", 0, nil, nil},
			{9, "dcerpc.pkt_type", "2", 0, nil, nil},
			{11, "dcerpc.pkt_type", "3", 0, nil, nil},
			{4, "dcerpc.cn_call_id", "1", 0, nil, nil},
			{8, "dcerpc.cn_call_id", "3", 0, nil, nil},
			{11, "dcerpc.cn_call_id", "4", 0, nil, nil},
		},
		[]fr{{4, 54, "05000B0310000000"}})

	// —— 簇③：BIND 变体（6-11）——
	add("dcerpc_bind_multi_context", "一 BIND 双 context+双 transfer syntax、result 逐项对应",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(map[string]interface{}{
				"kind": "bind",
				"contexts": toIface([]map[string]interface{}{
					ctx(0, genAUUID, 1, ndrUUID),
					ctx(1, genBUUID, 2, ndrUUID)}),
				"respond": ackRespond("", ackResult(0, 0), ackResult(1, 0))})}}), 9,
		[]fld{
			{4, "dcerpc.cn_num_ctx_items", "2", 0, nil, nil},
			{4, "dcerpc.cn_bind_to_uuid", genAUUID + "," + genBUUID, 0, nil, nil},
			{5, "dcerpc.cn_num_results", "2", 0, nil, nil},
			{5, "dcerpc.cn_ack_result", "0,0", 0, nil, nil},
		},
		nil)

	add("dcerpc_bind_single_context_min", "最小合法 BIND（单 ctx 单 syntax）",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(map[string]interface{}{
				"kind":     "bind",
				"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)})})}}), 8,
		[]fld{
			{4, "dcerpc.pkt_type", "11", 0, nil, nil},
			{4, "dcerpc.cn_num_ctx_items", "1", 0, nil, nil},
			{4, "dcerpc.cn_frag_len", "72", 0, nil, nil},
		},
		[]fr{{4, 54, "05000B03100000004800000001000000"}})

	add("dcerpc_bind_ack_secondary_address", "secondary address \"1025\" 长度前缀+对齐",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(map[string]interface{}{
				"kind":     "bind",
				"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)}),
				"respond":  ackRespond("1025", ackResult(0, 0))})}}), 9,
		[]fld{
			{5, "dcerpc.pkt_type", "12", 0, nil, nil},
			{5, "dcerpc.cn_sec_addr", "1025", 0, nil, nil},
			{5, "dcerpc.cn_sec_addr_len", "4", 0, nil, nil},
		},
		nil)

	add("dcerpc_bind_ack_secondary_empty", "secondary address 空串形态",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(map[string]interface{}{
				"kind":     "bind",
				"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)}),
				"respond":  ackRespond("", ackResult(0, 0))})}}), 9,
		[]fld{
			{5, "dcerpc.cn_sec_addr_len", "0", 0, nil, nil},
		},
		nil)

	add("dcerpc_bind_ack_rejected_result", "result=2 provider rejection 传播",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(map[string]interface{}{
				"kind":     "bind",
				"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)}),
				"respond":  ackRespond("", ackResult(0, 2))})}}), 9,
		[]fld{
			{5, "dcerpc.cn_ack_result", "2", 0, nil, nil},
		},
		nil)

	add("dcerpc_bind_ack_assoc_group", "assoc_group_id 显式值回带（ack assoc 777=0x309）",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(map[string]interface{}{
				"kind": "bind", "assoc_group": 777,
				"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)}),
				"respond":  ackRespond("", ackResult(0, 0))})}}), 9,
		[]fld{
			{4, "dcerpc.cn_assoc_group", "0x00000309", 0, nil, nil},
			{5, "dcerpc.cn_assoc_group", "0x00000309", 0, nil, nil},
		},
		nil)

	// —— 簇④：ALTER（12-13）——
	altBase := func(resp map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"sessions": []interface{}{sess(
			map[string]interface{}{
				"kind":     "bind",
				"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)}),
				"respond":  ackRespond("", ackResult(0, 0)),
			},
			map[string]interface{}{
				"kind":     "alter_ctx",
				"contexts": toIface([]map[string]interface{}{ctx(1, genBUUID, 1, ndrUUID)}),
				"respond":  resp,
			})}}
	}
	add("dcerpc_alter_context", "已绑定 association 新增 context→ALTER_RESP",
		chain(altBase(map[string]interface{}{"ack": "alter_ctx_resp",
			"results": toIface([]map[string]interface{}{ackResult(1, 0)})})), 11,
		[]fld{
			{6, "dcerpc.pkt_type", "14", 0, nil, nil},
			{6, "dcerpc.cn_ctx_id", "1", 0, nil, nil},
			{7, "dcerpc.pkt_type", "15", 0, nil, nil},
		},
		nil)

	add("dcerpc_alter_context_resp_reject", "ALTER_RESP rejected→该 context 后续拒（负例侧呼应）",
		chain(altBase(map[string]interface{}{"ack": "alter_ctx_resp",
			"results": toIface([]map[string]interface{}{ackResult(1, 2)})})), 11,
		[]fld{
			{7, "dcerpc.cn_ack_result", "2", 0, nil, nil},
		},
		nil)

	// —— 簇⑤：调用与 FAULT（14-15）——
	add("dcerpc_request_response_ndr", "REQUEST/RESPONSE call_id 同值、opnum、NDR scalar+struct",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(map[string]interface{}{
				"kind": "request", "context_id": 0, "opnum": 5, "alloc_hint": 16,
				"stub":    "443322110a001e00",
				"respond": map[string]interface{}{"ack": "response", "stub": "44332211"}})}}), 9,
		[]fld{
			{4, "dcerpc.pkt_type", "0", 0, nil, nil},
			{4, "dcerpc.opnum", "5", 0, nil, nil},
			{4, "dcerpc.cn_alloc_hint", "16", 0, nil, nil},
			{4, "dcerpc.cn_call_id", "1", 0, nil, nil},
			{5, "dcerpc.pkt_type", "2", 0, nil, nil},
			{5, "dcerpc.cn_call_id", "1", 0, nil, nil},
		},
		nil)

	add("dcerpc_fault_status", "REQUEST→FAULT status、call 终态",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(map[string]interface{}{
				"kind": "request", "context_id": 0, "opnum": 0,
				"respond": map[string]interface{}{"ack": "fault", "status": 5}})}}), 9,
		[]fld{
			{4, "dcerpc.pkt_type", "0", 0, nil, nil},
			{5, "dcerpc.pkt_type", "3", 0, nil, nil},
			{5, "dcerpc.cn_status", "0x00000005", 0, nil, nil},
		},
		nil)

	// —— 簇⑥：NDR stub 面（16-21，未知接口 stub opaque，帧 hex 权威）——
	add("dcerpc_ndr_pointer_array_union", "pointer referent+conformant array 三计数+union 单 arm",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(map[string]interface{}{
				"kind": "request", "context_id": 0, "opnum": 0,
				"stub":    "01000000" + "03000000" + "00000000" + "03000000" + "010002000300" + "01000000" + "0a000000",
				"respond": map[string]interface{}{"ack": "response", "stub": "01000000"}})}}), 9,
		[]fld{{4, "dcerpc.pkt_type", "0", 0, nil, nil}},
		[]fr{{4, 54, "05000003100000003600000001000000000000000000000001000000030000000000000003000000010002000300010000000A000000"}})

	add("dcerpc_ndr_scalars_hyper", "8B hyper 对齐/LE",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(reqResp(map[string]interface{}{"stub": "0123456789abcdef"}, "0123456789abcdef")...)}}), 9,
		[]fld{{4, "dcerpc.cn_frag_len", "32", 0, nil, nil}},
		[]fr{{4, 54, "0500000310000000200000000100000000000000000000000123456789ABCDEF"}})

	add("dcerpc_ndr_utf16_string", "UTF-16 max/offset/actual 2B code unit",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(reqResp(map[string]interface{}{"stub": "030000000000000003000000410042004300"}, "")...)}}), 9,
		[]fld{{4, "dcerpc.cn_frag_len", "42", 0, nil, nil}},
		[]fr{{4, 54, "05000003100000002A000000010000000000000000000000030000000000000003000000410042004300"}})

	add("dcerpc_ndr_conformant_array", "max/offset/actual+元素 LE",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(reqResp(map[string]interface{}{"stub": "04000000000000000400000001000000020000000300000004000000"}, "")...)}}), 9,
		[]fld{{4, "dcerpc.cn_frag_len", "52", 0, nil, nil}},
		[]fr{{4, 54, "05000003100000003400000001000000000000000000000004000000000000000400000001000000020000000300000004000000"}})

	add("dcerpc_ndr_unique_pointer_null", "referent=0 NULL 语义",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(reqResp(map[string]interface{}{"stub": "0000000005000000"}, "")...)}}), 9,
		[]fld{{4, "dcerpc.cn_frag_len", "32", 0, nil, nil}},
		[]fr{{4, 54, "0500000310000000200000000100000000000000000000000000000005000000"}})

	add("dcerpc_ndr_struct_padding", "尾部 padding 计入 stub",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(reqResp(map[string]interface{}{"stub": "2b000000000000000102030405060708"}, "")...)}}), 9,
		[]fld{{4, "dcerpc.cn_frag_len", "40", 0, nil, nil}},
		[]fr{{4, 54, "0500000310000000280000000100000000000000000000002B000000000000000102030405060708"}})

	// —— 簇⑦：auth（22-24）——
	add("dcerpc_auth_trailer_opaque", "auth_len>0、pad/trailer 闭合、opaque credentials",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(
				map[string]interface{}{
					"kind":     "bind",
					"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)}),
					"respond":  ackRespond("", ackResult(0, 0)),
					"auth":     map[string]interface{}{"type": 9, "level": 2, "context_id": 0, "credentials": "deadbeef"}},
				map[string]interface{}{
					"kind": "request", "context_id": 0, "opnum": 0, "stub": "aabbccdd",
					"auth": map[string]interface{}{"type": 9, "level": 2, "context_id": 0, "credentials": "deadbeef"}})}}), 10,
		[]fld{{6, "dcerpc.pkt_type", "0", 0, nil, nil}},
		[]fr{{6, 54, "050000031000000026000A00020000000000000000000000AABBCCDD090200000000DEADBEEF"}})

	add("dcerpc_auth_pad_2bytes", "pad=2 与实际填充一致",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(
				map[string]interface{}{
					"kind":     "bind",
					"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)}),
					"respond":  ackRespond("", ackResult(0, 0)),
					"auth":     map[string]interface{}{"type": 9, "level": 2, "context_id": 0, "credentials": "cafe"}},
				map[string]interface{}{
					"kind": "request", "context_id": 0, "opnum": 0, "stub": "aabbccddeeff",
					"auth": map[string]interface{}{"type": 9, "level": 2, "pad": 2, "context_id": 0, "credentials": "cafe"}})}}), 10,
		[]fld{{6, "dcerpc.pkt_type", "0", 0, nil, nil}},
		[]fr{{6, 54, "050000031000000028000800020000000000000000000000AABBCCDDEEFF0000090202000000CAFE"}})

	add("dcerpc_auth_type_level_variants", "type/level 组合矩阵代表值",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(
				map[string]interface{}{
					"kind":     "bind",
					"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID), ctx(1, genBUUID, 1, ndrUUID)}),
					"respond":  ackRespond("", ackResult(0, 0), ackResult(1, 0)),
					"auth":     map[string]interface{}{"type": 9, "level": 2, "context_id": 0, "credentials": "beef"}},
				map[string]interface{}{
					"kind": "request", "context_id": 0, "opnum": 0, "stub": "aa",
					"auth": map[string]interface{}{"type": 9, "level": 2, "pad": 3, "context_id": 0, "credentials": "beef"}},
				map[string]interface{}{
					"kind": "request", "context_id": 1, "opnum": 1, "stub": "bb",
					"auth": map[string]interface{}{"type": 10, "level": 6, "pad": 3, "context_id": 1, "credentials": "feedface"}})}}), 11,
		[]fld{
			{6, "dcerpc.pkt_type", "0", 0, nil, nil},
			{7, "dcerpc.pkt_type", "0", 0, nil, nil},
		},
		nil)

	// —— 簇⑨：多会话多调用（25）——
	bind2ctx := map[string]interface{}{
		"kind":     "bind",
		"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID), ctx(1, genBUUID, 1, ndrUUID)}),
		"respond":  ackRespond("", ackResult(0, 0), ackResult(1, 0)),
	}
	reqCtx := func(c, op int) interface{} {
		return map[string]interface{}{"kind": "request", "context_id": c, "opnum": op,
			"respond": map[string]interface{}{"ack": "response"}}
	}
	add("dcerpc_multi_context_call_session", "2 session×2 ctx×并发 2 call 隔离",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(bind2ctx, reqCtx(0, 1), reqCtx(1, 2)),
			map[string]interface{}{"dst_port": 4135,
				"events": []interface{}{bind2ctx, reqCtx(0, 1), reqCtx(1, 2)}},
		}}), 26,
		[]fld{
			{4, "dcerpc.cn_call_id", "1", 0, nil, nil},
			{6, "dcerpc.cn_call_id", "2", 0, nil, nil},
			{6, "dcerpc.cn_ctx_id", "0", 0, nil, nil},
			{8, "dcerpc.cn_call_id", "3", 0, nil, nil},
			{8, "dcerpc.cn_ctx_id", "1", 0, nil, nil},
			{15, "dcerpc.cn_call_id", "2", 0, nil, nil},
		},
		nil, "tcp.port==4135,dcerpc")

	// —— 簇⑧：分片与多 PDU（26-28）——
	add("dcerpc_fragment_first_last", "REQUEST 拆 2 片 FIRST/LAST+重组",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(map[string]interface{}{
				"kind": "request", "context_id": 0, "opnum": 0, "fragments": 2,
				"stub": "0011223344556677"})}}), 9,
		[]fld{
			{4, "dcerpc.cn_flags.first_frag", "1", 0, nil, nil},
			{4, "dcerpc.cn_flags.last_frag", "0", 0, nil, nil},
			{5, "dcerpc.cn_flags.first_frag", "0", 0, nil, nil},
			{5, "dcerpc.cn_flags.last_frag", "1", 0, nil, nil},
			{4, "dcerpc.cn_call_id", "1", 0, nil, nil},
			{5, "dcerpc.cn_call_id", "1", 0, nil, nil},
		},
		[]fr{{4, 54, "05000001100000001C00000001000000"}, {5, 54, "05000002100000001C00000001000000"}})

	add("dcerpc_fragment_three_pieces", "3 片（首/中/末）flags 矩阵",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(map[string]interface{}{
				"kind": "request", "context_id": 0, "opnum": 0, "fragments": 3,
				"stub": "001122334455667788"})}}), 10,
		[]fld{
			{4, "dcerpc.cn_flags.first_frag", "1", 0, nil, nil},
			{5, "dcerpc.cn_flags.first_frag", "0", 0, nil, nil},
			{5, "dcerpc.cn_flags.last_frag", "0", 0, nil, nil},
			{6, "dcerpc.cn_flags.last_frag", "1", 0, nil, nil},
		},
		[]fr{{5, 54, "05000000100000001B00000001000000"}})

	add("dcerpc_multi_pdu_back_to_back", "多 PDU 背靠背（PDU≠TCP record 观察面）",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(append(
				reqResp(map[string]interface{}{"opnum": 1}, ""),
				reqResp(map[string]interface{}{"opnum": 2}, "")...)...)}}), 11,
		[]fld{
			{4, "dcerpc.pkt_type", "0", 0, nil, nil},
			{5, "dcerpc.pkt_type", "2", 0, nil, nil},
			{6, "dcerpc.pkt_type", "0", 0, nil, nil},
			{7, "dcerpc.pkt_type", "2", 0, nil, nil},
			{4, "tcp.stream", "", 7, nil, nil},
		},
		nil)

	// —— 簇②续：边界值（29-38）——
	add("dcerpc_frag_len_min", "最小合法 PDU（empty REQUEST frag_len 24）",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(reqResp(map[string]interface{}{}, "")...)}}), 9,
		[]fld{
			{4, "dcerpc.cn_frag_len", "24", 0, nil, nil},
			{4, "dcerpc.cn_auth_len", "0", 0, nil, nil},
		},
		[]fr{{4, 54, "050000031000000018000000010000000000000000000000"}})

	add("dcerpc_call_id_boundary", "call_id 0 与 4294967295",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(
				map[string]interface{}{"kind": "request", "call_id": 0, "context_id": 0, "opnum": 0,
					"respond": map[string]interface{}{"ack": "response"}},
				map[string]interface{}{"kind": "request", "call_id": 4294967295, "context_id": 0, "opnum": 0,
					"respond": map[string]interface{}{"ack": "response"}})}}), 11,
		[]fld{
			{4, "dcerpc.cn_call_id", "0", 0, nil, nil},
			{6, "dcerpc.cn_call_id", "4294967295", 0, nil, nil},
		},
		nil)

	add("dcerpc_call_id_adjacent", "相邻值 7/8 应答配对",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(
				map[string]interface{}{"kind": "bind", "call_id": 7,
					"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)}),
					"respond":  ackRespond("", ackResult(0, 0))},
				map[string]interface{}{"kind": "request", "call_id": 8, "context_id": 0, "opnum": 0,
					"respond": map[string]interface{}{"ack": "response"}})}}), 11,
		[]fld{
			{4, "dcerpc.cn_call_id", "7", 0, nil, nil},
			{5, "dcerpc.cn_call_id", "7", 0, nil, nil},
			{6, "dcerpc.cn_call_id", "8", 0, nil, nil},
			{7, "dcerpc.cn_call_id", "8", 0, nil, nil},
		},
		nil)

	add("dcerpc_opnum_boundary", "opnum 0 与 65535",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(
				map[string]interface{}{"kind": "request", "context_id": 0, "opnum": 0,
					"respond": map[string]interface{}{"ack": "response"}},
				map[string]interface{}{"kind": "request", "context_id": 0, "opnum": 65535,
					"respond": map[string]interface{}{"ack": "response"}})}}), 11,
		[]fld{
			{4, "dcerpc.opnum", "0", 0, nil, nil},
			{6, "dcerpc.opnum", "65535", 0, nil, nil},
		},
		nil)

	add("dcerpc_context_id_zero", "context_id=0 最小值",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(
				map[string]interface{}{
					"kind":     "bind",
					"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)}),
					"respond":  ackRespond("", ackResult(0, 0))},
				reqCtx(0, 1))}}), 11,
		[]fld{
			{4, "dcerpc.cn_ctx_id", "0", 0, nil, nil},
			{6, "dcerpc.cn_ctx_id", "0", 0, nil, nil},
		},
		nil)

	add("dcerpc_alloc_hint_variants", "alloc_hint 0 与≠实际 stub（合法提示）",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(
				map[string]interface{}{"kind": "request", "context_id": 0, "opnum": 0, "alloc_hint": 0,
					"stub": "aabbccdd", "respond": map[string]interface{}{"ack": "response"}},
				map[string]interface{}{"kind": "request", "context_id": 0, "opnum": 0, "alloc_hint": 99,
					"stub": "aabb", "respond": map[string]interface{}{"ack": "response"}})}}), 11,
		[]fld{
			{4, "dcerpc.cn_alloc_hint", "0", 0, nil, nil},
			{6, "dcerpc.cn_alloc_hint", "99", 0, nil, nil},
		},
		nil)

	add("dcerpc_request_object_uuid", "PFC_OBJECT_UUID 置位+16B object UUID",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(reqResp(map[string]interface{}{
				"object_uuid": rawUUID, "stub": "0102"}, "")...)}}), 9,
		[]fld{
			{4, "dcerpc.cn_flags.object", "1", 0, nil, nil},
		},
		[]fr{{4, 78, "0403020106050807090A0B0C0D0E0F10"}})

	add("dcerpc_response_cancel_count", "cancel_count>0",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(map[string]interface{}{
				"kind": "request", "context_id": 0, "opnum": 0,
				"respond": map[string]interface{}{"ack": "response", "cancel_count": 3}})}}), 9,
		[]fld{{5, "dcerpc.cn_cancel_count", "3", 0, nil, nil}},
		nil)

	add("dcerpc_fault_status_boundary", "status 边界值（nca 域 0x1C010003）",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(map[string]interface{}{
				"kind": "request", "context_id": 0, "opnum": 0,
				"respond": map[string]interface{}{"ack": "fault", "status": 469762051}})}}), 9,
		[]fld{{5, "dcerpc.cn_status", "0x1c000003", 0, nil, nil}},
		nil)

	add("dcerpc_empty_stub", "合法 empty stub（req/resp 双 24B）",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(reqResp(map[string]interface{}{}, "")...)}}), 9,
		[]fld{
			{4, "dcerpc.cn_frag_len", "24", 0, nil, nil},
			{5, "dcerpc.cn_frag_len", "24", 0, nil, nil},
		},
		nil)

	add("dcerpc_prebound_profile", "fixture 声明 prebound（跳 bind 直接调用合法面）",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(reqResp(map[string]interface{}{"opnum": 4}, "")...)}}), 9,
		[]fld{
			{4, "dcerpc.pkt_type", "0", 0, nil, nil},
			{4, "dcerpc.opnum", "4", 0, nil, nil},
		},
		nil)

	// —— 簇⑨续：多会话形状（40-41）——
	add("dcerpc_multi_session_sequential", "多会话按序整块展开（单事件会话→块连续）",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(map[string]interface{}{
				"kind":     "bind",
				"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)}),
				"respond":  ackRespond("", ackResult(0, 0))}),
			map[string]interface{}{"dst_port": 4135, "prebound": true,
				"events": reqResp(map[string]interface{}{}, "")},
		}}), 18,
		[]fld{
			{4, "dcerpc.pkt_type", "11", 0, nil, nil},
			{4, "tcp.dstport", "135", 0, nil, nil},
			{9, "dcerpc.pkt_type", "0", 0, nil, nil},
			{9, "tcp.dstport", "4135", 0, nil, nil},
		},
		nil, "tcp.port==4135,dcerpc")

	add("dcerpc_concurrent_sessions", "concurrent 交错（双会话按 event index 交替）",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(
				map[string]interface{}{
					"kind":     "bind",
					"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)}),
					"respond":  ackRespond("", ackResult(0, 0))},
				reqCtx(0, 1)),
			map[string]interface{}{"dst_port": 4135, "prebound": true,
				"events": reqResp(map[string]interface{}{"opnum": 1}, "")},
		}}), 20,
		[]fld{
			{4, "tcp.dstport", "135", 0, nil, nil},
			{6, "tcp.dstport", "135", 0, nil, nil},
			{11, "tcp.dstport", "4135", 0, nil, nil},
		},
		nil, "tcp.port==4135,dcerpc")

	add("dcerpc_max_xmit_recv_frag", "max_xmit/max_recv 变体（0xFFFF 边界）",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(map[string]interface{}{
				"kind": "bind", "max_xmit": 65535, "max_recv": 4096,
				"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)})})}}), 8,
		[]fld{
			{4, "dcerpc.cn_max_xmit", "65535", 0, nil, nil},
			{4, "dcerpc.cn_max_recv", "4096", 0, nil, nil},
		},
		[]fr{{4, 54, "05000B03100000004800000001000000FFFF00100000000001000000"}})

	// EPM tower / annotation（43-44）：lookup 应答携 7 floor ncacn_ip_tcp
	// tower（f1 abstract EPM v3.0 / f2 ndr v2.0 / f3 proto 0x07 / f4 port
	// 4135 / f5 host 198.51.100.63 / f6 annotation / f7 空 hostname）。
	// epmTowerResp 组 [out] stub：entry_handle(20B)+num_towers(4)+
	// max_count(4)+tower(num_floors 4+floors)。
	// epmTowerResp lookup 应答（wireshark epm_dissect_ept_lookup_resp 实证）：
	// handle20+num_ents4+REF ucvarray(off4+act4)+entries+rc4；entry =
	// object uuid16+tower unique ptr4+tower[len4+len4+num_floors u16+floors]+
	// ann_offset4+ann_len4+annotation。floor = lhs_len u16+lhs+rhs_len u16+rhs。
	epmTowerResp := func(annotation string) string {
		uid := uuidHex(t, epmUUID)
		nid := uuidHex(t, ndrUUID)
		floors := "1100" + "0D" + uid + "0200" + "0300" // f1 abstract EPM v3.0
		floors += "1100" + "0D" + nid + "0200" + "0200" // f2 transfer NDR v2.0
		floors += "0100" + "07" + "0200" + "1027"       // f3 TCP port 4135（BE）
		floors += "0100" + "09" + "0400" + "C633643F"   // f4 IP 198.51.100.63
		towerData := "0400" + floors                    // num_floors=4（u16）
		L := leHex(len(towerData)/2, 4)
		tower := L + L + towerData // twr_t：conformance len + len + data
		// wireshark 对 unique pointer 指向物延迟分解：tower 字节在 entry 之后。
		entry := "00000000000000000000000000000000" + // object uuid 全零
			"01000000" + // tower unique referent
			"00000000" + leHex(len(annotation), 4) + hexStr(annotation)
		return "0000000000000000000000000000000000000000" + // entry_handle 20B
			"01000000" + "01000000" + "00000000" + "01000000" + // num_ents + ucarray max/off/act
			entry + tower + "00000000" // entry + tower（延迟指向物） + rc=0
	}
	add("dcerpc_epm_tower_variants", "tower 长度/UUID/端口边界（EPM response 内观察）",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(append(epmBind(), epmLookup(epmTowerResp("")))...)}}), 11,
		[]fld{
			{7, "dcerpc.pkt_type", "2", 0, nil, nil},
			{7, "epm.tower.num_floors", "4", 0, nil, nil},
		},
		[]fr{{7, 54, "0500020310000000"}})

	add("dcerpc_epm_annotation", "annotation 长度前缀字符串",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(append(epmBind(), epmLookup(epmTowerResp("epmapper")))...)}}), 11,
		[]fld{
			{6, "dcerpc.opnum", "2", 0, nil, nil},
			{7, "epm.annotation", "epmapper", 0, nil, nil},
		},
		nil)

	add("dcerpc_bind_ack_reject_then_altctx", "reject 后 ALTER 换 syntax 成功",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(
				map[string]interface{}{
					"kind":     "bind",
					"contexts": toIface([]map[string]interface{}{ctx(0, genAUUID, 1, ndrUUID)}),
					"respond":  ackRespond("", ackResult(0, 2))},
				map[string]interface{}{
					"kind":     "alter_ctx",
					"contexts": toIface([]map[string]interface{}{ctx(1, genBUUID, 2, ndrUUID)}),
					"respond": map[string]interface{}{"ack": "alter_ctx_resp",
						"results": toIface([]map[string]interface{}{ackResult(1, 0)})}})}}), 11,
		[]fld{
			{5, "dcerpc.cn_ack_result", "2", 0, nil, nil},
			{6, "dcerpc.pkt_type", "14", 0, nil, nil},
			{7, "dcerpc.cn_ack_result", "0", 0, nil, nil},
		},
		nil)

	add("dcerpc_large_stub", "1024B 级 stub（frag_len 扩展）",
		chain(map[string]interface{}{"sessions": []interface{}{
			preSess(reqResp(map[string]interface{}{"stub": strings.Repeat("aa", 1024)}, "")...)}}), 9,
		[]fld{
			{4, "dcerpc.cn_frag_len", "1048", 0, nil, nil},
		},
		[]fr{{4, 54, "050000031000000018040000010000000000000000000000AA"}})

	add("dcerpc_port_dynamic_declared", "动态端口显式声明（非 135，tshark DecodeAs 口径）",
		chainPort(4135, map[string]interface{}{"sessions": []interface{}{
			map[string]interface{}{"dst_port": 4135, "prebound": true,
				"events": reqResp(map[string]interface{}{}, "")}}}), 9,
		[]fld{
			{4, "dcerpc.pkt_type", "0", 0, nil, nil},
			{4, "tcp.dstport", "4135", 0, nil, nil},
		},
		nil, "tcp.port==4135,dcerpc")

	add("dcerpc_uuid_encoding_authority", "MS/AD 混合端序 UUID 逐字节钉（编解码权威）",
		chain(map[string]interface{}{"sessions": []interface{}{
			sess(map[string]interface{}{
				"kind":     "bind",
				"contexts": toIface([]map[string]interface{}{ctx(0, rawUUID, 1, ndrUUID)}),
				"respond":  ackRespond("", ackResult(0, 0))})}}), 9,
		[]fld{
			{4, "dcerpc.cn_bind_to_uuid", rawUUID, 0, nil, nil},
		},
		[]fr{{4, 86, "0403020106050807090A0B0C0D0E0F10"}})

	if len(positives) != 48 {
		t.Fatalf("want 48 positives, built %d", len(positives))
	}

	// —— 负例 32（49-80，wire_fault 注入单锚词；75/76/78 自然载体形状）——
	inject := func(id string, fault string) negCase {
		return negCase{id: id, summary: "wire_fault 注入：" + fault,
			layers: chain(map[string]interface{}{"wire_fault": fault}),
			anchor: wireFaultAnchor(t, fault)}
	}
	negatives := []negCase{
		inject("dcerpc_neg_version_not5", "version_not5"),
		inject("dcerpc_neg_version_minor_not0", "version_minor_not0"),
		inject("dcerpc_neg_packet_type_unknown", "packet_type_unknown"),
		inject("dcerpc_neg_packet_type_reserved", "packet_type_reserved"),
		inject("dcerpc_neg_flags_first_no_last", "flags_first_no_last"),
		inject("dcerpc_neg_flags_last_no_first", "flags_last_no_first"),
		inject("dcerpc_neg_drep_not_le", "drep_not_le"),
		inject("dcerpc_neg_frag_len_lt16", "frag_len_lt16"),
		inject("dcerpc_neg_frag_len_mismatch", "frag_len_mismatch"),
		inject("dcerpc_neg_auth_len_over", "auth_len_over"),
		inject("dcerpc_neg_call_id_reuse", "call_id_reuse"),
		inject("dcerpc_neg_call_mismatch", "call_mismatch"),
		inject("dcerpc_neg_state_ack_no_call", "state_ack_no_call"),
		inject("dcerpc_neg_state_request_unbound", "state_request_unbound"),
		inject("dcerpc_neg_context_duplicate", "context_duplicate"),
		inject("dcerpc_neg_context_unknown", "context_unknown"),
		inject("dcerpc_neg_syntax_mismatch", "syntax_mismatch"),
		inject("dcerpc_neg_uuid_version_missing", "uuid_version_missing"),
		inject("dcerpc_neg_alloc_hint_negative", "alloc_hint_negative"),
		inject("dcerpc_neg_ndr_alignment", "ndr_alignment"),
		inject("dcerpc_neg_ndr_array_count", "ndr_array_count"),
		inject("dcerpc_neg_ndr_union_unknown", "ndr_union_unknown"),
		inject("dcerpc_neg_ndr_stub_overflow", "ndr_stub_overflow"),
		inject("dcerpc_neg_auth_pad_invalid", "auth_pad_invalid"),
		inject("dcerpc_neg_auth_trailer_over", "auth_trailer_over"),
		inject("dcerpc_neg_auth_verifier_len", "auth_verifier_len"),
		{ // 75 缺 tcp 载体（自然形状）
			id: "dcerpc_neg_carrier_layer_missing", summary: "缺 tcp 载体",
			layers: []interface{}{ipLayer(dceCli, dceSrv), dceLayer(map[string]interface{}{})},
			anchor: "carrier",
		},
		{ // 76 udp 载体（自然形状）
			id: "dcerpc_neg_carrier_udp", summary: "udp 载体声明",
			layers: []interface{}{
				ipLayer(dceCli, dceSrv),
				map[string]interface{}{"udp": map[string]interface{}{"src_port": 135, "dst_port": 135}},
				dceLayer(map[string]interface{}{})},
			anchor: "carrier",
		},
		inject("dcerpc_neg_port_undeclared", "port_undeclared"),
		{ // 78 混地址族（自然形状）
			id: "dcerpc_neg_address_family_mismatch", summary: "IPv4/IPv6 混地址族",
			layers: []interface{}{
				ipLayer("2001:db8::63", dceSrv),
				tcpLayer(135), dceLayer(map[string]interface{}{})},
			anchor: "family",
		},
		inject("dcerpc_neg_uuid_width", "uuid_width"),
		inject("dcerpc_neg_assoc_group_width", "assoc_group_width"),
	}
	if len(negatives) != 32 {
		t.Fatalf("want 32 negatives, built %d", len(negatives))
	}

	// —— 组装 JSON ——
	type outCase struct {
		ID       string                 `json:"id"`
		Proto    string                 `json:"proto"`
		Summary  string                 `json:"summary"`
		Spec     map[string]interface{} `json:"spec_json"`
		Expect   map[string]interface{} `json:"expect"`
		DecodeAs []string               `json:"decode_as,omitempty"`
	}
	var out []outCase
	for _, pc := range positives {
		fields := make([]interface{}, 0, len(pc.fields))
		for _, f := range pc.fields {
			fields = append(fields, f.m())
		}
		frames := make([]interface{}, 0, len(pc.frames))
		for _, f := range pc.frames {
			frames = append(frames, f.m())
		}
		expect := map[string]interface{}{
			"packet_count": pc.count,
			"fields":       fields,
			"frames":       frames,
		}
		out = append(out, outCase{ID: pc.id, Proto: "dcerpc", Summary: pc.summary,
			Spec: map[string]interface{}{"layers": pc.layers}, Expect: expect, DecodeAs: pc.decodeAs})
	}
	for _, nc := range negatives {
		out = append(out, outCase{ID: nc.id, Proto: "dcerpc", Summary: nc.summary,
			Spec:   map[string]interface{}{"layers": nc.layers},
			Expect: map[string]interface{}{"expect_error": true, "error_contains": nc.anchor}})
	}
	if len(out) != 80 {
		t.Fatalf("want 80 cases, built %d", len(out))
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../../../test/protocol_pcap/cases/dcerpc.json", b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d cases", len(out))
}

func leHex(v int, width int) string {
	b := make([]byte, width)
	for i := 0; i < width; i++ {
		b[i] = byte(v >> (8 * i))
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

func hexStr(s string) string {
	return strings.ToUpper(hex.EncodeToString([]byte(s)))
}

// uuidHex UUID 混合端序线上字节（builder uuidEncode 单权威同源）。
func uuidHex(t *testing.T, s string) string {
	t.Helper()
	b, err := uuidEncode(s)
	if err != nil {
		t.Fatalf("uuidEncode %s: %v", s, err)
	}
	return strings.ToUpper(hex.EncodeToString(b))
}

// wireFaultAnchor 负例锚词（DescribeDCERPCWireFault 同表——三方同源）。
func wireFaultAnchor(t *testing.T, fault string) string {
	t.Helper()
	a, err := core.DescribeDCERPCWireFault(fault)
	if err != nil {
		t.Fatalf("anchor for %s: %v", fault, err)
	}
	return a
}

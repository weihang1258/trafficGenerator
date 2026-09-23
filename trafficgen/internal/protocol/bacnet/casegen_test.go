package bacnet

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

// 用例生成器（一次性，D-BACNET-1 P4→P5）：按用例文档 §2 权威序产出 97 例
// （55 正 + 42 负）。正例帧断言取自全链真实回放（BuildLayersPlanner→Plan，
// 与套件同路径——单权威，无重复编码）。先跑后钉：字段渲染格式（tshark
// 十进制/十六进制/布尔）若与实测不符，P5 round-1 校准本文件并重跑生成。

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

func ipLayer(src, dst string) map[string]interface{} {
	return map[string]interface{}{"ip": map[string]interface{}{"src": src, "dst": dst}}
}
func udpLayer(sport, dport int) map[string]interface{} {
	return map[string]interface{}{"udp": map[string]interface{}{"src_port": sport, "dst_port": dport}}
}
func bacnetLayer(cfg map[string]interface{}) map[string]interface{} {
	return map[string]interface{}{"bacnet": cfg}
}
func chain(cfg map[string]interface{}) []interface{} {
	return []interface{}{ipLayer("192.0.2.66", "198.51.100.66"), udpLayer(47808, 47808), bacnetLayer(cfg)}
}
func ev(m map[string]interface{}) interface{} { return m }
func sess(events ...interface{}) interface{} {
	return map[string]interface{}{"events": events}
}

// plan renders the chain through the real planner (packets' Payload = UDP
// payload = BVLC datagram).
func planChain(t *testing.T, layersArr []interface{}, srcIP, dstIP string) []core.PacketConfig {
	t.Helper()
	raw, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatal(err)
	}
	p, err := layers.BuildLayersPlanner("bacnet", raw)
	if err != nil {
		t.Fatalf("BuildLayersPlanner: %v", err)
	}
	spec := core.FlowSpec{SrcIP: srcIP, DstIP: dstIP, SrcPort: 47808, DstPort: 47808}
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

func frameAsserts(t *testing.T, pkts []core.PacketConfig, specs []fr) []fr {
	t.Helper()
	out := make([]fr, 0, len(specs))
	for _, sp := range specs {
		if sp.Packet > len(pkts) {
			t.Fatalf("frame %d out of range (%d packets)", sp.Packet, len(pkts))
		}
		payload := pkts[sp.Packet-1].Payload
		n := sp.Hex
		_ = n
		ln := len(sp.Hex) / 2
		if ln == 0 || ln > len(payload) {
			ln = len(payload)
		}
		h := strings.ToUpper(hex.EncodeToString(payload[:ln]))
		if !strings.HasPrefix(h, sp.Hex) {
			t.Fatalf("frame %d: wire %s does not match pin %s", sp.Packet, h, sp.Hex)
		}
		out = append(out, fr{Packet: sp.Packet, Offset: sp.Offset, Hex: sp.Hex})
	}
	return out
}

// broadcastLayers builds case 3's layer chain (directed-broadcast dst).
func broadcastLayers() []interface{} {
	evs := []interface{}{
		map[string]interface{}{"kind": "who_is", "low": 0, "high": 100, "respond_i_am": true},
		map[string]interface{}{"kind": "i_am", "device_instance": 200},
	}
	bnet := map[string]interface{}{"sessions": []interface{}{map[string]interface{}{"events": evs}}}
	return []interface{}{ipLayer("192.0.2.66", "198.51.100.255"), udpLayer(47808, 47808), bacnetLayer(bnet)}
}

// portLayers builds case 46's layer chain (explicit 47809).
func portLayers() []interface{} {
	evs := []interface{}{map[string]interface{}{"kind": "who_is", "low": 0, "high": 100, "respond_i_am": true}}
	bnet := map[string]interface{}{"sessions": []interface{}{map[string]interface{}{"events": evs}}}
	return []interface{}{ipLayer("192.0.2.66", "198.51.100.66"), udpLayer(47809, 47809), bacnetLayer(bnet)}
}

// rpmMultiObjectLayers builds case 49 (two-object RPM with per-object results).
func rpmMultiObjectLayers() []interface{} {
	propRef := func(id int) map[string]interface{} { return map[string]interface{}{"property": id} }
	readSpec := func(ot, inst int) map[string]interface{} {
		return map[string]interface{}{"object_type": ot, "instance": inst,
			"props": []interface{}{propRef(85), propRef(77)}}
	}
	result := func(ot, inst int) map[string]interface{} {
		return map[string]interface{}{"object_type": ot, "instance": inst,
			"props": []interface{}{
				map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "real", "value": 22.5}},
				map[string]interface{}{"property": 77, "value": map[string]interface{}{"type": "char_string", "value": "obj"}}}}
	}
	evMap := map[string]interface{}{
		"kind": "rpm", "invoke_id": 1,
		"reads":   []interface{}{readSpec(0, 1), readSpec(8, 5)},
		"respond": map[string]interface{}{"ack": "complex", "results": []interface{}{result(0, 1), result(8, 5)}},
	}
	bnet := map[string]interface{}{"sessions": []interface{}{map[string]interface{}{"events": []interface{}{evMap}}}}
	return []interface{}{ipLayer("192.0.2.66", "198.51.100.66"), udpLayer(47808, 47808), bacnetLayer(bnet)}
}

func TestGenerateBACNETCases(t *testing.T) {
	const (
		cliA = "192.0.2.66"
		cliB = "192.0.2.67"
		srv  = "198.51.100.66"
	)
	_ = cliB
	var positives []posCase

	add := func(id, summary string, layersArr []interface{}, count int, fields []fld, framePins []fr, srcIP, dstIP string, decodeAs ...string) {
		pkts := planChain(t, layersArr, srcIP, dstIP)
		if len(pkts) != count {
			t.Fatalf("%s: rendered %d packets, contract pins %d", id, len(pkts), count)
		}
		fs, err := json.Marshal(layersArr)
		_ = fs
		_ = err
		frames := frameAsserts(t, pkts, framePins)
		positives = append(positives, posCase{id: id, summary: summary, layers: layersArr, count: count, fields: fields, frames: frames, decodeAs: decodeAs})
	}

	// —— 1 基线（§4 帧 hex 逐字节实测同构）——
	add("bacnet_bvlc_unicast_baseline", "Who-Is(0-100)→I-Am 单播基线：BVLC 0x0a/len12、I-Am u16 宽度 22 000f、厂商 15",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "who_is", "low": 0, "high": 100, "respond_i_am": true}),
		)}}), 2,
		[]fld{
			{1, "bvlc.function", "0x0a", 0, nil, nil},
			{1, "bacnet.version", "1", 0, nil, nil},
			{1, "bacnet.control", "0x00", 0, nil, nil},
			{1, "bacapp.unconfirmed_service", "8", 0, nil, nil},
			{2, "bacapp.objectType", "8", 0, nil, nil},
			{2, "bacapp.instance_number", "100", 0, nil, nil},
			{2, "bacapp.vendor_identifier", "15", 0, nil, nil},
		},
		[]fr{{1, 42, "810A000C0100100809001964"}, {2, 42, "810A001501001000C4020000642205C4910322"}},
		cliA, srv)

	// —— 2 最小帧 ——
	add("bacnet_min_frame", "无参数 Who-Is 8B BACnet/IP 最小帧（低/高限缺省，字段缺失断言）",
		chain(map[string]interface{}{}), 1,
		[]fld{
			{1, "bacapp.unconfirmed_service", "8", 0, nil, nil},
			{1, "udp.length", "16", 0, nil, nil},
		},
		[]fr{{1, 42, "810A000801001008"}},
		cliA, srv)

	// —— 3 广播 ——
	add("bacnet_bvlc_broadcast", "定向广播 Who-Is（0x0b）→ 双 I-Am（实例 100/200 distinct）",
		broadcastLayers(), 3,
		[]fld{
			{1, "bvlc.function", "0x0b", 0, nil, nil},
			{2, "bacapp.instance_number", "100", 0, nil, nil},
			{3, "bacapp.instance_number", "200", 0, nil, nil},
			{2, "bacapp.application_tag_number", "12,2,9,2", 0, nil, nil},
		},
		[]fr{{1, 42, "810B000C0100100809001964"}},
		cliA, "198.51.100.255")

	// —— 4 Forwarded-NPDU ——
	add("bacnet_bvlc_forwarded", "BBMD Forwarded-NPDU（0x04）：6B 原始源地址 192.0.2.99:47808 + 内层 Who-Is",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "forwarded_npdu", "fwd_ip": "192.0.2.99", "fwd_port": 47808,
				"inner": map[string]interface{}{"kind": "who_is"}}),
		)}}), 1,
		[]fld{
			{1, "bvlc.function", "0x04", 0, nil, nil},
			{1, "bvlc.fwd_ip", "192.0.2.99", 0, nil, nil},
			{1, "bvlc.fwd_port", "47808", 0, nil, nil},
			{1, "bacapp.unconfirmed_service", "8", 0, nil, nil},
		},
		[]fr{{1, 42, "8104000EC0000263BAC001001008"}},
		cliA, srv)

	// —— 5 RFD 600/0 ——
	add("bacnet_bvlc_register_foreign", "RFD TTL 600 与 0（立即到期合法边界）→ Result 0x0000 ×2",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "register_foreign_device", "ttl": 600}),
			ev(map[string]interface{}{"kind": "register_foreign_device", "ttl": 0}),
		)}}), 4,
		[]fld{
			{1, "bvlc.function", "0x05", 0, nil, nil},
			{1, "bvlc.reg_ttl", "600", 0, nil, nil},
			{2, "bvlc.result", "0x0000", 0, nil, nil},
			{3, "bvlc.reg_ttl", "0", 0, nil, nil},
		},
		[]fr{{1, 42, "810500060258"}, {3, 42, "810500060000"}},
		cliA, srv)

	// —— 6 Result NAK ——
	add("bacnet_bvlc_result_nak", "RFD→Result 0x0030（Register-FD NAK 合法错误路径）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "register_foreign_device", "ttl": 600,
				"respond": map[string]interface{}{"result": 48}}),
		)}}), 2,
		[]fld{{2, "bvlc.result", "0x0030", 0, nil, nil}},
		[]fr{{2, 42, "810000060030"}},
		cliA, srv)

	// —— 7 Write-BDT ——
	add("bacnet_bvlc_write_bdt", "Write-BDT 单表项（192.0.2.88:47808 掩码 /24）→ Result",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "write_bdt", "entries": []interface{}{
				map[string]interface{}{"ip": "192.0.2.88", "port": 47808, "mask": "ffffff00"}}}),
		)}}), 2,
		[]fld{
			{1, "bvlc.function", "0x01", 0, nil, nil},
			{1, "bvlc.bdt_ip", "192.0.2.88", 0, nil, nil},
			{1, "bvlc.bdt_port", "47808", 0, nil, nil},
			{1, "bvlc.bdt_mask", "ffffff00", 0, nil, nil},
		},
		[]fr{{1, 42, "8101000EC0000258BAC0FFFFFF00"}},
		cliA, srv)

	// —— 8 Read-BDT ——
	add("bacnet_bvlc_read_bdt", "Read-BDT（无负载 len 4）→ Ack 单表项",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_bdt", "respond": map[string]interface{}{"entries": []interface{}{
				map[string]interface{}{"ip": "192.0.2.88", "port": 47808, "mask": "ffffff00"}}}}),
		)}}), 2,
		[]fld{
			{1, "bvlc.function", "0x02", 0, nil, nil},
			{2, "bvlc.function", "0x03", 0, nil, nil},
			{2, "bvlc.bdt_ip", "192.0.2.88", 0, nil, nil},
		},
		[]fr{{1, 42, "81020004"}, {2, 42, "8103000EC0000258BAC0FFFFFF00"}},
		cliA, srv)

	// —— 9 Read-FDT ——
	add("bacnet_bvlc_read_fdt", "Read-FDT → Ack 表项（192.0.2.99 TTL 300 超时 120）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_fdt", "respond": map[string]interface{}{"entries": []interface{}{
				map[string]interface{}{"ip": "192.0.2.99", "port": 47808, "ttl": 300, "timeout": 120}}}}),
		)}}), 2,
		[]fld{
			{1, "bvlc.function", "0x06", 0, nil, nil},
			{2, "bvlc.function", "0x07", 0, nil, nil},
			{2, "bvlc.fdt_ip", "192.0.2.99", 0, nil, nil},
			{2, "bvlc.fdt_ttl", "300", 0, nil, nil},
			{2, "bvlc.fdt_timeout", "120", 0, nil, nil},
		},
		[]fr{{1, 42, "81060004"}, {2, 42, "8107000EC0000263BAC0012C0078"}},
		cliA, srv)

	// —— 10 Delete-FDT ——
	add("bacnet_bvlc_delete_fdt", "Delete-FDT-Entry（6B 外部设备地址）→ Result",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "delete_fdt", "entries": []interface{}{
				map[string]interface{}{"ip": "192.0.2.99", "port": 47808}}}),
		)}}), 2,
		[]fld{{1, "bvlc.function", "0x08", 0, nil, nil}},
		[]fr{{1, 42, "8108000AC0000263BAC0"}},
		cliA, srv)

	// —— 11 Distribute ——
	add("bacnet_bvlc_distribute_broadcast", "Distribute-Broadcast（0x09 承载 Who-Is，静默转发无 Result）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "distribute_broadcast",
				"inner": map[string]interface{}{"kind": "who_is", "low": 0, "high": 100}}),
		)}}), 1,
		[]fld{
			{1, "bvlc.function", "0x09", 0, nil, nil},
			{1, "bacapp.unconfirmed_service", "8", 0, nil, nil},
		},
		[]fr{{1, 42, "8109000C0100100809001964"}},
		cliA, srv)

	// —— 12 NPDU dest ——
	add("bacnet_npdu_dest_address", "NPDU 目的说明符：DNET 2001+DLEN 6+DADR+Hop（帧 1）/ DLEN=0 网内广播变体（帧 2）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "who_is",
				"npdu": map[string]interface{}{"dest": map[string]interface{}{"net": 2001, "ip": "192.0.2.99", "port": 47808}}}),
			ev(map[string]interface{}{"kind": "who_is",
				"npdu": map[string]interface{}{"dest": map[string]interface{}{"net": 2001}}}),
		)}}), 2,
		[]fld{
			{1, "bacnet.control", "0x20", 0, nil, nil},
			{1, "bacnet.control_dest", "1", 0, nil, nil},
			{1, "bacnet.dnet", "2001", 0, nil, nil},
			{1, "bacnet.dlen", "6", 0, nil, nil},
			{1, "bacnet.hopc", "255", 0, nil, nil},
			{2, "bacnet.dlen", "0", 0, nil, nil},
		},
		[]fr{{1, 42, "810A0012012007D106C0000263BAC0FF1008"}, {2, 42, "810A000C012007D100FF1008"}},
		cliA, srv)

	// —— 13 NPDU src ——
	add("bacnet_npdu_src_address", "NPDU 源说明符：I-Am 携 SNET 2001+SLEN 6+SADR（帧 2）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "who_is", "low": 0, "high": 100}),
			ev(map[string]interface{}{"kind": "i_am",
				"npdu": map[string]interface{}{"src": map[string]interface{}{"net": 2001, "ip": "192.0.2.99", "port": 47808}}}),
		)}}), 2,
		[]fld{
			{2, "bacnet.control", "0x08", 0, nil, nil},
			{2, "bacnet.control_src", "1", 0, nil, nil},
			{2, "bacnet.snet", "2001", 0, nil, nil},
			{2, "bacnet.slen", "6", 0, nil, nil},
			{2, "bacapp.instance_number", "100", 0, nil, nil},
		},
		[]fr{{2, 42, "810A001E010807D106C0000263BAC01000C4020000642205C4910322"}},
		cliA, srv)

	// —— 14 路由发现 ——
	add("bacnet_npdu_router_discovery", "网络层消息对：Who-Is-Router(0x00, DNET FFFF)→I-Am-Router(0x01, DNET 2001)",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "router_discovery", "nets": []interface{}{65535},
				"respond": map[string]interface{}{"nets": []interface{}{2001}}}),
		)}}), 2,
		[]fld{
			{1, "bacnet.control", "0x84", 0, nil, nil},
			{1, "bacnet.control_net", "1", 0, nil, nil},
			{1, "bacnet.mesgtyp", "0x00", 0, nil, nil},
			{2, "bacnet.control", "0x80", 0, nil, nil},
			{2, "bacnet.mesgtyp", "0x01", 0, nil, nil},
		},
		[]fr{{1, 42, "810A0009018400FFFF"}, {2, 42, "810A000901800107D1"}},
		cliA, srv)

	// —— 15 NPDU 优先级 ——
	add("bacnet_npdu_priority", "NPDU 网络优先级三值：0x01/0x02/0x03（Who-Is ×3）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "who_is", "npdu": map[string]interface{}{"priority": 1}}),
			ev(map[string]interface{}{"kind": "who_is", "npdu": map[string]interface{}{"priority": 2}}),
			ev(map[string]interface{}{"kind": "who_is", "npdu": map[string]interface{}{"priority": 3}}),
		)}}), 3,
		[]fld{
			{1, "bacnet.control_prio_high", "0", 0, nil, nil},
			{1, "bacnet.control_prio_low", "1", 0, nil, nil},
			{2, "bacnet.control_prio_high", "1", 0, nil, nil},
			{2, "bacnet.control_prio_low", "0", 0, nil, nil},
			{3, "bacnet.control_prio_high", "1", 0, nil, nil},
			{3, "bacnet.control_prio_low", "1", 0, nil, nil},
		},
		[]fr{{1, 42, "810A000801011008"}},
		cliA, srv)

	// —— 16 ReadProperty ——
	add("bacnet_read_property", "RP 请求（control 04 期望回复）→ ComplexACK Real 22.5 大端",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 1,
				"object_type": 0, "instance": 1, "property": 85,
				"respond": map[string]interface{}{"ack": "complex",
					"value": map[string]interface{}{"type": "real", "value": 22.5}}}),
		)}}), 2,
		[]fld{
			{1, "bacnet.control", "0x04", 0, nil, nil},
			{1, "bacapp.max_adpu_size", "5", 0, nil, nil},
			{1, "bacapp.invoke_id", "1", 0, nil, nil},
			{1, "bacapp.confirmed_service", "12", 0, nil, nil},
			{1, "bacapp.objectType", "0", 0, nil, nil},
			{1, "bacapp.instance_number", "1", 0, nil, nil},
			{1, "bacapp.property_identifier", "85", 0, nil, nil},
			{2, "bacapp.type", "3", 0, nil, nil},
			{2, "bacapp.invoke_id", "1", 0, nil, nil},
			{2, "bacapp.present_value.real", "22.5", 0, nil, nil},
		},
		[]fr{{1, 42, "810A001101040005010C0C000000011955"}, {2, 42, "810A0017010030010C0C0000000119553E4441B400003F"}},
		cliA, srv)

	// —— 17 数组下标 ——
	add("bacnet_read_property_array_index", "RP ctx2 下标 1 与 0（整个数组合法边界），应答回显下标",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 1,
				"object_type": 0, "instance": 1, "property": 85, "array_index": 1,
				"respond": map[string]interface{}{"ack": "complex",
					"value": map[string]interface{}{"type": "real", "value": 22.5}}}),
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 2,
				"object_type": 0, "instance": 1, "property": 85, "array_index": 0,
				"respond": map[string]interface{}{"ack": "complex",
					"value": map[string]interface{}{"type": "real", "value": 22.5}}}),
		)}}), 4,
		[]fld{
			{1, "bacapp.invoke_id", "1", 0, nil, nil},
			{3, "bacapp.invoke_id", "2", 0, nil, nil},
			{4, "bacapp.present_value.real", "22.5", 0, nil, nil},
		},
		[]fr{{1, 42, "810A001301040005010C0C0000000119552901"}, {3, 42, "810A001301040005020C0C0000000119552900"}},
		cliA, srv)

	// —— 18 RPM ——
	add("bacnet_read_property_multiple", "RPM 单对象双属性（开[1] 85+77 闭[1]）→ ComplexACK 双值",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "rpm", "invoke_id": 1,
				"reads": []interface{}{map[string]interface{}{
					"object_type": 0, "instance": 1,
					"props": []interface{}{
						map[string]interface{}{"property": 85},
						map[string]interface{}{"property": 77}}}},
				"respond": map[string]interface{}{"ack": "complex", "results": []interface{}{
					map[string]interface{}{"object_type": 0, "instance": 1, "props": []interface{}{
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "real", "value": 22.5}},
						map[string]interface{}{"property": 77, "value": map[string]interface{}{"type": "char_string", "value": "ai-1"}}}}}}}),
		)}}), 2,
		[]fld{
			{1, "bacapp.confirmed_service", "14", 0, nil, nil},
			{1, "bacapp.objectType", "0", 0, nil, nil},
			{1, "bacapp.instance_number", "1", 0, nil, nil},
			{2, "bacapp.property_identifier", "", 0, []string{"85,77"}, nil},
			{2, "bacapp.present_value.real", "22.5", 0, nil, nil},
			{2, "bacapp.object_name", "ai-1", 0, nil, nil},
		},
		[]fr{{1, 42, "810A001501040005010E0C000000011E0955094D1F"}},
		cliA, srv)

	// —— 19 WP ——
	add("bacnet_write_property", "WP 布尔 TRUE + 优先级 8（49 08）→ SimpleACK",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "write_property", "invoke_id": 2,
				"object_type": 0, "instance": 1, "property": 85,
				"value": map[string]interface{}{"type": "boolean", "value": true}, "priority": 8,
				"respond": map[string]interface{}{"ack": "simple"}}),
		)}}), 2,
		[]fld{
			{1, "bacapp.confirmed_service", "15", 0, nil, nil},
			{1, "bacapp.present_value.boolean", "1", 0, nil, nil},
			{2, "bacapp.type", "2", 0, nil, nil},
			{2, "bacapp.invoke_id", "2", 0, nil, nil},
			{2, "bacapp.confirmed_service", "15", 0, nil, nil},
		},
		[]fr{{1, 42, "810A001601040005020F0C0000000119553E113F4908"}, {2, 42, "810A0009010020020F"}},
		cliA, srv)

	// —— 20 WP 无优先级 ——
	add("bacnet_write_property_no_priority", "WP 缺省优先级（无 49 xx 尾巴 = 语义 16）→ SimpleACK",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "write_property", "invoke_id": 2,
				"object_type": 0, "instance": 1, "property": 85,
				"value":   map[string]interface{}{"type": "boolean", "value": true},
				"respond": map[string]interface{}{"ack": "simple"}}),
		)}}), 2,
		[]fld{{2, "bacapp.invoke_id", "2", 0, nil, nil}},
		[]fr{{1, 42, "810A001401040005020F0C0000000119553E113F"}},
		cliA, srv)

	// —— 21 Who-Has/I-Have ——
	add("bacnet_who_has_i_have", "Who-Has 名字分支（ctx3 CharacterString）→ I-Have；[2] 对象 ID 分支 → I-Have",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "who_has", "object_name": "ai-1"}),
			ev(map[string]interface{}{"kind": "i_have", "device_instance": 100, "object_type": 0, "instance": 1, "object_name": "ai-1"}),
			ev(map[string]interface{}{"kind": "who_has", "object_type": 0, "instance": 1}),
			ev(map[string]interface{}{"kind": "i_have", "device_instance": 100, "object_type": 0, "instance": 1, "object_name": "ai-1"}),
		)}}), 4,
		[]fld{
			{1, "bacapp.unconfirmed_service", "7", 0, nil, nil},
			{1, "bacapp.object_name", "ai-1", 0, nil, nil},
			{1, "bacapp.string_character_set", "0", 0, nil, nil},
			{2, "bacapp.unconfirmed_service", "1", 0, nil, nil},
			{3, "bacapp.objectType", "0", 0, nil, nil},
			{3, "bacapp.instance_number", "1", 0, nil, nil},
			{4, "bacapp.application_tag_number", "", 0, []string{"12,12,7"}, nil},
		},
		[]fr{{1, 42, "810A000F010010073D050061692D31"}, {3, 42, "810A000D010010072C00000001"}},
		cliA, srv)

	// —— 22 SubscribeCOV ——
	add("bacnet_subscribe_cov", "SubscribeCOV（process 1/device:5/issue-confirmed TRUE/lifetime 600）→ SimpleACK",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "subscribe_cov", "invoke_id": 3, "process_id": 1,
				"object_type": 8, "instance": 5, "issue_confirmed": true, "lifetime": 600,
				"respond": map[string]interface{}{"ack": "simple"}}),
		)}}), 2,
		[]fld{
			{1, "bacapp.confirmed_service", "5", 0, nil, nil},
			{1, "bacapp.context_tag_number", "0,1,2,3", 0, nil, nil},
			{1, "bacapp.objectType", "8", 0, nil, nil},
			{1, "bacapp.instance_number", "5", 0, nil, nil},
		},
		[]fr{{1, 42, "810A001601040005030509011C0200000529013A0258"}},
		cliA, srv)

	// —— 23 COV 通知 ——
	add("bacnet_cov_notification", "UnconfirmedCOVNotification 单帧（开[4] ctx0 属性+开[2] Real 24.0 闭[2] 闭[4]）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "cov_notification", "process_id": 1,
				"initiating_device": 5, "object_type": 8, "instance": 5, "time_remaining": 540,
				"cov_values": []interface{}{map[string]interface{}{
					"property": 85, "value": map[string]interface{}{"type": "real", "value": 24.0}}}}),
		)}}), 1,
		[]fld{
			{1, "bacapp.unconfirmed_service", "2", 0, nil, nil},
			{1, "bacapp.processId", "1", 0, nil, nil},
			{1, "bacapp.present_value.real", "24", 0, nil, nil},
		},
		[]fr{{1, 42, "810A00220100100209011C020000052C020000053A021C4E09552E4441C000002F4F"}},
		cliA, srv)

	// —— 24 COV 取消 ——
	add("bacnet_subscribe_cov_cancel", "SubscribeCOV 取消形态（[2][3] 均缺省）→ SimpleACK",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "subscribe_cov", "invoke_id": 3, "process_id": 1,
				"object_type": 8, "instance": 5,
				"respond": map[string]interface{}{"ack": "simple"}}),
		)}}), 2,
		[]fld{{2, "bacapp.confirmed_service", "5", 0, nil, nil}},
		[]fr{{1, 42, "810A001101040005030509011C02000005"}},
		cliA, srv)

	// —— 25 DCC ——
	add("bacnet_device_communication_control", "DCC duration 0+disable 1+password pass（[2] ctx3 CharacterString 实占 7B）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "dcc", "invoke_id": 4,
				"duration": 0, "disable": 1, "password": "pass",
				"respond": map[string]interface{}{"ack": "simple"}}),
		)}}), 2,
		[]fld{{1, "bacapp.confirmed_service", "17", 0, nil, nil}},
		[]fr{{1, 42, "810A00160104000504110A000019012D050070617373"}},
		cliA, srv)

	// —— 26 Error ——
	add("bacnet_error_response", "Error 应答 invoke 配对（class 2 property + code 32/40 两组合）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 5, "property": 85}),
			ev(map[string]interface{}{"kind": "error", "invoke_id": 5, "service_choice": 12, "error_class": 2, "error_code": 32}),
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 6, "property": 85}),
			ev(map[string]interface{}{"kind": "error", "invoke_id": 6, "service_choice": 12, "error_class": 2, "error_code": 40}),
		)}}), 4,
		[]fld{
			{2, "bacapp.type", "5", 0, nil, nil},
			{2, "bacapp.invoke_id", "5", 0, nil, nil},
			{2, "bacapp.confirmed_service", "12", 0, nil, nil},
			{2, "bacapp.error_class", "2", 0, nil, nil},
			{2, "bacapp.error_code", "32", 0, nil, nil},
			{4, "bacapp.error_code", "40", 0, nil, nil},
			{2, "bacapp.application_tag_number", "", 0, []string{"9,9"}, nil},
		},
		[]fr{{2, 42, "810A000D010050050C91029120"}, {4, 42, "810A000D010050060C91029128"}},
		cliA, srv)

	// —— 27 Reject ——
	add("bacnet_reject", "Reject 应答（60 02 05 missing-required-parameter）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "write_property", "invoke_id": 2,
				"value": map[string]interface{}{"type": "boolean", "value": true}}),
			ev(map[string]interface{}{"kind": "reject", "invoke_id": 2, "reject_reason": 5}),
		)}}), 2,
		[]fld{
			{2, "bacapp.type", "6", 0, nil, nil},
			{2, "bacapp.invoke_id", "2", 0, nil, nil},
			{2, "bacapp.reject_reason", "5", 0, nil, nil},
		},
		[]fr{{2, 42, "810A00090100600205"}},
		cliA, srv)

	// —— 28 Abort ——
	add("bacnet_abort", "Abort 应答（71 02 0b，SRV=1 设备侧）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "write_property", "invoke_id": 2,
				"value": map[string]interface{}{"type": "boolean", "value": true}}),
			ev(map[string]interface{}{"kind": "abort", "invoke_id": 2, "abort_reason": 11, "srv": true}),
		)}}), 2,
		[]fld{
			{2, "bacapp.type", "7", 0, nil, nil},
			{2, "bacapp.invoke_id", "2", 0, nil, nil},
			{2, "bacapp.abort_reason", "11", 0, nil, nil},
		},
		[]fr{{2, 42, "810A0009010071020B"}},
		cliA, srv)

	// —— 29 分段请求 ——
	big465 := strings.Repeat("BACnetSegment.", 33) + "BAC"
	add("bacnet_segmented_request", "分段 WriteProperty（465B CharacterString 天然超 480）两段+SegmentACK（SRV=1）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "segmented_request", "invoke_id": 6, "window_size": 2,
				"object_type": 0, "instance": 1, "property": 85,
				"value": map[string]interface{}{"type": "char_string", "value": big465}, "priority": 8}),
		)}}), 3,
		[]fld{
			{1, "bacapp.segmented_request", "1", 0, nil, nil},
			{1, "bacapp.more_segments", "1", 0, nil, nil},
			{1, "bacapp.sequence_number", "0", 0, nil, nil},
			{1, "bacapp.window_size", "2", 0, nil, nil},
			{1, "bacapp.confirmed_service", "15", 0, nil, nil},
			{2, "bacapp.more_segments", "0", 0, nil, nil},
			{2, "bacapp.sequence_number", "1", 0, nil, nil},
			{2, "bacapp.fragment.count", "2", 0, nil, nil},
			{2, "bacapp.reassembled.length", "481", 0, nil, nil},
			{3, "bacapp.type", "4", 0, nil, nil},
			{3, "bacapp.invoke_id", "6", 0, nil, nil},
			{3, "bacapp.sequence_number", "1", 0, nil, nil},
			{3, "bacapp.window_size", "2", 0, nil, nil},
		},
		[]fr{{1, 42, "810A001401040C230600020F0C0000000119553E"}, {3, 42, "810A000A010041060102"}},
		cliA, srv)

	// —— 30 分段 ComplexACK ——
	add("bacnet_segmented_complex_ack", "分段 ComplexACK（窗口 4，SRV=0 客户端 SegmentACK）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 7, "property": 85}),
			ev(map[string]interface{}{"kind": "segmented_ack", "invoke_id": 7, "window_size": 4,
				"object_type": 0, "instance": 1, "property": 85,
				"value": map[string]interface{}{"type": "real", "value": 22.5}}),
		)}}), 4,
		[]fld{
			{2, "bacapp.sequence_number", "", 0, []string{"0", "1"}, nil},
			{3, "bacapp.fragment.count", "2", 0, nil, nil},
			{3, "bacapp.reassembled.length", "14", 0, nil, nil},
		},
		[]fr{{2, 42, "810A001301043C0700040C0C0000000119553E"}, {4, 42, "810A000A010040070104"}},
		cliA, srv)

	// —— 31 I-Am 能力变体 ——
	add("bacnet_i_am_capabilities", "I-Am 能力三变体（分段能力 0/1/2 + max-APDU 1024，无符号最短式）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "i_am", "device_instance": 200, "max_apdu": 1024, "segmentation": 0, "vendor_id": 15}),
			ev(map[string]interface{}{"kind": "i_am", "device_instance": 201, "max_apdu": 1024, "segmentation": 1, "vendor_id": 15}),
			ev(map[string]interface{}{"kind": "i_am", "device_instance": 202, "max_apdu": 1024, "segmentation": 2, "vendor_id": 15}),
		)}}), 3,
		[]fld{
			{1, "bacapp.objectType", "8", 0, nil, nil},
			{1, "bacapp.vendor_identifier", "15", 0, nil, nil},
			{1, "bacapp.instance_number", "", 0, []string{"200", "201", "202"}, nil},
		},
		[]fr{{1, 42, "810A001501001000C4020000C8220400910022000F"}, {2, 42, "810A001501001000C4020000C9220400910122000F"}},
		cliA, srv)

	// —— 32 应用标签全枚举（4 帧：RPM 13 值 + RP Boolean FALSE；§4 帧数 3 的
	// 声明化重构——每个 ComplexACK 需各自请求帧，T-BACNET 登记）——
	add("bacnet_app_tag_encoding", "ComplexACK 承载 13 种应用标签值（标签 0-12 逐一：null/bool/uint/int/real/double/octet/char/bit/enum/date/time/objectID）+ 追加 Boolean FALSE（10 无内容字节）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "rpm", "invoke_id": 1,
				"reads": []interface{}{map[string]interface{}{
					"object_type": 0, "instance": 1,
					"props": func() []interface{} {
						ps := []interface{}{}
						for i := 0; i < 13; i++ {
							ps = append(ps, map[string]interface{}{"property": 85})
						}
						return ps
					}()}},
				"respond": map[string]interface{}{"ack": "complex", "results": []interface{}{
					map[string]interface{}{"object_type": 0, "instance": 1, "props": []interface{}{
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "null"}},
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "boolean", "value": true}},
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "unsigned", "value": 42}},
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "int", "value": -7}},
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "real", "value": 22.5}},
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "double", "value": 3.14}},
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "octet_string", "value": "DEADBEEF"}},
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "char_string", "value": "objs"}},
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "bit_string", "value": "70", "unused_bits": 5}},
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "enumerated", "value": 5}},
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "date", "value": map[string]interface{}{"year": 2026, "month": 9, "day": 24, "weekday": 4}}},
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "time", "value": map[string]interface{}{"hour": 12, "minute": 30, "second": 45, "hundredths": 50}}},
						map[string]interface{}{"property": 85, "value": map[string]interface{}{"type": "object_id", "object_type": 8, "object_instance": 5}}}}}}}),
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 2, "property": 85,
				"respond": map[string]interface{}{"ack": "complex",
					"value": map[string]interface{}{"type": "boolean", "value": false}}}),
		)}}), 4,
		[]fld{
			{2, "bacapp.application_tag_number", "0,1,2,3,4,5,6,7,8,9,10,11,12", 0, nil, nil},
			{2, "bacapp.present_value.uint", "42", 0, nil, nil},
			{2, "bacapp.present_value.real", "22.5", 0, nil, nil},
			{2, "bacapp.present_value.double", "3.14", 0, nil, nil},
			{4, "bacapp.present_value.boolean", "0", 0, nil, nil},
		},
		[]fr{
			{2, 42, "810A0079010030010E0C000000011E29554E004F29554E114F29554E212A4F29554E31F94F29554E4441B400004F29554E550840091EB851EB851F4F29554E64DEADBEEF4F29554E7505006F626A734F29554E8205704F29554E91054F29554EA47E0918044F29554EB40C1E2D324F29554EC4020000054F1F"},
			{4, 42, "810A0013010030020C0C0000000019553E103F"},
		},
		cliA, srv)

	// —— 33 对象 ID 边界 ——
	add("bacnet_object_id_boundary", "对象 analog-input:0 与私有类型 128 实例 0x3FFFFF（0c 00000000 / 0c 203fffff）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 1, "object_type": 0, "instance": 0, "property": 85,
				"respond": map[string]interface{}{"ack": "complex", "value": map[string]interface{}{"type": "real", "value": 22.5}}}),
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 2, "object_type": 128, "instance": 4194303, "property": 85,
				"respond": map[string]interface{}{"ack": "complex", "value": map[string]interface{}{"type": "real", "value": 22.5}}}),
		)}}), 4,
		[]fld{
			{1, "bacapp.instance_number", "", 0, []string{"0", "4194303"}, nil},
			{3, "bacapp.objectType", "128", 0, nil, nil},
		},
		[]fr{{1, 42, "810A001101040005010C0C000000001955"}, {3, 42, "810A001101040005020C0C203FFFFF1955"}},
		cliA, srv)

	// —— 34 Invoke ID 边界 ——
	add("bacnet_invoke_id_boundary", "Invoke ID 0 与 255 边界（ACK 回显 same_as_packet）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 0, "property": 85,
				"respond": map[string]interface{}{"ack": "complex", "value": map[string]interface{}{"type": "real", "value": 22.5}}}),
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 255, "property": 85,
				"respond": map[string]interface{}{"ack": "complex", "value": map[string]interface{}{"type": "real", "value": 22.5}}}),
		)}}), 4,
		[]fld{
			{1, "bacapp.invoke_id", "0", 0, nil, nil},
			{2, "bacapp.invoke_id", "0", 0, nil, nil},
			{3, "bacapp.invoke_id", "255", 0, nil, nil},
			{4, "bacapp.invoke_id", "255", 0, nil, nil},
		},
		[]fr{{1, 42, "810A001101040005000C0C000000001955"}},
		cliA, srv)

	// —— 35 多事务 ——
	add("bacnet_multi_transaction", "单会话六帧序列 Who-Is→I-Am→RP(1)→ACK→WP(2)→ACK（方向交替 invoke 递增）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "who_is", "respond_i_am": true}),
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 1, "property": 85,
				"respond": map[string]interface{}{"ack": "complex", "value": map[string]interface{}{"type": "real", "value": 22.5}}}),
			ev(map[string]interface{}{"kind": "write_property", "invoke_id": 2,
				"value":   map[string]interface{}{"type": "boolean", "value": true},
				"respond": map[string]interface{}{"ack": "simple"}}),
		)}}), 6,
		[]fld{
			{3, "bacapp.invoke_id", "1", 0, nil, nil},
			{4, "bacapp.invoke_id", "1", 0, nil, nil},
			{5, "bacapp.invoke_id", "2", 0, nil, nil},
			{6, "bacapp.invoke_id", "2", 0, nil, nil},
			{1, "bacapp.unconfirmed_service", "8", 0, nil, nil},
		},
		[]fr{{1, 42, "810A000801001008"}},
		cliA, srv)

	// —— 36 IPv6 ——
	add("bacnet_ipv6", "IPv6 承载（2001:db8::65→2001:db8::100:65）：BVLC 首字节 offset 62，字节与用例 1 一致",
		[]interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "2001:db8::65", "dst": "2001:db8::100:65"}},
			udpLayer(47808, 47808),
			bacnetLayer(map[string]interface{}{"sessions": []interface{}{sess(
				ev(map[string]interface{}{"kind": "who_is", "low": 0, "high": 100, "respond_i_am": true}),
			)}}),
		}, 2,
		[]fld{
			{1, "ipv6.nxt", "17", 0, nil, nil},
			{1, "bvlc.function", "0x0a", 0, nil, nil},
		},
		[]fr{{1, 62, "810A000C0100100809001964"}},
		"2001:db8::65", "2001:db8::100:65")

	// —— 37 多会话 ——
	add("bacnet_multi_session", "双会话按序整块展开（会话 2 首包 = 3；src .66/.67 distinct；实例 100/300）",
		chain(map[string]interface{}{"sessions": []interface{}{
			map[string]interface{}{"src_ip": "192.0.2.66", "device_instance": 100, "events": []interface{}{
				ev(map[string]interface{}{"kind": "who_is", "respond_i_am": true})}},
			map[string]interface{}{"src_ip": "192.0.2.67", "device_instance": 300, "events": []interface{}{
				ev(map[string]interface{}{"kind": "who_is", "respond_i_am": true})}},
		}}), 4,
		[]fld{
			{1, "ip.src", "", 0, []string{"192.0.2.66", "192.0.2.67"}, []string{"198.51.100.66"}},
			{4, "bacapp.instance_number", "300", 0, nil, nil},
		},
		[]fr{{3, 42, "810A000801001008"}},
		cliA, srv)

	// —— 38 大字符串 ——
	big1024 := strings.Repeat("z", 1024)
	add("bacnet_large_charstring", "1024B CharacterString（扩展长度档 fe 0401）单帧 1089B 不分片",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 8, "property": 77,
				"respond": map[string]interface{}{"ack": "complex",
					"value": map[string]interface{}{"type": "char_string", "value": big1024}}}),
		)}}), 2,
		[]fld{
			{2, "udp.length", "1055", 0, nil, nil},
		},
		[]fr{{2, 42, "810A0417010030080C0C00000000194D3E75FE0401007A7A"}},
		cliA, srv)

	// —— 39 Invoke 相邻 ——
	add("bacnet_invoke_id_adjacent", "Invoke 1 与 254 相邻值（ACK 回显）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 1, "property": 85,
				"respond": map[string]interface{}{"ack": "complex", "value": map[string]interface{}{"type": "real", "value": 22.5}}}),
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 254, "property": 85,
				"respond": map[string]interface{}{"ack": "complex", "value": map[string]interface{}{"type": "real", "value": 22.5}}}),
		)}}), 4,
		[]fld{
			{1, "bacapp.invoke_id", "", 0, []string{"1", "254"}, nil},
			{2, "bacapp.invoke_id", "1", 0, nil, nil},
		},
		[]fr{{3, 42, "810A001101040005FE0C0C000000001955"}},
		cliA, srv)

	// —— 40 实例相邻 ——
	add("bacnet_instance_adjacent", "实例 1 与 4194302（0x3FFFFE）相邻值",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 1, "instance": 1, "property": 85,
				"respond": map[string]interface{}{"ack": "complex", "value": map[string]interface{}{"type": "real", "value": 22.5}}}),
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 2, "instance": 4194302, "property": 85,
				"respond": map[string]interface{}{"ack": "complex", "value": map[string]interface{}{"type": "real", "value": 22.5}}}),
		)}}), 4,
		[]fld{
			{1, "bacapp.instance_number", "", 0, []string{"1", "4194302"}, nil},
		},
		[]fr{{3, 42, "810A001101040005020C0C003FFFFE1955"}},
		cliA, srv)

	// —— 41 对象类型边界 ——
	add("bacnet_object_type_boundaries", "类型 127（标准末值）与 1023（10 位满值）：0c 1fc00001 / 0c 3fc00001",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 1, "object_type": 127, "instance": 1, "property": 85,
				"respond": map[string]interface{}{"ack": "complex", "value": map[string]interface{}{"type": "real", "value": 22.5}}}),
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 2, "object_type": 1023, "instance": 1, "property": 85,
				"respond": map[string]interface{}{"ack": "complex", "value": map[string]interface{}{"type": "real", "value": 22.5}}}),
		)}}), 4,
		[]fld{{3, "bacapp.objectType", "1023", 0, nil, nil}},
		[]fr{{1, 42, "810A001101040005010C0C1FC000011955"}, {3, 42, "810A001101040005020C0CFFC000011955"}},
		cliA, srv)

	// —— 42 优先级边界 ——
	add("bacnet_priority_boundaries", "WP 优先级显式 1 与显式 16（4901/4910 三形态之二）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "write_property", "invoke_id": 1, "property": 85,
				"value": map[string]interface{}{"type": "boolean", "value": true}, "priority": 1,
				"respond": map[string]interface{}{"ack": "simple"}}),
			ev(map[string]interface{}{"kind": "write_property", "invoke_id": 2, "property": 85,
				"value": map[string]interface{}{"type": "boolean", "value": true}, "priority": 16,
				"respond": map[string]interface{}{"ack": "simple"}}),
		)}}), 4,
		[]fld{
			{1, "bacapp.invoke_id", "1", 0, nil, nil},
			{3, "bacapp.invoke_id", "2", 0, nil, nil},
		},
		[]fr{{1, 42, "810A001601040005010F0C0000000019553E113F4901"}, {3, 42, "810A001601040005020F0C0000000019553E113F4910"}},
		cliA, srv)

	// —— 43 窗口边界 ——
	add("bacnet_window_size_boundaries", "窗口 1 逐段确认（4 帧）与窗口 255 整窗确认（3 帧）——提议值非段数",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "segmented_request", "invoke_id": 1, "window_size": 1,
				"value": map[string]interface{}{"type": "char_string", "value": big465}, "priority": 8}),
			ev(map[string]interface{}{"kind": "segmented_request", "invoke_id": 2, "window_size": 255,
				"value": map[string]interface{}{"type": "char_string", "value": big465}, "priority": 8}),
		)}}), 7,
		[]fld{
			{1, "bacapp.window_size", "1", 0, nil, nil},
			{5, "bacapp.window_size", "255", 0, nil, nil},
			{4, "bacapp.sequence_number", "1", 0, nil, nil},
		},
		[]fr{{1, 42, "810A001401040C230100010F"}, {5, 42, "810A001401040C230200FF0F"}},
		cliA, srv)

	// —— 44 厂商上界 ——
	add("bacnet_vendor_id_max", "I-Am 厂商 ID 65535（u16 上界 22 ffff）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "i_am", "device_instance": 200, "max_apdu": 1476, "segmentation": 3, "vendor_id": 65535}),
		)}}), 1,
		[]fld{{1, "bacapp.vendor_identifier", "65535", 0, nil, nil}},
		[]fr{{1, 42, "810A001501001000C4020000C82205C4910322FFFF"}},
		cliA, srv)

	// —— 45 TTL 上界 ——
	add("bacnet_ttl_max", "RFD TTL 65535（u16 上界）→ Result",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "register_foreign_device", "ttl": 65535}),
		)}}), 2,
		[]fld{{1, "bvlc.reg_ttl", "65535", 0, nil, nil}},
		[]fr{{1, 42, "81050006FFFF"}},
		cliA, srv)

	// —— 46 非默认端口 ——
	add("bacnet_port_nondefault", "显式 47809（src=dst）：BACnet 字节与用例 1 一致，DecodeAs 解码",
		portLayers(), 2,
		[]fld{
			{1, "udp.srcport", "47809", 0, nil, nil},
			{1, "udp.dstport", "47809", 0, nil, nil},
			{1, "bacapp.unconfirmed_service", "8", 0, nil, nil},
		},
		[]fr{{1, 42, "810A000C0100100809001964"}},
		cliA, srv, "udp.port==47809,bvlc")

	// —— 47 并发会话 ——
	add("bacnet_concurrent_sessions", "concurrent 双客户端交错（up 帧源 IP 交替，各自事务配对完整）",
		chain(map[string]interface{}{"concurrent": true, "sessions": []interface{}{
			map[string]interface{}{"src_ip": "192.0.2.66", "events": []interface{}{
				ev(map[string]interface{}{"kind": "who_is"}),
				ev(map[string]interface{}{"kind": "i_am", "device_instance": 100})}},
			map[string]interface{}{"src_ip": "192.0.2.67", "events": []interface{}{
				ev(map[string]interface{}{"kind": "who_is"}),
				ev(map[string]interface{}{"kind": "i_am", "device_instance": 300})}},
		}}), 4,
		[]fld{
			{1, "ip.src", "192.0.2.66", 0, nil, nil},
			{2, "ip.src", "192.0.2.67", 0, nil, nil},
			{3, "ip.dst", "192.0.2.66", 0, nil, nil},
			{4, "ip.dst", "192.0.2.67", 0, nil, nil},
		},
		[]fr{{1, 42, "810A000801001008"}},
		cliA, srv)

	// —— 48 Who-Has 范围对 ——
	add("bacnet_who_has_limits", "Who-Has [0][1] 范围对（0/100）+ [2] 对象 ID 分支 → I-Have",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "who_has", "low": 0, "high": 100, "object_type": 0, "instance": 1}),
			ev(map[string]interface{}{"kind": "i_have", "device_instance": 100, "object_type": 0, "instance": 1, "object_name": "ai-1"}),
		)}}), 2,
		[]fld{{1, "bacapp.unconfirmed_service", "7", 0, nil, nil}},
		[]fr{{1, 42, "810A001101001007090019642C00000001"}},
		cliA, srv)

	// —— 49 RPM 双对象 ——
	add("bacnet_rpm_multi_object", "RPM 双对象（ai:1 与 device:5 各双属性）→ ComplexACK 双对象多值",
		rpmMultiObjectLayers(), 2,
		[]fld{
			{1, "bacapp.objectType", "0,8", 0, nil, nil},
			{1, "bacapp.instance_number", "1,5", 0, nil, nil},
			{1, "bacapp.property_identifier", "85,77,85,77", 0, nil, nil},
			{2, "bacapp.objectType", "0,8", 0, nil, nil},
			{2, "bacapp.instance_number", "1,5", 0, nil, nil},
			{2, "bacapp.property_identifier", "85,77,85,77", 0, nil, nil},
			{2, "bacapp.object_name", "obj,obj", 0, nil, nil},
		},
		[]fr{{1, 42, "810A002001040005010E0C000000011E0955094D1F0C020000051E0955094D1F"}},
		cliA, srv)

	// —— 50 DCC 变体 ——
	add("bacnet_dcc_variants", "DCC 三变体：enable+duration 30 / disable-initiation+duration 0 / 缺省 [0]+disable 1",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "dcc", "invoke_id": 1, "duration": 30, "disable": 0,
				"respond": map[string]interface{}{"ack": "simple"}}),
			ev(map[string]interface{}{"kind": "dcc", "invoke_id": 2, "duration": 0, "disable": 2,
				"respond": map[string]interface{}{"ack": "simple"}}),
			ev(map[string]interface{}{"kind": "dcc", "invoke_id": 3, "disable": 1,
				"respond": map[string]interface{}{"ack": "simple"}}),
		)}}), 6,
		[]fld{{1, "bacapp.confirmed_service", "17", 0, nil, nil}},
		[]fr{{1, 42, "810A000F0104000501110A001E1900"}, {3, 42, "810A000F0104000502110A00001902"}, {5, 42, "810A000C0104000503111901"}},
		cliA, srv)

	// —— 51 COV unconfirmed ——
	add("bacnet_subscribe_cov_unconfirmed", "SubscribeCOV [2] 存在且 FALSE（2900）+ lifetime",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "subscribe_cov", "invoke_id": 3, "process_id": 1,
				"object_type": 8, "instance": 5, "issue_confirmed": false, "lifetime": 600,
				"respond": map[string]interface{}{"ack": "simple"}}),
		)}}), 2,
		[]fld{{2, "bacapp.confirmed_service", "5", 0, nil, nil}},
		[]fr{{1, 42, "810A001601040005030509011C0200000529003A0258"}},
		cliA, srv)

	// —— 52 SA bit ——
	add("bacnet_confirmed_request_sa", "Confirmed-REQ 首字节 SA bit1=1（02）客户端声明接受分段响应",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 1, "property": 85, "sa": true,
				"respond": map[string]interface{}{"ack": "complex", "value": map[string]interface{}{"type": "real", "value": 22.5}}}),
		)}}), 2,
		[]fld{{1, "bacapp.invoke_id", "1", 0, nil, nil}},
		[]fr{{1, 42, "810A001101040205010C0C000000001955"}},
		cliA, srv)

	// —— 53 全局广播 ——
	add("bacnet_npdu_global_broadcast", "NPDU 全局广播（DNET FFFF+DLEN 0+Hop FF，路由侧语义钉死）",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "who_is",
				"npdu": map[string]interface{}{"dest": map[string]interface{}{"net": 65535}}}),
		)}}), 1,
		[]fld{
			{1, "bacnet.dnet", "65535", 0, nil, nil},
			{1, "bacnet.dlen", "0", 0, nil, nil},
			{1, "bacnet.hopc", "255", 0, nil, nil},
		},
		[]fr{{1, 42, "810A000C0120FFFF00FF1008"}},
		cliA, srv)

	// —— 54 BDT 多表项 ——
	add("bacnet_bdt_multi_entry", "Write-BDT 双表项（len 0x18）+ Read-FDT-Ack 双表项",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "write_bdt", "entries": []interface{}{
				map[string]interface{}{"ip": "192.0.2.88", "port": 47808, "mask": "ffffff00"},
				map[string]interface{}{"ip": "192.0.2.90", "port": 47808, "mask": "ffffff00"}}}),
			ev(map[string]interface{}{"kind": "read_fdt", "respond": map[string]interface{}{"entries": []interface{}{
				map[string]interface{}{"ip": "192.0.2.99", "port": 47808, "ttl": 300, "timeout": 120},
				map[string]interface{}{"ip": "192.0.2.101", "port": 47808, "ttl": 60, "timeout": 30}}}}),
		)}}), 4,
		[]fld{
			{1, "bvlc.bdt_ip", "", 0, []string{"192.0.2.88,192.0.2.90"}, nil},
			{4, "bvlc.fdt_ip", "", 0, []string{"192.0.2.99,192.0.2.101"}, nil},
		},
		[]fr{{1, 42, "81010018C0000258BAC0FFFFFF00"}},
		cliA, srv)

	// —— 55 UCS-2 ——
	add("bacnet_charstring_ucs2", "charset 4（UCS-2）CharacterString：7303 直存（putLength 修复后合法）04 4e2d",
		chain(map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 9, "property": 77,
				"respond": map[string]interface{}{"ack": "complex",
					"value": map[string]interface{}{"type": "char_string", "charset": 4, "value": "中"}}}),
		)}}), 2,
		[]fld{
			{2, "bacapp.string_character_set", "4", 0, nil, nil},
			{2, "bacapp.object_name", "中", 0, nil, nil},
		},
		[]fr{{2, 42, "810A0016010030090C0C00000000194D3E73044E2D3F"}},
		cliA, srv)

	// —— 负例 56-97（wire_fault 注入口 + 主锚词；载体内形状负例按 §5）——
	// 负例定义（wire_fault 注入口 + 主锚词；值域自然面负例坏输入 + token
	// 双锚——dispatch 先行同锚词；载体形状负例以 offending 链形注入）。
	validRP := func() map[string]interface{} {
		return map[string]interface{}{"sessions": []interface{}{sess(
			ev(map[string]interface{}{"kind": "read_property", "invoke_id": 1, "property": 85,
				"respond": map[string]interface{}{"ack": "complex",
					"value": map[string]interface{}{"type": "real", "value": 22.5}}}))}}
	}
	neg := func(id, summary, anchor string, layersArr []interface{}) negCase {
		return negCase{id: id, summary: summary, layers: layersArr, anchor: anchor}
	}
	negWire := func(id, summary, anchor, fault string) negCase {
		cfg := validRP()
		cfg["wire_fault"] = fault
		return neg(id, summary, anchor, chain(cfg))
	}
	var negatives []negCase
	negatives = append(negatives,
		negWire("bacnet_neg_bvlc_type", "BVLC Type ≠0x81（如 0x80/0x82/0xFF）", "type", "bvlc_type"),
		negWire("bacnet_neg_bvlc_function", "BVLC Function ∉0x00–0x0B 明文功能域", "function", "bvlc_function"),
		negWire("bacnet_neg_bvlc_secure", "Secure-BVLL 0x0C 被当明文产生", "secure", "bvlc_secure"),
		negWire("bacnet_neg_bvlc_length_min", "BVLC Length <4", "length", "bvlc_length_min"),
		negWire("bacnet_neg_bvlc_length_mismatch", "BVLC Length ≠ 4+功能负载实际字节", "length", "bvlc_length_mismatch"),
		negWire("bacnet_neg_bvlc_length_forwarded", "Forwarded-NPDU Length 未计 6B 源地址", "length", "bvlc_length_forwarded"),
		negWire("bacnet_neg_npdu_version", "NPDU Version ≠0x01", "version", "npdu_version"),
		negWire("bacnet_neg_npdu_dest_missing", "Control bit5=1 而 DNET/HopCount 缺失", "dnet", "npdu_dest_missing"),
		negWire("bacnet_neg_npdu_src_len_zero", "Control bit3=1 而 SLEN=0", "snet", "npdu_src_len_zero"),
		negWire("bacnet_neg_npdu_reserved_bits", "Control 保留位 bit6/bit4 置 1", "control", "npdu_reserved_bits"),
		negWire("bacnet_neg_npdu_no_message_type", "Control bit7=1 而 Message Type 缺失", "control", "npdu_no_message_type"),
		negWire("bacnet_neg_npdu_dlen_invalid", "DLEN ∉{0,6}", "dlen", "npdu_dlen_invalid"),
		negWire("bacnet_neg_apdu_type_invalid", "APDU 首字节高 4 位 >7", "apdu", "apdu_type_invalid"),
		negWire("bacnet_neg_apdu_header_confirmed", "Confirmed-Request 头部不完整", "header", "apdu_header_confirmed"),
		negWire("bacnet_neg_apdu_header_simpleack", "SimpleACK <3 字节", "header", "apdu_header_simpleack"),
		negWire("bacnet_neg_service_confirmed_unimplemented", "确认服务不在子集（如 ReadRange 34）", "service", "service_confirmed_unimplemented"),
		negWire("bacnet_neg_service_unconfirmed_invalid", "非确认服务 ∉{0,1,2,7,8}", "service", "service_unconfirmed_invalid"),
		negWire("bacnet_neg_tag_lvt_mismatch", "LVT=4 而内容仅 2 字节", "lvt", "tag_lvt_mismatch"),
		negWire("bacnet_neg_tag_open_unmatched", "开标签无同号闭标签配对", "tag", "tag_open_unmatched"),
		negWire("bacnet_neg_tag_boolean_lvt", "Boolean 应用标签 LVT=2", "tag", "tag_boolean_lvt"),
		negWire("bacnet_neg_tag_context_number", "上下文标签号超出服务 ASN.1 定义", "tag", "tag_context_number"),
		negWire("bacnet_neg_segment_missing_fields", "SEG=1 缺 seq/window", "segment", "segment_missing_fields"),
		negWire("bacnet_neg_segment_sequence_skip", "seq 回绕/跳变", "sequence", "segment_sequence_skip"),
		negWire("bacnet_neg_port_undeclared", "端口 ≠47808 未显式声明（静默回退禁止）", "port", "port_undeclared"),
		negWire("bacnet_neg_address_family_derived", "从 IPv4 fixture 推导 IPv6 地址", "address", "address_family_derived"),
		negWire("bacnet_neg_state_iam_no_whois", "I-Am 无前置 Who-Is（注入通道；正例 31 钉独立宣告合法）", "state", "state_iam_no_whois"),
		negWire("bacnet_neg_state_cov_no_subscribe", "COV 通知无前置订阅（注入通道；正例 23 钉单帧通知合法）", "state", "state_cov_no_subscribe"),
		// 值域自然面负例（坏输入 + token，dispatch 先行同锚词）
		neg("bacnet_neg_object_type_overflow", "对象类型 >1023（10 位溢出，如 1024）", "object",
			chain(map[string]interface{}{"wire_fault": "object_type_overflow", "sessions": []interface{}{sess(
				ev(map[string]interface{}{"kind": "read_property", "object_type": 1024, "property": 85}))}})),
		neg("bacnet_neg_object_instance_overflow", "对象实例 >4194303（22 位溢出）", "instance",
			chain(map[string]interface{}{"wire_fault": "object_instance_overflow", "sessions": []interface{}{sess(
				ev(map[string]interface{}{"kind": "read_property", "instance": 4194304, "property": 85}))}})),
		neg("bacnet_neg_object_iam_not_device", "I-Am 设备标识对象类型 ≠8", "object",
			chain(map[string]interface{}{"wire_fault": "object_iam_not_device"})),
		neg("bacnet_neg_property_id_vendor", "属性 ID >511 未声明厂商私有", "property",
			chain(map[string]interface{}{"wire_fault": "property_id_vendor", "sessions": []interface{}{sess(
				ev(map[string]interface{}{"kind": "read_property", "property": 512}))}})),
		neg("bacnet_neg_property_index_negative", "数组下标为负（-1）", "property",
			chain(map[string]interface{}{"wire_fault": "property_index_negative", "sessions": []interface{}{sess(
				ev(map[string]interface{}{"kind": "read_property", "property": 85, "array_index": -1}))}})),
		neg("bacnet_neg_priority_range", "优先级 ∉1–16（0）", "priority",
			chain(map[string]interface{}{"wire_fault": "priority_range", "sessions": []interface{}{sess(
				ev(map[string]interface{}{"kind": "write_property", "property": 85,
					"value": map[string]interface{}{"type": "boolean", "value": true}, "priority": 0}))}})),
		neg("bacnet_neg_error_class_range", "error-class 越域（8）", "error",
			chain(map[string]interface{}{"wire_fault": "error_class_range", "sessions": []interface{}{sess(
				ev(map[string]interface{}{"kind": "read_property", "invoke_id": 1, "property": 85}),
				ev(map[string]interface{}{"kind": "error", "invoke_id": 1, "service_choice": 12, "error_class": 8, "error_code": 32}))}})),
		neg("bacnet_neg_invoke_mismatch", "应答 Invoke ≠ 触发请求 Invoke", "invoke",
			chain(map[string]interface{}{"wire_fault": "invoke_mismatch", "sessions": []interface{}{sess(
				ev(map[string]interface{}{"kind": "read_property", "invoke_id": 1, "property": 85}),
				ev(map[string]interface{}{"kind": "error", "invoke_id": 2, "service_choice": 12, "error_class": 2, "error_code": 32}))}})),
		neg("bacnet_neg_invoke_reuse", "未完成事务期间复用同一 Invoke ID", "invoke",
			chain(map[string]interface{}{"wire_fault": "invoke_reuse", "sessions": []interface{}{sess(
				ev(map[string]interface{}{"kind": "read_property", "invoke_id": 3, "property": 85}),
				ev(map[string]interface{}{"kind": "write_property", "invoke_id": 3,
					"value": map[string]interface{}{"type": "boolean", "value": true}}))}})),
		neg("bacnet_neg_segment_extra_fields", "SEG=0 却携带 seq/window", "segment",
			chain(map[string]interface{}{"wire_fault": "segment_extra_fields", "sessions": []interface{}{sess(
				ev(map[string]interface{}{"kind": "read_property", "property": 85, "window_size": 2}))}})),
		neg("bacnet_neg_segment_window_zero", "提议窗口 0（合法 1-255）", "window",
			chain(map[string]interface{}{"wire_fault": "segment_window_zero", "sessions": []interface{}{sess(
				ev(map[string]interface{}{"kind": "segmented_request", "invoke_id": 1, "window_size": 0,
					"value": map[string]interface{}{"type": "char_string", "value": big465}}))}})),
		// 载体形状负例
		neg("bacnet_neg_carrier_layer_missing", "层链缺 udp（[bacnet] 直连）", "carrier",
			[]interface{}{bacnetLayer(map[string]interface{}{})}),
		neg("bacnet_neg_carrier_tcp", "TCP 载体声明（BACnet/IP 仅 UDP，Annex J）", "carrier",
			[]interface{}{ipLayer(cliA, srv), map[string]interface{}{"tcp": map[string]interface{}{"src_port": 47808, "dst_port": 47808}}, bacnetLayer(map[string]interface{}{})}),
		neg("bacnet_neg_address_family_mismatch", "IPv6 地址配 IPv4 层链", "family",
			[]interface{}{ipLayer("192.0.2.66", "2001:db8::1"), udpLayer(47808, 47808), bacnetLayer(map[string]interface{}{})}),
		neg("bacnet_neg_state_ack_no_request", "ACK/Error 事件无前置确认请求", "state",
			chain(map[string]interface{}{"wire_fault": "state_ack_no_request", "sessions": []interface{}{sess(
				ev(map[string]interface{}{"kind": "error", "invoke_id": 9, "service_choice": 12, "error_class": 2, "error_code": 32}))}})),
	)
	negMap := map[string]negCase{}
	for _, nc := range negatives {
		negMap[nc.id] = nc
	}
	// §5 表 56-97 逐行同序（三方同序——契约 §7.10）。
	order := []string{
		"bacnet_neg_bvlc_type", "bacnet_neg_bvlc_function", "bacnet_neg_bvlc_secure",
		"bacnet_neg_bvlc_length_min", "bacnet_neg_bvlc_length_mismatch", "bacnet_neg_bvlc_length_forwarded",
		"bacnet_neg_npdu_version", "bacnet_neg_npdu_dest_missing", "bacnet_neg_npdu_src_len_zero",
		"bacnet_neg_npdu_reserved_bits", "bacnet_neg_npdu_no_message_type", "bacnet_neg_npdu_dlen_invalid",
		"bacnet_neg_apdu_type_invalid", "bacnet_neg_apdu_header_confirmed", "bacnet_neg_apdu_header_simpleack",
		"bacnet_neg_service_confirmed_unimplemented", "bacnet_neg_service_unconfirmed_invalid",
		"bacnet_neg_tag_lvt_mismatch", "bacnet_neg_tag_open_unmatched", "bacnet_neg_tag_boolean_lvt",
		"bacnet_neg_tag_context_number",
		"bacnet_neg_object_type_overflow", "bacnet_neg_object_instance_overflow", "bacnet_neg_object_iam_not_device",
		"bacnet_neg_property_id_vendor", "bacnet_neg_property_index_negative", "bacnet_neg_priority_range",
		"bacnet_neg_error_class_range",
		"bacnet_neg_invoke_mismatch", "bacnet_neg_invoke_reuse",
		"bacnet_neg_segment_extra_fields", "bacnet_neg_segment_missing_fields", "bacnet_neg_segment_window_zero",
		"bacnet_neg_segment_sequence_skip",
		"bacnet_neg_carrier_layer_missing", "bacnet_neg_carrier_tcp", "bacnet_neg_port_undeclared",
		"bacnet_neg_address_family_mismatch", "bacnet_neg_address_family_derived",
		"bacnet_neg_state_ack_no_request", "bacnet_neg_state_iam_no_whois", "bacnet_neg_state_cov_no_subscribe",
	}
	var negatives2 []negCase
	for _, id := range order {
		nc, ok := negMap[id]
		if !ok {
			t.Fatalf("negative %s missing", id)
		}
		negatives2 = append(negatives2, nc)
	}
	negatives = negatives2
	if len(negatives) != 42 {
		t.Fatalf("want 42 negatives, ordered %d", len(negatives))
	}

	// —— 组装 JSON ——
	type outCase struct {
		ID      string                 `json:"id"`
		Proto   string                 `json:"proto"`
		Summary string                 `json:"summary"`
		Spec    map[string]interface{} `json:"spec_json"`
		Expect   map[string]interface{} `json:"expect"`
		DecodeAs []string               `json:"decode_as,omitempty"` // 顶层（pcaptest.Case 形状）
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
		out = append(out, outCase{ID: pc.id, Proto: "bacnet", Summary: pc.summary, Spec: map[string]interface{}{"layers": pc.layers}, Expect: expect, DecodeAs: pc.decodeAs})
	}
	for _, nc := range negatives {
		out = append(out, outCase{ID: nc.id, Proto: "bacnet", Summary: nc.summary,
			Spec:   map[string]interface{}{"layers": nc.layers},
			Expect: map[string]interface{}{"expect_error": true, "error_contains": nc.anchor}})
	}
	if len(out) != 97 {
		t.Fatalf("want 97 cases, built %d", len(out))
	}
	b, err := json.MarshalIndent(out, "", " ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile("../../../test/protocol_pcap/cases/bacnet.json", b, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("wrote %d cases", len(out))
}

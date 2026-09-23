package layers_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/bacnet" // init 注册 bacnet 终结层生成器+校验器
)

// D-BACNET-1 P4 链级红例（xmrmining_chain_test 先例同构）：
// ①who_is→I-Am 基线字节钉（BVLC 0x0a/len 12、无符号 u16 宽度 22 000f、
// NPDU control 0x00）/②min frame 8B 缺省基线/③who_has 名字分支 ctx3
// CharacterString/④RP 请求→ComplexACK Real 大端（41b40000=22.5）/⑤WP
// 布尔+优先级 49 08→SimpleACK/⑥RFD→BVLC-Result 0x0000（规则⑤）/⑦
// distribute 无 Result（规则⑤例外，1 帧）/⑧NPDU dest（control 0x20+DNET
// +hop）/⑨分两段 WriteProperty（值边界分割 8|473 + SegmentACK seq=1
// window=2 SRV=1）/⑩多会话按序展开（会话 2 首包=前会话总数+1，SrcIP
// 覆盖）/⑪concurrent 交错/⑫error 应答 invoke 配对；负例⑬自然面值域
// （object_type 溢出/priority 0/property>511/array -1/npdu src SLEN=0/
// window=0/unsegmented window/invoke_reuse/error 无前置请求/invoke_mismatch/
// ttl 负/npdu priority 4）/⑭未知 kind/⑮未知 wire_fault/⑯carrier 三形状
// （缺 udp/tcp 载体/混合地址族）。
// 契约 fixture：客户端 192.0.2.66 / 设备 198.51.100.66 / 端口 47808 /
// I-Am 100/1476/3/15。

func bacnetChainJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, _ := json.Marshal(layersArr)
	return out
}

func bacnetLayers(cfg map[string]interface{}, ipSrc, ipDst string) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": ipSrc, "dst": ipDst}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": 47808, "dst_port": 47808}},
		map[string]interface{}{"bacnet": cfg},
	}
}

func planBACNETChainAt(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("bacnet", bacnetChainJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: "192.0.2.66", DstIP: "198.51.100.66", SrcPort: 47808, DstPort: 47808}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		return nil, err
	}
	var pkts []core.PacketConfig
	for c := range ch {
		pkts = append(pkts, c)
	}
	return pkts, nil
}

func driveBACNET(t *testing.T, cfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := planBACNETChainAt(t, bacnetLayers(cfg, "192.0.2.66", "198.51.100.66"))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func driveBACNETErrAt(t *testing.T, layersArr []interface{}) error {
	t.Helper()
	_, err := planBACNETChainAt(t, layersArr)
	return err
}

func driveBACNETErr(t *testing.T, cfg map[string]interface{}) error {
	t.Helper()
	_, err := planBACNETChainAt(t, bacnetLayers(cfg, "192.0.2.66", "198.51.100.66"))
	return err
}

func bacnetHex(t *testing.T, pkts []core.PacketConfig, idx int) string {
	t.Helper()
	if idx >= len(pkts) {
		t.Fatalf("packet %d out of range (have %d packets)", idx, len(pkts))
	}
	return strings.ToUpper(hex.EncodeToString(pkts[idx].Payload))
}

// ① 基线：who_is(low 0, high 100, respond_i_am) 2 帧——帧 1 与正例 1 帧 1
// 逐字节同（81 0a 00 0c 01 00 10 08 09 00 19 64），帧 2 I-Am u16 宽度
// （22 05c4 / 91 03 / 22 000f）与实例 c4 02000064。
func TestBACNETChain_WhoIsBaselineBytes(t *testing.T) {
	pkts := driveBACNET(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "who_is", "low": 0, "high": 100, "respond_i_am": true},
			},
		}},
	})
	if len(pkts) != 2 {
		t.Fatalf("want 2 packets, got %d", len(pkts))
	}
	if got := bacnetHex(t, pkts, 0); got != "810A000C0100100809001964" {
		t.Fatalf("frame 1 mismatch: %s", got)
	}
	if got := bacnetHex(t, pkts, 1); got != "810A001501001000C4020000642205C4910322000F" {
		t.Fatalf("frame 2 mismatch: %s", got)
	}
	if pkts[0].Direction != "up" || pkts[1].Direction != "down" {
		t.Fatalf("directions: %s / %s", pkts[0].Direction, pkts[1].Direction)
	}
}

// ② 缺省基线：空配置 1 帧 8B 最小帧（正例 2 形态）。
func TestBACNETChain_EmptyBaselineMinFrame(t *testing.T) {
	pkts := driveBACNET(t, map[string]interface{}{})
	if len(pkts) != 1 || bacnetHex(t, pkts, 0) != "810A000801001008" {
		t.Fatalf("want single 8B min frame, got %d pkts / %s", len(pkts), bacnetHex(t, pkts, 0))
	}
}

// ③ who_has 名字分支：ctx3 CharacterString（3d 05 00 61692d31，正例 21 帧 1）。
func TestBACNETChain_WhoHasNameBranch(t *testing.T) {
	pkts := driveBACNET(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "who_has", "object_name": "ai-1"},
			},
		}},
	})
	if got := bacnetHex(t, pkts, 0); got != "810A000F010010073D050061692D31" {
		t.Fatalf("who_has mismatch: %s", got)
	}
}

// ④ RP 请求→ComplexACK Real 大端（41B40000=22.5，正例 16 双帧同构）。
func TestBACNETChain_ReadPropertyAckReal(t *testing.T) {
	pkts := driveBACNET(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{
					"kind": "read_property", "invoke_id": 1,
					"object_type": 0, "instance": 1, "property": 85,
					"respond": map[string]interface{}{
						"ack":   "complex",
						"value": map[string]interface{}{"type": "real", "value": 22.5},
					},
				},
			},
		}},
	})
	if len(pkts) != 2 {
		t.Fatalf("want 2 packets, got %d", len(pkts))
	}
	if got := bacnetHex(t, pkts, 0); got != "810A001101040005010C0C000000011955" {
		t.Fatalf("rp request mismatch: %s", got)
	}
	if got := bacnetHex(t, pkts, 1); got != "810A0017010030010C0C0000000119553E4441B400003F" {
		t.Fatalf("rp ack mismatch: %s", got)
	}
}

// ⑤ WP 布尔 TRUE + 优先级 8（3e 11 3f 49 08，正例 19）→ SimpleACK。
func TestBACNETChain_WritePropertyPrioritySimpleAck(t *testing.T) {
	pkts := driveBACNET(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{
					"kind": "write_property", "invoke_id": 2,
					"object_type": 0, "instance": 1, "property": 85,
					"value": map[string]interface{}{"type": "boolean", "value": true},
					"priority": 8,
					"respond":  map[string]interface{}{"ack": "simple"},
				},
			},
		}},
	})
	if len(pkts) != 2 {
		t.Fatalf("want 2 packets, got %d", len(pkts))
	}
	if got := bacnetHex(t, pkts, 0); got != "810A001601040005020F0C0000000119553E113F4908" {
		t.Fatalf("wp request mismatch: %s", got)
	}
	if got := bacnetHex(t, pkts, 1); got != "810A0009010020020F" {
		t.Fatalf("simpleack mismatch: %s", got)
	}
}

// ⑥ RFD→自动 BVLC-Result 0x0000（规则⑤，正例 5 帧 1/2 同构）。
func TestBACNETChain_RegisterForeignDeviceResult(t *testing.T) {
	pkts := driveBACNET(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "register_foreign_device", "ttl": 600}},
		}},
	})
	if len(pkts) != 2 {
		t.Fatalf("want 2 packets, got %d", len(pkts))
	}
	if got := bacnetHex(t, pkts, 0); got != "810500060258" {
		t.Fatalf("rfd mismatch: %s", got)
	}
	if got := bacnetHex(t, pkts, 1); got != "810000060000" {
		t.Fatalf("result mismatch: %s", got)
	}
}

// ⑦ Distribute-Broadcast 静默转发不补 Result（规则⑤例外，正例 11）。
func TestBACNETChain_DistributeNoResult(t *testing.T) {
	pkts := driveBACNET(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{
				"kind":  "distribute_broadcast",
				"inner": map[string]interface{}{"kind": "who_is", "low": 0, "high": 100},
			}},
		}},
	})
	if len(pkts) != 1 {
		t.Fatalf("want 1 packet, got %d", len(pkts))
	}
	if got := bacnetHex(t, pkts, 0); got != "8109000C0100100809001964" {
		t.Fatalf("distribute mismatch: %s", got)
	}
}

// ⑧ NPDU dest 修饰：control 0x20 + DNET 2001 + DLEN 6 + DADR + hop FF
// （正例 12 帧 1 同构）。
func TestBACNETChain_NPDUDestAddress(t *testing.T) {
	pkts := driveBACNET(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{
				"kind": "who_is",
				"npdu": map[string]interface{}{
					"dest": map[string]interface{}{"net": 2001, "ip": "192.0.2.99", "port": 47808},
				},
			}},
		}},
	})
	if got := bacnetHex(t, pkts, 0); !strings.HasPrefix(got, "810A0012012007D106C0000263BAC0FF1008") {
		t.Fatalf("npdu dest mismatch: %s", got)
	}
}

// ⑨ 分段 WriteProperty：465B CharacterString 天然超 480 → 2 段
// （首段 8B 参数+开[3]、末段 470B 值+闭[3]+49 08）+ SegmentACK
// （41 06 01 02 SRV=1）。正例 29 全形态。
func TestBACNETChain_SegmentedWriteProperty(t *testing.T) {
	big := strings.Repeat("BACnetSegment.", 33) + "BAC" // 465B
	if len(big) != 465 {
		t.Fatalf("fixture content length %d", len(big))
	}
	pkts := driveBACNET(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{
				"kind": "segmented_request", "invoke_id": 6, "window_size": 2,
				"object_type": 0, "instance": 1, "property": 85,
				"value": map[string]interface{}{"type": "char_string", "value": big},
				"priority": 8,
			}},
		}},
	})
	if len(pkts) != 3 {
		t.Fatalf("want 3 packets (seg0,seg1,SegmentACK), got %d", len(pkts))
	}
	s0 := bacnetHex(t, pkts, 0)
	s1 := bacnetHex(t, pkts, 1)
	ack := bacnetHex(t, pkts, 2)
	if !strings.HasPrefix(s0, "810A001401040C230600020F0C0000000119553E") {
		t.Fatalf("seg0 header mismatch: %s", s0)
	}
	// 末段：0x08（仅 SEG）+ invoke 06 + seq 01 + window 02 + service 0f +
	// 扩展长度 charstring 75 FE 01D2 00 + close 3f + 49 08。
	if !strings.HasPrefix(s1, "810A01E5010408230601020F75FE01D200") || !strings.HasSuffix(s1, "3F4908") {
		t.Fatalf("seg1 mismatch: %s", s1)
	}
	if ack != "810A000A010041060102" {
		t.Fatalf("segmentack mismatch: %s", ack)
	}
}

// ⑩ 多会话按序整块展开：会话 2 首包 = 前会话总包 + 1，SrcIP 覆盖 up 直落
// （正例 37）。
func TestBACNETChain_MultiSessionSequential(t *testing.T) {
	pkts := driveBACNET(t, map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{
				"src_ip": "192.0.2.66", "device_instance": 100,
				"events": []interface{}{
					map[string]interface{}{"kind": "who_is", "respond_i_am": true},
				},
			},
			map[string]interface{}{
				"src_ip": "192.0.2.67", "device_instance": 300,
				"events": []interface{}{
					map[string]interface{}{"kind": "who_is", "respond_i_am": true},
				},
			},
		},
	})
	if len(pkts) != 4 {
		t.Fatalf("want 4 packets, got %d", len(pkts))
	}
	if pkts[2].L3.SrcIP != "192.0.2.67" {
		t.Fatalf("session 2 first packet src = %q, want 192.0.2.67", pkts[2].L3.SrcIP)
	}
	// 会话 2 的 I-Am 实例 300（device_instance 会话缺省——规则①）。
	if got := bacnetHex(t, pkts, 3); !strings.Contains(got, "C40200012C") {
		t.Fatalf("session 2 i-am instance missing (want device:300 c4 0200012c): %s", got)
	}
}

// ⑪ concurrent 交错：event index round-robin（正例 47）。
func TestBACNETChain_ConcurrentInterleave(t *testing.T) {
	pkts := driveBACNET(t, map[string]interface{}{
		"concurrent": true,
		"sessions": []interface{}{
			map[string]interface{}{
				"src_ip": "192.0.2.66",
				"events": []interface{}{
					map[string]interface{}{"kind": "who_is"},
					map[string]interface{}{"kind": "i_am", "device_instance": 100},
				},
			},
			map[string]interface{}{
				"src_ip": "192.0.2.67",
				"events": []interface{}{
					map[string]interface{}{"kind": "who_is"},
					map[string]interface{}{"kind": "i_am", "device_instance": 300},
				},
			},
		},
	})
	if len(pkts) != 4 {
		t.Fatalf("want 4 packets, got %d", len(pkts))
	}
	// 交错序：A whois(up .66), B whois(up .67), A iam(down), B iam(down)——
	// up 帧源 IP 按会话交错，down 帧走链层交换（服务端源）。
	if pkts[0].L3.SrcIP != "192.0.2.66" || pkts[1].L3.SrcIP != "192.0.2.67" {
		t.Fatalf("up interleave order wrong: %v %v", pkts[0].L3.SrcIP, pkts[1].L3.SrcIP)
	}
	if pkts[2].Direction != "down" || pkts[3].Direction != "down" {
		t.Fatalf("down frames wrong: %v %v", pkts[2].Direction, pkts[3].Direction)
	}
	if pkts[2].L3.DstIP != "192.0.2.66" || pkts[3].L3.DstIP != "192.0.2.67" {
		t.Fatalf("down dst wrong: %v %v", pkts[2].L3.DstIP, pkts[3].L3.DstIP)
	}
}

// ⑫ Error 应答 invoke 配对（正例 26 同构：RP invoke 5 → 50 05 0c 91 02 91 20）。
func TestBACNETChain_ErrorInvokePairing(t *testing.T) {
	pkts := driveBACNET(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "read_property", "invoke_id": 5, "property": 85},
				map[string]interface{}{"kind": "error", "invoke_id": 5, "service_choice": 12, "error_class": 2, "error_code": 32},
			},
		}},
	})
	if len(pkts) != 2 {
		t.Fatalf("want 2 packets, got %d", len(pkts))
	}
	if got := bacnetHex(t, pkts, 1); got != "810A000D010050050C91029120" {
		t.Fatalf("error mismatch: %s", got)
	}
}

// ⑬ 自然面值域负例（红线词逐条）。
func TestBACNETChain_NaturalGuards(t *testing.T) {
	cases := []struct {
		name   string
		events []interface{}
		anchor string
	}{
		{"object_type_overflow", []interface{}{map[string]interface{}{"kind": "read_property", "object_type": 1024, "property": 85}}, "object"},
		{"object_instance_overflow", []interface{}{map[string]interface{}{"kind": "read_property", "object_type": 0, "instance": 4194304, "property": 85}}, "instance"},
		{"priority_zero", []interface{}{map[string]interface{}{"kind": "write_property", "value": map[string]interface{}{"type": "boolean", "value": true}, "priority": 0}}, "priority"},
		{"priority_17", []interface{}{map[string]interface{}{"kind": "write_property", "value": map[string]interface{}{"type": "boolean", "value": true}, "priority": 17}}, "priority"},
		{"property_vendor", []interface{}{map[string]interface{}{"kind": "read_property", "property": 512}}, "property"},
		{"array_index_negative", []interface{}{map[string]interface{}{"kind": "read_property", "property": 85, "array_index": -1}}, "property"},
		{"npdu_src_len_zero", []interface{}{map[string]interface{}{"kind": "who_is", "npdu": map[string]interface{}{"src": map[string]interface{}{"net": 1}}}}, "snet"},
		{"npdu_priority_4", []interface{}{map[string]interface{}{"kind": "who_is", "npdu": map[string]interface{}{"priority": 4}}}, "control"},
		{"segment_window_zero", []interface{}{map[string]interface{}{"kind": "segmented_request", "invoke_id": 1, "window_size": 0, "value": map[string]interface{}{"type": "boolean", "value": true}}}, "window"},
		{"segment_extra_fields", []interface{}{map[string]interface{}{"kind": "read_property", "property": 85, "window_size": 2}}, "segment"},
		{"invoke_reuse", []interface{}{
			map[string]interface{}{"kind": "read_property", "invoke_id": 3, "property": 85},
			map[string]interface{}{"kind": "write_property", "invoke_id": 3, "value": map[string]interface{}{"type": "boolean", "value": true}},
		}, "invoke"},
		{"error_no_request", []interface{}{map[string]interface{}{"kind": "error", "invoke_id": 9, "service_choice": 12, "error_class": 2, "error_code": 32}}, "state"},
		{"invoke_mismatch", []interface{}{
			map[string]interface{}{"kind": "read_property", "invoke_id": 1, "property": 85},
			map[string]interface{}{"kind": "error", "invoke_id": 2, "service_choice": 12, "error_class": 2, "error_code": 32},
		}, "invoke"},
		{"ttl_negative", []interface{}{map[string]interface{}{"kind": "register_foreign_device", "ttl": -1}}, "property"},
		{"unknown_kind", []interface{}{map[string]interface{}{"kind": "mystery"}}, "unknown event kind"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := driveBACNETErr(t, map[string]interface{}{"sessions": []interface{}{
				map[string]interface{}{"events": tc.events},
			}})
			if err == nil {
				t.Fatalf("expected rejection for %s", tc.name)
			}
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("error %q missing anchor %q", err.Error(), tc.anchor)
			}
		})
	}
}

// ⑭ 未知 wire_fault 分发拒。
func TestBACNETChain_UnknownWireFault(t *testing.T) {
	err := driveBACNETErr(t, map[string]interface{}{"wire_fault": "made_up_fault"})
	if err == nil || !strings.Contains(err.Error(), "unknown wire_fault") {
		t.Fatalf("want unknown wire_fault rejection, got %v", err)
	}
}

// ⑮ 载体三形状：缺 udp（carrier）/tcp 载体（carrier）/混合地址族（family）。
func TestBACNETChain_CarrierShapes(t *testing.T) {
	// 缺 udp：[ip, bacnet]
	_, err := planBACNETChainAt(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.66", "dst": "198.51.100.66"}},
		map[string]interface{}{"bacnet": map[string]interface{}{}},
	})
	if err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("missing udp: want carrier rejection, got %v", err)
	}
	// tcp 载体：[ip, tcp, bacnet]
	_, err = planBACNETChainAt(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.66", "dst": "198.51.100.66"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 47808, "dst_port": 47808}},
		map[string]interface{}{"bacnet": map[string]interface{}{}},
	})
	if err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("tcp carrier: want carrier rejection, got %v", err)
	}
	// 混合地址族：[ip(v4/v6), udp, bacnet]
	_, err = planBACNETChainAt(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.66", "dst": "2001:db8::1"}},
		map[string]interface{}{"udp": map[string]interface{}{}},
		map[string]interface{}{"bacnet": map[string]interface{}{}},
	})
	if err == nil || !strings.Contains(err.Error(), "family") {
		t.Fatalf("mixed family: want family rejection, got %v", err)
	}
}

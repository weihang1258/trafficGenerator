package layers_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/edp" // init 注册 edp 终结层生成器+校验器
)

// D-EDP-1 P4 链级红例（hl7_chain_test/mmse_chain_test 先例同构）：
// ①CONNREQ 方式 1/②方式 2（0xC0 空 devid）/③PING 最小帧/④SAVEDATA type1
// flag 0xC0 + SAVEACK msg_id 回带/⑤DISCONNECT 2 字节/⑥coalesce 多帧粘连
//（JoinNext，裁定7）/⑦并发会话交错（C-2）；负例⑧未知 wire_fault/⑨未知层键
//（裁定8 DisallowUnknownFields）/⑩未知 kind/⑪缺 apikey/⑫format 越域/
// ⑬connack_rtn 越域/⑭空会话。
// 契约 fixture 常量：devid=123456789 / apikey=kJ8mQ2xV / userid=284276 /
// authinfo=secret-auth-info / keep_time=128(0x0080) / msg_id=0x55AA(21930)。

// edpChainJSON builds the layers JSON [ip,tcp,edp] with the given edp cfg.
func edpChainJSON(t *testing.T, cfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.72", "dst": "198.51.100.72"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 41072, "dst_port": 4472}},
		map[string]interface{}{"edp": cfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func planEDPChain(t *testing.T, cfg map[string]interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("edp", edpChainJSON(t, cfg))
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: "192.0.2.72", DstIP: "198.51.100.72", SrcPort: 41072, DstPort: 4472}
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

func driveEDP(t *testing.T, cfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := planEDPChain(t, cfg)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func driveEDPErr(t *testing.T, cfg map[string]interface{}) error {
	t.Helper()
	_, err := planEDPChain(t, cfg)
	return err
}

func payloadHex(t *testing.T, pkts []core.PacketConfig, idx int) string {
	t.Helper()
	if idx >= len(pkts) {
		t.Fatalf("packet %d out of range (have %d packets)", idx, len(pkts))
	}
	return hex.EncodeToString(pkts[idx].Payload)
}

func connectEv() map[string]interface{} {
	return map[string]interface{}{"kind": "connect", "auth": "devid", "devid": "123456789", "apikey": "kJ8mQ2xV"}
}

// 红例① CONNREQ 方式 1（devid 鉴权 0x40）+ 自动 CONNRESP rtn=0。
// 契约 §4.1 全 32 字节帧：101e 000345445001 40 0080 0009+devid 0008+apikey。
func TestEDPChain_ConnectDevidMode(t *testing.T) {
	pkts := driveEDP(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{connectEv()},
		}},
	})
	// TCP 9 包 = 3 握手 + CONNREQ + CONNRESP + 4 挥手
	if len(pkts) != 9 {
		t.Fatalf("expected 9 packets (3 handshake + CONNREQ + CONNRESP + 4 teardown), got %d", len(pkts))
	}
	payload := payloadHex(t, pkts, 3)
	wantPrefix := "101e000345445001400080000931323334353637383900086b4a386d51327856"
	if !strings.HasPrefix(payload, wantPrefix) {
		t.Fatalf("CONNREQ payload mismatch:\n want prefix %s\n got prefix %s", wantPrefix, payload[:minInt(len(payload), len(wantPrefix))])
	}
	// 帧 5 = CONNRESP 20 02 00 00
	if got := payloadHex(t, pkts, 4); got != "20020000" {
		t.Fatalf("CONNRESP payload = %q, want 20020000", got)
	}
}

// 红例② CONNREQ 方式 2（userid 鉴权 0xC0 + 空 devid + userid + authinfo）。
// 契约 §4.2：1025 000345445001 c0 0080 0000 0006+userid 0010+authinfo。
func TestEDPChain_ConnectUseridMode(t *testing.T) {
	pkts := driveEDP(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{
				"kind": "connect", "auth": "userid", "userid": "284276", "authinfo": "secret-auth-info", "keep_time": 128,
			}},
		}},
	})
	if len(pkts) != 9 {
		t.Fatalf("expected 9 packets, got %d", len(pkts))
	}
	payload := payloadHex(t, pkts, 3)
	wantPrefix := "1025000345445001c000800000000632383432373600107365637265742d617574682d696e666f"
	if !strings.HasPrefix(payload, wantPrefix) {
		t.Fatalf("CONNREQ mode2 payload mismatch:\n want %s\n got  %s", wantPrefix, payload[:minInt(len(payload), len(wantPrefix))])
	}
}

// 红例③ PINGREQ→PINGRESP 最小 2 字节帧（c000 / d000）。
func TestEDPChain_PingMinimal(t *testing.T) {
	pkts := driveEDP(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{connectEv(), map[string]interface{}{"kind": "ping"}},
		}},
	})
	// 11 包 = 3 + CONNREQ + CONNRESP + PINGREQ + PINGRESP + 4 挥手
	if len(pkts) != 11 {
		t.Fatalf("expected 11 packets, got %d", len(pkts))
	}
	if got := payloadHex(t, pkts, 5); got != "c000" {
		t.Fatalf("PINGREQ payload = %q, want c000", got)
	}
	if got := payloadHex(t, pkts, 6); got != "d000" {
		t.Fatalf("PINGRESP payload = %q, want d000", got)
	}
}

// 红例④ SAVEDATA flag 0xC0（devid+msg_id）type1 + 自动 SAVEACK（msg_id 回带）。
// 契约 §4.8 存储帧前缀 8067 c0 0009+devid 55aa 01 0056+JSON。
func TestEDPChain_SavedataType1FlagC0(t *testing.T) {
	pkts := driveEDP(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				connectEv(),
				map[string]interface{}{
					"kind": "savedata", "direction": "up", "devid_flag": 1, "msg_id_flag": 1, "devid": "123456789",
					"msg_id": 21930, "format": 1, "ack": true,
					"json": `{"datastreams":[{"id":"temp","datapoints":[{"at":"2026-08-31 12:00:00","value":22}]}]}`,
				},
			},
		}},
	})
	// 11 包 = 3 + CONNREQ + CONNRESP + SAVEDATA + SAVEACK + 4
	if len(pkts) != 11 {
		t.Fatalf("expected 11 packets, got %d", len(pkts))
	}
	payload := payloadHex(t, pkts, 5)
	wantPrefix := "8067c0000931323334353637383955aa010056"
	if !strings.HasPrefix(payload, wantPrefix) {
		t.Fatalf("SAVEDATA payload mismatch:\n want prefix %s\n got prefix %s", wantPrefix, payload[:minInt(len(payload), len(wantPrefix))])
	}
	// SAVEACK（帧 7）回带 msg_id=21930 → JSON 内含 21930
	ackPayload := string(pkts[6].Payload)
	if !strings.Contains(ackPayload, "21930") {
		t.Fatalf("SAVEACK payload %q lacks msg_id 21930 echo", ackPayload)
	}
	if pkts[6].Payload[0] != 0x90 {
		t.Fatalf("SAVEACK first byte = 0x%02x, want 0x90", pkts[6].Payload[0])
	}
}

// 红例⑤ DISCONNECT 2 字节最小帧（4000）。
func TestEDPChain_DisconnectMinimal(t *testing.T) {
	pkts := driveEDP(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{connectEv(), map[string]interface{}{"kind": "disconnect"}},
		}},
	})
	if len(pkts) != 10 {
		t.Fatalf("expected 10 packets (3+CONNREQ+CONNRESP+DISCONNECT+4), got %d", len(pkts))
	}
	if got := payloadHex(t, pkts, 5); got != "4000" {
		t.Fatalf("DISCONNECT payload = %q, want 4000", got)
	}
}

// 红例⑥ coalesce 多帧粘连：同向相邻帧拼一个 TCP 段（JoinNext 累积-冲洗，
// 裁定7/契约 §6 用例 43 多帧粘连合法形态——两帧一个段）。请求/响应对不
// 粘（hl7 先例：请求必须先于其派生应答帧）。
func TestEDPChain_CoalesceJoinNext(t *testing.T) {
	pkts := driveEDP(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"coalesce": true,
			"events": []interface{}{
				connectEv(),
				map[string]interface{}{"kind": "pushdata", "direction": "up", "devid": "987654321", "data_b64": "R0FURVdBWTpIRUxMTw=="},
				map[string]interface{}{"kind": "pushdata", "direction": "up", "devid": "987654321", "data_b64": "R0FURVdBWTpIRUxMTw=="},
			},
		}},
	})
	// 两帧上行 PUSHDATA 粘一个段：TCP 包数 = 3 + CONNREQ + CONNRESP +
	// 粘连段 + 4 挥手 = 10（契约 §4.43 edp_multi_frame_segment 同包数）。
	if len(pkts) != 10 {
		t.Fatalf("expected 10 packets with coalesce (3+1+1+1+4), got %d", len(pkts))
	}
	merged := payloadHex(t, pkts, 5)
	// 两帧 PUSHDATA 顺序拼接（§3.7：30 + remainlen 0x18 = 2+9+13 +
	// devid u16 + devid + 裸 data 13B，无 data 长度前缀）。
	wantOne := "30180009393837363534333231474154455741593a48454c4c4f"
	if !strings.HasPrefix(merged, wantOne) || !strings.HasSuffix(merged, wantOne) || merged == wantOne {
		t.Fatalf("coalesced segment should be two PUSHDATA frames back to back, got %s", merged)
	}
}

// 红例⑦ 并发会话：双会话交错回放，包总数 = 两会话之和（v2.1 C-2）。
func TestEDPChain_ConcurrentSessions(t *testing.T) {
	pkts := driveEDP(t, map[string]interface{}{
		"concurrent": true,
		"sessions": []interface{}{
			map[string]interface{}{"src_port": 41072, "dst_port": 4472, "events": []interface{}{
				connectEv(),
			}},
			map[string]interface{}{"src_port": 41073, "dst_port": 4472, "events": []interface{}{
				map[string]interface{}{"kind": "connect", "auth": "devid", "devid": "987654321", "apikey": "zZ9yX8wV"},
			}},
		},
	})
	// 双会话各 9 包 = 18 包（并发交错，包总数不变）
	if len(pkts) != 18 {
		t.Fatalf("expected 18 packets (2 sessions × 9), got %d", len(pkts))
	}
}

// ——负例（validator/translate 面）——

// 红例⑧ 未知 wire_fault 值即拒（28 值闭环，裁定4）。
func TestEDPChain_UnknownWireFault(t *testing.T) {
	err := driveEDPErr(t, map[string]interface{}{"wire_fault": "not_a_known_fault"})
	if err == nil {
		t.Fatal("unknown wire_fault should be rejected")
	}
}

// 红例⑨ 未知层键即拒（translate DisallowUnknownFields，裁定8）。
func TestEDPChain_UnknownLayerKey(t *testing.T) {
	_, err := planEDPChain(t, map[string]interface{}{"bogus_key": 1})
	if err == nil {
		t.Fatal("unknown edp layer key should be rejected (DisallowUnknownFields)")
	}
}

// 红例⑩ 未知消息 kind 即拒。
func TestEDPChain_UnknownKind(t *testing.T) {
	err := driveEDPErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "bogus_kind"}},
		}},
	})
	if err == nil {
		t.Fatal("unknown event kind should be rejected")
	}
}

// 红例⑪ 方式 1 缺 apikey 即拒（auth_apikey_empty）。
func TestEDPChain_ConnectMissingApikey(t *testing.T) {
	err := driveEDPErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "connect", "auth": "devid", "devid": "123456789"}},
		}},
	})
	if err == nil {
		t.Fatal("devid connect without apikey should be rejected")
	}
}

// 红例⑫ savedata format 越域即拒（format_flag，0x01–0x05 值域外）。
func TestEDPChain_SavedataFormatRange(t *testing.T) {
	err := driveEDPErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				connectEv(),
				map[string]interface{}{"kind": "savedata", "devid": "123456789", "format": 6, "json": "{}"},
			},
		}},
	})
	if err == nil {
		t.Fatal("savedata format 6 should be rejected (0x01-0x05 domain)")
	}
}

// 红例⑬ connack_rtn 越域即拒（connack_rtn，0–9 值域外）。
func TestEDPChain_ConnackRtnRange(t *testing.T) {
	err := driveEDPErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "connect", "auth": "devid", "devid": "123456789", "apikey": "kJ8mQ2xV", "connack_rtn": 10},
			},
		}},
	})
	if err == nil {
		t.Fatal("connack_rtn 10 should be rejected (0-9 domain)")
	}
}

// 红例⑭ 空会话即拒（events 空）。
func TestEDPChain_EmptySession(t *testing.T) {
	err := driveEDPErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{}},
	})
	if err == nil {
		t.Fatal("session with no events should be rejected")
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// 红例⑮ wire_fault 注入锚词模型：已知 fault → validator 拒且错误含 §7
// 主锚词（28 负例全部依赖此通道——裁定4）；未知 fault 同样拒。
func TestEDPChain_WireFaultAnchors(t *testing.T) {
	cases := []struct{ fault, anchor string }{
		{"type_unknown", "type"},
		{"remainlen_mismatch", "remainlen"},
		{"remainlen_truncated", "truncat"},
		{"state_no_connect", "connect"},
		{"json_over_u16", "json"},
		{"carrier_udp", "carrier"},
		{"auth_apikey_empty", "apikey"},
		{"connack_rtn", "rtn"},
		{"cmdid", "cmdid"},
		{"msg_id", "msg_id"},
	}
	for _, tc := range cases {
		err := driveEDPErr(t, map[string]interface{}{"wire_fault": tc.fault})
		if err == nil {
			t.Errorf("wire_fault %q should be rejected", tc.fault)
			continue
		}
		if !strings.Contains(err.Error(), tc.anchor) {
			t.Errorf("wire_fault %q error %q lacks anchor %q", tc.fault, err.Error(), tc.anchor)
		}
	}
	if err := driveEDPErr(t, map[string]interface{}{"wire_fault": "totally_bogus"}); err == nil ||
		!strings.Contains(err.Error(), "not a known negative-path kind") {
		t.Errorf("unknown wire_fault should be rejected with kind error, got %v", err)
	}
}

// ——隔离终审 F11 补红例（自然面守卫 + 嵌套严格解码 + kind 白名单真触达）——

// 红例⑯ 自然面 state_after_reject：rtn≠0 后排业务事件，validator 走查拒
// （非 wire_fault 注入通道——28 负例全走注入，自然面拒绝路径此前零已提交测试）。
func TestEDPChain_NaturalStateAfterReject(t *testing.T) {
	err := driveEDPErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "connect", "auth": "devid", "devid": "123456789", "apikey": "kJ8mQ2xV", "connack_rtn": 2},
				map[string]interface{}{"kind": "ping"},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("natural state_after_reject should reject with anchor state, got %v", err)
	}
}

// 红例⑰ 自然面 state_after_disconnect：DISCONNECT 后排业务事件拒。
func TestEDPChain_NaturalStateAfterDisconnect(t *testing.T) {
	err := driveEDPErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				connectEv(),
				map[string]interface{}{"kind": "disconnect"},
				map[string]interface{}{"kind": "ping"},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("natural state_after_disconnect should reject with anchor state, got %v", err)
	}
}

// 红例⑱ kind 白名单真触达：connect-first 守卫先放行 connect，第二个事件
// 携未知 kind → 走 validateEvent 的 kind 分支（红例⑩单事件被 connect-first
// 先拒——测试因错误的原因通过，此处修正触达路径）。
func TestEDPChain_UnknownKindSecondEvent(t *testing.T) {
	err := driveEDPErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				connectEv(),
				map[string]interface{}{"kind": "bogus_kind"},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "kind") {
		t.Fatalf("unknown kind on second event should hit kind whitelist, got %v", err)
	}
}

// 红例⑲ 嵌套级未知键严格拒（裁定8 三级——session/event 级经 stdlib
// DisallowUnknownFields 递归覆盖，隔离终审探针实证转正）。
func TestEDPChain_NestedUnknownKeys(t *testing.T) {
	_, err := planEDPChain(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"bogus_sess_key": 1,
			"events":         []interface{}{connectEv()},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "bogus_sess_key") {
		t.Fatalf("session-level unknown key should be rejected, got %v", err)
	}
	_, err = planEDPChain(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{
				"kind": "connect", "auth": "devid", "devid": "1", "apikey": "k",
				"bogus_ev_key": 1,
			}},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "bogus_ev_key") {
		t.Fatalf("event-level unknown key should be rejected, got %v", err)
	}
}

// 红例⑳ u16 标识符上界（终审 F2：超界 uint16 截断产坏帧——validator 即拒）。
func TestEDPChain_U16IdentifierBound(t *testing.T) {
	err := driveEDPErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "connect", "auth": "devid", "devid": strings.Repeat("D", 70000), "apikey": "k"},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "u16 bound") {
		t.Fatalf("70000B devid should be rejected (u16 bound), got %v", err)
	}
}

// 红例㉑ 会话间端口一致性（终审 F10：port_conflict 自然面——会话级
// dst_port 显式声明彼此不一致即拒）。
func TestEDPChain_SessionPortConflict(t *testing.T) {
	err := driveEDPErr(t, map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{"src_port": 41072, "dst_port": 4472, "events": []interface{}{connectEv()}},
			map[string]interface{}{"src_port": 41073, "dst_port": 5555, "events": []interface{}{connectEv()}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("conflicting session dst_ports should be rejected (port_conflict), got %v", err)
	}
}

// 红例㉒ SAVEACK 回带对象守卫（复评 N2：§5③"带 msg_id"= msg_id 真入帧）。
// msg_id_flag=0 时 SAVEDATA 帧不载 msg_id——即便 msg_id 置位、ack:true，
// SAVEACK 也无回带对象，不得臆造回带。
func TestEDPChain_SaveAckRequiresMsgIDOnWire(t *testing.T) {
	pkts := driveEDP(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				connectEv(),
				map[string]interface{}{
					"kind": "savedata", "direction": "up", "devid_flag": 1, "msg_id_flag": 0, "devid": "123456789",
					"msg_id": 21930, "format": 1, "ack": true,
					"json": `{"ds_id":"temp"}`,
				},
			},
		}},
	})
	// 10 包 = 3 + CONNREQ + CONNRESP + SAVEDATA + 4（无 SAVEACK）
	if len(pkts) != 10 {
		t.Fatalf("expected 10 packets (no SAVEACK when msg_id not on wire), got %d", len(pkts))
	}
	payload := payloadHex(t, pkts, 5)
	if strings.Contains(payload, "55aa") {
		t.Fatalf("SAVEDATA with msg_id_flag=0 must not carry msg_id bytes, got %s", payload)
	}
}

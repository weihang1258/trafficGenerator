package layers_test

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dtls" // init 注册 dtls 终结层生成器+校验器
)

// D-DTLS-1 P4 链级红例（bacnet_chain_test 先例同构）：
// ①空配置基线（33B 最小 CH datagram，record 头 13B 全大端 fefd）/
// ②CH 事件字节钉（record len = 12B 握手头 + body）/③v1.0 legacy
// feff/④HVR cookie 自动组 body（ver2+len1+cookie，长度前缀=实际字节）/
// ⑤CCS→加密 epoch 切换（epoch/seq 每方向独立计数，opaque 填充 0xA5）/
// ⑥方向独立（up seq0 与 down seq0 并存）/⑦声明 seq 采纳+推进/⑧多会话
// 状态隔离（walker 逐会话独立）；负例⑨自然守卫（epoch 回退/seq 回退/
// seq 复用/未知 kind/版本非法/缺 handshake/分片越界/cookie 非 HVR/
// dst_port 冲突）+ ⑩6 wire_fault 注入锚词 + 未知 fault；⑪carrier 三
// 形状（缺 udp/tcp 载体/混合地址族）；⑫严格解码（config 未知键拒）。
// 契约 fixture：客户端 192.0.2.63 / 服务端 198.51.100.63 / 端口 4433。

func dtlsChainJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, _ := json.Marshal(layersArr)
	return out
}

func dtlsLayers(cfg map[string]interface{}, ipSrc, ipDst string, srcPort, dstPort interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": ipSrc, "dst": ipDst}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": srcPort, "dst_port": dstPort}},
		map[string]interface{}{"dtls": cfg},
	}
}

func planDTLSChainAt(t *testing.T, layersArr []interface{}, srcIP, dstIP string) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("dtls", dtlsChainJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: srcIP, DstIP: dstIP, SrcPort: 44330, DstPort: 4433}
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

func driveDTLS(t *testing.T, cfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := planDTLSChainAt(t, dtlsLayers(cfg, "192.0.2.63", "198.51.100.63", 44330, 4433), "192.0.2.63", "198.51.100.63")
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func driveDTLSErrAt(t *testing.T, layersArr []interface{}) error {
	t.Helper()
	_, err := planDTLSChainAt(t, layersArr, "192.0.2.63", "198.51.100.63")
	return err
}

func driveDTLSErr(t *testing.T, cfg map[string]interface{}) error {
	t.Helper()
	_, err := planDTLSChainAt(t, dtlsLayers(cfg, "192.0.2.63", "198.51.100.63", 44330, 4433), "192.0.2.63", "198.51.100.63")
	return err
}

func dtlsHex(t *testing.T, pkts []core.PacketConfig, idx int) string {
	t.Helper()
	if idx >= len(pkts) {
		t.Fatalf("packet %d out of range (have %d packets)", idx, len(pkts))
	}
	return strings.ToUpper(hex.EncodeToString(pkts[idx].Payload))
}

func hsEvent(typ int, extra map[string]interface{}) map[string]interface{} {
	m := map[string]interface{}{"type": typ}
	for k, v := range extra {
		m[k] = v
	}
	return m
}

// ① 空配置基线：1 datagram up，最小 CH（type 22/fefd/epoch 0/seq 0，
// len = 12+8=20）。字节逐位钉。
func TestDTLSChain_BaselineDefault(t *testing.T) {
	pkts := driveDTLS(t, map[string]interface{}{})
	if len(pkts) != 1 {
		t.Fatalf("want 1 baseline datagram, got %d", len(pkts))
	}
	if pkts[0].Direction != "up" {
		t.Fatalf("baseline direction %q", pkts[0].Direction)
	}
	want := "16FEFD00000000000000000014" + "010000080000000000000008" + "0000000000000000"
	if got := dtlsHex(t, pkts, 0); got != want {
		t.Fatalf("baseline bytes:\n got %s\nwant %s", got, want)
	}
}

// ② CH 事件：record len = 12B 握手头 + 4B body = 16（0x0010）。
func TestDTLSChain_CHEventBytes(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"events": []interface{}{
			map[string]interface{}{"kind": "handshake", "up": true,
				"handshake": hsEvent(1, map[string]interface{}{"body": "01020304"})},
		}},
	}}
	pkts := driveDTLS(t, cfg)
	if len(pkts) != 1 {
		t.Fatalf("want 1, got %d", len(pkts))
	}
	want := "16FEFD00000000000000000010" + "010000040000000000000004" + "01020304"
	if got := dtlsHex(t, pkts, 0); got != want {
		t.Fatalf("CH bytes:\n got %s\nwant %s", got, want)
	}
}

// ③ v1.0 legacy record version = feff（会话缺省级）。
func TestDTLSChain_Version10Legacy(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"version": "1.0", "events": []interface{}{
			map[string]interface{}{"kind": "ccs", "up": true},
		}},
	}}
	pkts := driveDTLS(t, cfg)
	want := "14FEFF0000000000000000000101"
	if got := dtlsHex(t, pkts, 0); got != want {
		t.Fatalf("v1.0 bytes:\n got %s\nwant %s", got, want)
	}
	// 事件级覆盖同面。
	cfg2 := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"events": []interface{}{
			map[string]interface{}{"kind": "ccs", "up": true, "version": "1.0"},
		}},
	}}
	pkts2 := driveDTLS(t, cfg2)
	if got := dtlsHex(t, pkts2, 0); got != want {
		t.Fatalf("v1.0 event override:\n got %s\nwant %s", got, want)
	}
}

// ④ HVR cookie：body = fefd(2)+cookie_len(1)+cookie(3)，长度前缀=实际字节。
func TestDTLSChain_HVRCookie(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"events": []interface{}{
			map[string]interface{}{"kind": "handshake", "up": false,
				"handshake": hsEvent(3, map[string]interface{}{"cookie": "AABBCC"})},
		}},
	}}
	pkts := driveDTLS(t, cfg)
	if pkts[0].Direction != "down" {
		t.Fatalf("HVR direction %q", pkts[0].Direction)
	}
	// record len = 12 + 6 = 18（0x0012）；msg_seq 0。
	want := "16FEFD00000000000000000012" + "03" + "000006" + "0000" + "000000" + "000006" + "FEFD03AABBCC"
	if got := dtlsHex(t, pkts, 0); got != want {
		t.Fatalf("HVR bytes:\n got %s\nwant %s", got, want)
	}
}

// ⑤ CCS→加密 epoch：ccs(epoch0,seq0) → appdata(epoch1,seq0)——epoch
// 切换后 seq 从 0 重新计数（(epoch,方向) 独立 48-bit 计数）。
func TestDTLSChain_CCSAndEpochTransition(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"events": []interface{}{
			map[string]interface{}{"kind": "ccs", "up": true},
			map[string]interface{}{"kind": "appdata", "up": true, "epoch": 1, "ciphertext_len": 4},
		}},
	}}
	pkts := driveDTLS(t, cfg)
	if len(pkts) != 2 {
		t.Fatalf("want 2, got %d", len(pkts))
	}
	if got := dtlsHex(t, pkts, 0); got != "14FEFD0000000000000000000101" {
		t.Fatalf("ccs bytes: %s", got)
	}
	want := "17FEFD00010000000000000004A5A5A5A5"
	if got := dtlsHex(t, pkts, 1); got != want {
		t.Fatalf("appdata bytes:\n got %s\nwant %s", got, want)
	}
}

// ⑥ 方向独立：up 与 down 各自 epoch/seq 计数（两包都 seq 0）。
func TestDTLSChain_DirectionIndependentSeq(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"events": []interface{}{
			map[string]interface{}{"kind": "ccs", "up": true},
			map[string]interface{}{"kind": "alert", "up": false, "alert_level": 2, "alert_desc": 10},
		}},
	}}
	pkts := driveDTLS(t, cfg)
	if pkts[0].Direction != "up" || pkts[1].Direction != "down" {
		t.Fatalf("directions: %s / %s", pkts[0].Direction, pkts[1].Direction)
	}
	// 两个方向 seq 都是 0（header 第 8-13 字节）。
	for i, want := range []string{"14FEFD0000000000000000000101", "15FEFD00000000000000000002020A"} {
		if got := dtlsHex(t, pkts, i); got != want {
			t.Fatalf("pkt %d:\n got %s\nwant %s", i, got, want)
		}
	}
}

// ⑦ 声明 seq 采纳+推进：声明 5 → 缺省 6；msg_seq 声明采纳（重传复用合法）。
func TestDTLSChain_DeclaredSeqAdoptAndAdvance(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"events": []interface{}{
			map[string]interface{}{"kind": "ccs", "up": true, "seq": 5},
			map[string]interface{}{"kind": "ccs", "up": true},
		}},
	}}
	pkts := driveDTLS(t, cfg)
	if got := dtlsHex(t, pkts, 0)[10:22]; got != "000000000005" {
		t.Fatalf("declared seq bytes: %s", got)
	}
	if got := dtlsHex(t, pkts, 1)[10:22]; got != "000000000006" {
		t.Fatalf("advanced seq bytes: %s", got)
	}
}

// ⑧ 多会话状态隔离：会话 2 的 epoch/seq/cookie 状态不串会话 1
//（逐会话独立 walker；按序整块回放）。
func TestDTLSChain_MultiSessionIsolation(t *testing.T) {
	cfg := map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"src_port": 5001, "events": []interface{}{
			map[string]interface{}{"kind": "appdata", "up": true, "epoch": 3, "ciphertext_len": 2},
		}},
		map[string]interface{}{"src_port": 5002, "events": []interface{}{
			map[string]interface{}{"kind": "ccs", "up": true},
		}},
	}}
	pkts := driveDTLS(t, cfg)
	if len(pkts) != 2 {
		t.Fatalf("want 2, got %d", len(pkts))
	}
	// 会话 2 的 ccs 回到 epoch 0 seq 0（隔离）；会话 1 保持 epoch 3。
	if got := dtlsHex(t, pkts, 0); !strings.HasPrefix(got, "17FEFD00030000000000000002") {
		t.Fatalf("session1 bytes: %s", got)
	}
	if got := dtlsHex(t, pkts, 1); got != "14FEFD0000000000000000000101" {
		t.Fatalf("session2 bytes: %s", got)
	}
	if pkts[0].L4.SrcPort != 5001 || pkts[1].L4.SrcPort != 5002 {
		t.Fatalf("src ports: %d / %d", pkts[0].L4.SrcPort, pkts[1].L4.SrcPort)
	}
}

// ⑨ 自然守卫红例（锚词逐条）。
func TestDTLSChain_NaturalGuards(t *testing.T) {
	mk := func(events ...map[string]interface{}) map[string]interface{} {
		return map[string]interface{}{"sessions": []interface{}{
			map[string]interface{}{"events": events},
		}}
	}
	cases := []struct {
		name   string
		cfg    map[string]interface{}
		anchor string
	}{
		{"epoch_regression", mk(
			map[string]interface{}{"kind": "appdata", "up": true, "epoch": 2, "ciphertext_len": 2},
			map[string]interface{}{"kind": "appdata", "up": true, "epoch": 1, "ciphertext_len": 2}), "(epoch)"},
		{"seq_regression", mk(
			map[string]interface{}{"kind": "ccs", "up": true, "seq": 3},
			map[string]interface{}{"kind": "ccs", "up": true, "seq": 1}), "(sequence)"},
		{"seq_reuse", mk(
			map[string]interface{}{"kind": "ccs", "up": true},
			map[string]interface{}{"kind": "ccs", "up": true, "seq": 0}), "(sequence)"},
		{"seq_overflow", mk(
			map[string]interface{}{"kind": "ccs", "up": true, "seq": 281474976710656}), "(sequence)"},
		{"unknown_kind", mk(map[string]interface{}{"kind": "magic", "up": true}), "(kind)"},
		{"bad_version", mk(map[string]interface{}{"kind": "ccs", "up": true, "version": "9.9"}), "(version)"},
		{"handshake_missing", mk(map[string]interface{}{"kind": "handshake", "up": true}), "(handshake)"},
		{"fragment_bounds", mk(map[string]interface{}{"kind": "handshake", "up": true,
			"handshake": map[string]interface{}{"type": 1, "body": "01020304", "fragment_offset": 2, "fragment_length": 4}}), "(fragment)"},
		{"cookie_non_hvr", mk(map[string]interface{}{"kind": "handshake", "up": true,
			"handshake": map[string]interface{}{"type": 1, "cookie": "AABB"}}), "(cookie)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := driveDTLSErr(t, tc.cfg)
			if err == nil {
				t.Fatalf("want error with anchor %s, got nil", tc.anchor)
			}
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("error %q missing anchor %s", err, tc.anchor)
			}
		})
	}
	// dst_port 会话间冲突。
	err := driveDTLSErr(t, map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"dst_port": 5001, "events": []interface{}{map[string]interface{}{"kind": "ccs", "up": true}}},
		map[string]interface{}{"dst_port": 5002, "events": []interface{}{map[string]interface{}{"kind": "ccs", "up": true}}},
	}})
	if err == nil || !strings.Contains(err.Error(), "(port)") {
		t.Fatalf("dst_port conflict: %v", err)
	}
}

// ⑩ 6 wire_fault 注入锚词 + 未知 fault 拒。
func TestDTLSChain_WireFaults(t *testing.T) {
	for fault, anchor := range map[string]string{
		"record_length":     "anchor record",
		"version_epoch":     "anchor version",
		"sequence_overflow": "anchor sequence",
		"fragment_bounds":   "anchor fragment",
		"cookie_state":      "anchor cookie",
		"carrier_udp":       "anchor udp",
	} {
		err := driveDTLSErr(t, map[string]interface{}{"wire_fault": fault})
		if err == nil {
			t.Fatalf("%s: want error, got nil", fault)
		}
		if !strings.Contains(err.Error(), anchor) {
			t.Fatalf("%s: error %q missing anchor %s", fault, err, anchor)
		}
	}
	if err := driveDTLSErr(t, map[string]interface{}{"wire_fault": "no_such_fault"}); err == nil ||
		!strings.Contains(err.Error(), "unknown wire_fault") {
		t.Fatalf("unknown fault: %v", err)
	}
}

// ⑪ carrier 三形状：缺 udp / tcp 载体 / 混合地址族（预检锚词）。
func TestDTLSChain_CarrierShapes(t *testing.T) {
	cases := []struct {
		name   string
		layers []interface{}
		anchor string
	}{
		{"missing_udp", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.63", "dst": "198.51.100.63"}},
			map[string]interface{}{"dtls": map[string]interface{}{}},
		}, "(carrier)"},
		{"tcp_carrier", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.63", "dst": "198.51.100.63"}},
			map[string]interface{}{"tcp": map[string]interface{}{"src_port": 44330, "dst_port": 4433}},
			map[string]interface{}{"dtls": map[string]interface{}{}},
		}, "(carrier)"},
		{"mixed_family", []interface{}{
			map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.63", "dst": "2001:db8:ffff::63"}},
			map[string]interface{}{"udp": map[string]interface{}{"src_port": 44330, "dst_port": 4433}},
			map[string]interface{}{"dtls": map[string]interface{}{}},
		}, "(family)"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := driveDTLSErrAt(t, tc.layers)
			if err == nil {
				t.Fatalf("want error with anchor %s, got nil", tc.anchor)
			}
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Fatalf("error %q missing anchor %s", err, tc.anchor)
			}
		})
	}
}

// ⑫ 严格解码：dtls 层 config 未知键拒（三级 DisallowUnknownFields 之外层）。
func TestDTLSChain_StrictDecode(t *testing.T) {
	err := driveDTLSErrAt(t, dtlsLayers(map[string]interface{}{"no_such_key": 1},
		"192.0.2.63", "198.51.100.63", 44330, 4433))
	if err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("strict decode: %v", err)
	}
	// 事件级未知键同样拒（UnmarshalJSON 递归严格）。
	err = driveDTLSErr(t, map[string]interface{}{"sessions": []interface{}{
		map[string]interface{}{"events": []interface{}{
			map[string]interface{}{"kind": "ccs", "up": true, "bogus": 1},
		}},
	}})
	if err == nil || !strings.Contains(err.Error(), "dtls layer config decode") {
		t.Fatalf("event strict decode: %v", err)
	}
}

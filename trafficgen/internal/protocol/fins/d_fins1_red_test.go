package fins

import (
	"bytes"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// D-FINS-1 §4 红例④⑤⑥（failing 先行，P-PIPE #11 P4）。
// 实现前预期：④红（请求 switch 无 0103 分支 → default unsupported）；
// ⑤红（同上 0104）；⑥红（cfg 级只查 validICF 位合法，0xC1 放行）。

// 红例④【D-FINS-1 §1/§3】：0103 Fill 请求体 = 寻址 4B + NC 2B + 填充字 2B
// （无 DC，剩余长度恒 8，设计 §3.8 / W342 / tshark 口径）。
func TestFillRequestVector(t *testing.T) {
	cfg := &FINSConfig{}
	cmd := FINSCommand{Command: CommandMemoryAreaFill, MemoryArea: "dm", Address: 100, Items: 3, Data: []byte{0xAB, 0xCD}}
	frame, err := BuildFrameWithConfig(cfg, cmd, false, 1)
	if err != nil {
		t.Fatalf("build 0103: %v", err)
	}
	want := []byte{
		0x81, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0x01, // 头：ICF/RSV/GCT/DNA/DA1/DA2/SNA/SA1/SA2/SID
		0x01, 0x03, // 命令码 0103
		0x82, 0x00, 0x64, 0x00, // DM 区码 + 地址 100 + bit 0
		0x00, 0x03, // NC=3
		0xAB, 0xCD, // 填充字（无 DC）
	}
	if !bytes.Equal(frame, want) {
		t.Fatalf("0103 frame = % X, want % X", frame, want)
	}
}

// 红例⑤【D-FINS-1 §1/§3】：0104 双组读。请求 = 组数 1B +
// [区码+地址2+bit+NC2]×2（tshark 怪癖：请求组按 4B/组忽略 NC，断言走原始
// 字节）；响应 = 结束码 + 逐组数据（字口径组内 uint16(i+1) BE 重起）。
func TestMultipleReadVectors(t *testing.T) {
	cfg := &FINSConfig{}
	cmd := FINSCommand{Command: CommandMultipleMemoryAreaRead, ReadAreas: []FINSReadArea{
		{MemoryArea: "dm", Address: 100, Items: 1},
		{MemoryArea: "hr", Address: 16, Items: 1},
	}}
	req, err := BuildFrameWithConfig(cfg, cmd, false, 1)
	if err != nil {
		t.Fatalf("build 0104 req: %v", err)
	}
	wantReq := []byte{
		0x81, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0x01,
		0x01, 0x04, // 命令码 0104
		0x02,                               // 组数
		0x82, 0x00, 0x64, 0x00, 0x00, 0x01, // 组1：DM 地址 100 NC=1
		0xB2, 0x00, 0x10, 0x00, 0x00, 0x01, // 组2：HR 地址 16 NC=1
	}
	if !bytes.Equal(req, wantReq) {
		t.Fatalf("0104 req = % X, want % X", req, wantReq)
	}
	resp, err := BuildFrameWithConfig(cfg, cmd, true, 1)
	if err != nil {
		t.Fatalf("build 0104 resp: %v", err)
	}
	wantResp := []byte{
		0xC1, 0x00, 0x02, 0, 0, 0, 0, 0, 0, 0x01,
		0x01, 0x04,
		0x00, 0x00, // 结束码 0x0000
		0x00, 0x01, // 组1 数据（字 1 元素 = 1）
		0x00, 0x01, // 组2 数据（组内重起 = 1）
	}
	if !bytes.Equal(resp, wantResp) {
		t.Fatalf("0104 resp = % X, want % X", resp, wantResp)
	}
}

// 红例⑥【D-FINS-1 依赖链 E-06 行】：cfg 级 ICF 方向一致性——cfg.ICF 是
// 请求 ICF，bit6（响应位）必须清零、bit0（不期望响应）必须清零。
// 现状：cfg 级只查 validICF 位合法（fins.go:50），0xC1（bit7+bit6）放行。
func TestCfgICFRequestDirectionBit(t *testing.T) {
	cfg := &FINSConfig{ICF: 0xC1, Commands: []FINSCommand{{Command: CommandMemoryAreaRead, MemoryArea: "dm", Address: 0, Items: 1}}}
	spec := core.FlowSpec{Metadata: map[string]interface{}{MetadataKey: cfg}}
	err := (&Planner{}).Validate(spec)
	if err == nil {
		t.Fatal("cfg.ICF=0xC1 (response bit set on request ICF) must be rejected (E-06)")
	}
	if !strings.Contains(err.Error(), "icf request direction bit must be clear") {
		t.Fatalf("anchor mismatch: %v", err)
	}
}

// P4 自审补红：0104 分支曾置于 direction/ICF 校验之前并 continue，
// 坏 ICF 的 0104 漏检——校验顺序锁（红→移位→绿）。
func TestMultipleReadCommandLevelICFStillChecked(t *testing.T) {
	cfg := &FINSConfig{Commands: []FINSCommand{{
		Command: CommandMultipleMemoryAreaRead, ICF: 0x81,
		ReadAreas: []FINSReadArea{{MemoryArea: "dm", Address: 0, Items: 1}},
	}}}
	spec := core.FlowSpec{Metadata: map[string]interface{}{MetadataKey: cfg}}
	err := (&Planner{}).Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "icf response-required bit must be clear") {
		t.Fatalf("0104 with bad cmd-level ICF must be rejected, got: %v", err)
	}
}

package jt808

// D-JT808-1 隔离复审 F1/F2（2026-09-21）：线格式对规范原文保真红例。
// F1 JT/T 808 §5.4.2 消息体封装项 = 消息总包数 WORD(+12) + 包数据序号 WORD(+14)
//   ——legacy 发 [序号, 总包数] 反序（builder/parser/legacy 测试全链自洽地错）。
// F2 JT/T 808 0x8103 消息体 = 参数总数 BYTE + Σ[参数ID DWORD + 参数长度 BYTE
//   + 参数值] ——legacy 缺总数前导且 ID 线上 1 字节。
// 规范与实现冲突：先改实现再补用例（CORE_MEMORY 4.24）。9.7 先红后绿。

import (
	"bytes"
	"context"
	"encoding/hex"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func TestSpecOrderPackageInfo(t *testing.T) {
	// 体=1+6×(4+1+200)=1231>1023 → 分包；单参数 ≤255（长度字节 uint8）。
	params := make([]JT808Param, 6)
	for i := range params {
		params[i] = JT808Param{Id: uint32(i + 1), Value: bytes.Repeat([]byte{0x41}, 200)}
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 50000, DstPort: 7611}
	cfg := &JT808Config{Phone: "012345678901"}
	cfg.Procedures = []JT808Procedure{{Type: "set_params", Params: params}}
	ch, err := NewPlanner().PlanWithConfig(context.Background(), spec, cfg)
	if err != nil {
		t.Fatalf("PlanWithConfig: %v", err)
	}
	n := 0
	for pkt := range ch {
		n++
		if len(pkt.Payload) < 20 {
			continue
		}
		dec, derr := hex.DecodeString(hex.EncodeToString(pkt.Payload[1 : len(pkt.Payload)-1])) // strip 0x7e pair（无转义字节面）
		if derr != nil {
			t.Fatalf("decode: %v", derr)
		}
		if len(dec) < 16 {
			continue
		}
		if dec[2]>>6 != 0 || dec[3]&0xC0 == 0 {
			// not distinguishing props bits here; use PackageFlag from props bit14
		}
		total := uint16(dec[12])<<8 | uint16(dec[13])
		num := uint16(dec[14])<<8 | uint16(dec[15])
		if total != 2 {
			t.Fatalf("spec order: 消息总包数@+12 = %d, want 2（规范：总包数在前）", total)
		}
		if num != 1 {
			t.Fatalf("spec order: 包数据序号@+14 = %d, want 1（首分片）", num)
		}
		return
	}
	t.Fatalf("no fragmented frame emitted (packets=%d)", n)
}

func TestSpecShapeSetParams(t *testing.T) {
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 50000, DstPort: 7611}
	cfg := &JT808Config{Phone: "012345678901"}
	cfg.Procedures = []JT808Procedure{{Type: "set_params", Params: []JT808Param{
		{Id: 0x00000001, Value: []byte("abcd")},
	}}}
	ch, err := NewPlanner().PlanWithConfig(context.Background(), spec, cfg)
	if err != nil {
		t.Fatalf("PlanWithConfig: %v", err)
	}
	for pkt := range ch {
		if len(pkt.Payload) == 0 {
			continue
		}
		dec, _ := hex.DecodeString(hex.EncodeToString(pkt.Payload[1 : len(pkt.Payload)-1]))
		// 0x8103 体自 +12 起：总数(1)+ID(4)+LEN(1)+VAL
		if dec[12] != 1 {
			t.Fatalf("spec shape: 参数总数前导 = %d, want 1（0x8103 体首字节=参数总数）", dec[12])
		}
		id := uint32(dec[13])<<24 | uint32(dec[14])<<16 | uint32(dec[15])<<8 | uint32(dec[16])
		if id != 1 {
			t.Fatalf("spec shape: 参数ID = 0x%08x, want DWORD 0x00000001", id)
		}
		if dec[17] != 4 || string(dec[18:22]) != "abcd" {
			t.Fatalf("spec shape: len/value = %d %q", dec[17], dec[18:22])
		}
		return
	}
	t.Fatalf("no 0x8103 frame emitted")
}

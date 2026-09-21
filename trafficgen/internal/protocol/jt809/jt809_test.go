package jt809

// D-JT809-1 P4 单测面（suite 号不在此占）：金向量逐字节复现（外部权威锚
// SmallChi 0x1001 例，jtcommon 金向量同源）、2019 30B 头形、转义真字节、
// 解析对称+负路径、ValidateConfig 锚（T-11/T-12/T-13 同源锚词）、编排面
// 主/从链时序与 SN 计数。

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// SmallChi JT809_0x1001PackageTest.Test1 期望 hex（2013 形 22B 头）。
const goldenWireHex = "5B000000480000008510010133EFB8010000000000270F0133EFB8" +
	"32303138303932303132372E302E302E31" +
	"0000000000000000000000000000000000000000000000" +
	"03296A915D"

// 锚：typed config → 逐字节复现金向量（头序/MsgLength 整帧语义/CRC/
// 版本缺省字面/双 pad 全在一条断言里钉死）。
func TestBuildFrame_GoldenVector(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 20180920,
		UserId:       20180920,
		Password:     "20180920",
		VersionFlag:  1, // 2013：22B 头，0x1001 体 46B
		EncryptKey:   9999,
		DownLinkIP:   "127.0.0.1",
		DownLinkPort: 809,
	}
	frame, err := buildFrame(cfg, 133, MsgMainLogin, buildLoginBody(cfg, nil))
	if err != nil {
		t.Fatalf("buildFrame: %v", err)
	}
	if got := hex.EncodeToString(frame); !strings.EqualFold(got, goldenWireHex) {
		t.Fatalf("golden mismatch:\n got %s\nwant %s", got, goldenWireHex)
	}
	pf, err := ParseFrame(frame, 1)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if pf.MsgID != MsgMainLogin || pf.MsgSN != 133 || pf.GNSSCenterId != 20180920 {
		t.Fatalf("header fields: %+v", pf)
	}
	uid, pw, gnss, ip, port, err := pf.LoginBody()
	if err != nil {
		t.Fatalf("LoginBody: %v", err)
	}
	if uid != 20180920 || pw != "20180920" || gnss != 0 || ip != "127.0.0.1" || port != 809 {
		t.Fatalf("body: uid=%d pw=%q gnss=%d ip=%q port=%d", uid, pw, gnss, ip, port)
	}
}

// 2019 形：30B 头（Time 8B）+ 0x1001 体 50B（GNSSCenterId 入体）。
func TestBuildFrame_2019Shape(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 291,
		UserId:       1001,
		Password:     "pw123456",
		VersionFlag:  2,
		VersionBytes: "020000",
		EncryptFlag:  1,
		EncryptKey:   0xDEADBEEF,
		TimeSec:      1700000000,
		DownLinkIP:   "10.0.0.1",
		DownLinkPort: 8813,
	}
	frame, err := buildFrame(cfg, 7, MsgMainLogin, buildLoginBody(cfg, nil))
	if err != nil {
		t.Fatalf("buildFrame: %v", err)
	}
	// 整帧长 = 1 + 30 + 50 + 2 + 1 = 84（勘误1/勘误4）。
	if len(frame) != 84 {
		t.Fatalf("frame len %d, want 84 (1+30+50+2+1)", len(frame))
	}
	if binary.BigEndian.Uint32(frame[1:5]) != 84 {
		t.Fatalf("MsgLength field %d, want 84 (整帧语义)", binary.BigEndian.Uint32(frame[1:5]))
	}
	pf, err := ParseFrame(frame, 2)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	if pf.TimeSec != 1700000000 {
		t.Fatalf("TimeSec %d, want 1700000000", pf.TimeSec)
	}
	if string(pf.Version) != "\x02\x00\x00" {
		t.Fatalf("version bytes %x", pf.Version)
	}
	uid, pw, gnss, ip, port, err := pf.LoginBody()
	if err != nil {
		t.Fatalf("LoginBody: %v", err)
	}
	if uid != 1001 || pw != "pw123456" || gnss != 291 || ip != "10.0.0.1" || port != 8813 {
		t.Fatalf("body: uid=%d pw=%q gnss=%d ip=%q port=%d", uid, pw, gnss, ip, port)
	}
}

// 转义真字节（T-9 同形，值勘误：0x5B5D→5A 01/5E 01 双 escape 形——设计
// T-9 原值 0x5A5B 的 5B 逃逸形是 5A 01 非 5E 01）；CRC 对未转义体计算后
// CRC 字节随整体转义；解析回程还原。
func TestEscapeOnWire(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 1,
		VersionFlag:  1,
		DownLinkIP:   "1.2.3.4",
		DownLinkPort: 0x5B5D,
	}
	frame, err := buildFrame(cfg, 1, MsgMainLogin, buildLoginBody(cfg, nil))
	if err != nil {
		t.Fatalf("buildFrame: %v", err)
	}
	if !contains(frame, []byte{0x5A, 0x01}) || !contains(frame, []byte{0x5E, 0x01}) {
		t.Fatalf("wire missing escape forms 5A01/5E01: %x", frame)
	}
	pf, err := ParseFrame(frame, 1)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	_, _, _, _, port, err := pf.LoginBody()
	if err != nil {
		t.Fatalf("LoginBody: %v", err)
	}
	if port != 0x5B5D {
		t.Fatalf("port %04x, want 5b5d", port)
	}
}

func contains(hay, needle []byte) bool {
	for i := 0; i+1 < len(hay); i++ {
		if hay[i] == needle[0] && hay[i+1] == needle[1] {
			return true
		}
	}
	return false
}

// 解析负路径：CRC 破坏 → CRC mismatch；MsgLength 篡改 → 长度自洽错。
func TestParseFrame_Negative(t *testing.T) {
	cfg := &JT809Config{GNSSCenterId: 1, VersionFlag: 1, Password: "x"}
	frame, err := buildFrame(cfg, 1, MsgMainKeepalive, nil)
	if err != nil {
		t.Fatalf("buildFrame: %v", err)
	}
	bad := append([]byte(nil), frame...)
	bad[len(bad)-3] ^= 0xFF // 体区字节翻转（CRC 之前）
	if _, err := ParseFrame(bad, 1); err == nil || !strings.Contains(err.Error(), "CRC mismatch") {
		t.Fatalf("want CRC mismatch, got %v", err)
	}
	bad2 := append([]byte(nil), frame...)
	bad2[4] ^= 0xFF // MsgLength 篡改
	if _, err := ParseFrame(bad2, 1); err == nil || !strings.Contains(err.Error(), "MsgLength") {
		t.Fatalf("want MsgLength error, got %v", err)
	}
}

// 解析负路径：0x1001 体畸形 47B（46<47<50 中间带）必须报错不 panic
// （隔离复审 M1：双形判定 len>need 在长度检查前切片越界）。
func TestParseFrame_LoginBodyMalformed(t *testing.T) {
	cfg := &JT809Config{GNSSCenterId: 1, VersionFlag: 1, Password: "x", DownLinkIP: "1.2.3.4"}
	frame, err := buildFrame(cfg, 1, MsgMainLogin, buildLoginBody(cfg, nil))
	if err != nil {
		t.Fatalf("buildFrame: %v", err)
	}
	pf, err := ParseFrame(frame, 1)
	if err != nil {
		t.Fatalf("ParseFrame: %v", err)
	}
	// 篡造 47B 体（CRC 校验通过后的解析面负例）。
	mal := make([]byte, len(pf.Body)+1)
	copy(mal, pf.Body)
	mal[46] = 0xAA
	pf2 := &ParsedFrame{MsgID: MsgMainLogin, Body: mal}
	if _, _, _, _, _, err := pf2.LoginBody(); err == nil || !strings.Contains(err.Error(), "want 46 or 50") {
		t.Fatalf("want 47B body error, got %v", err)
	}
}

// ValidateConfig 锚（T-11/T-12/T-13 同源锚词 + 区间面）。
func TestValidateConfig_Anchors(t *testing.T) {
	cases := []struct {
		name string
		cfg  *JT809Config
		want string
	}{
		{"gnss 超界", &JT809Config{GNSSCenterId: 1000000000}, "GNSSCenterId 1000000000 > 999999999"},
		{"version_flag 区间", &JT809Config{GNSSCenterId: 1, VersionFlag: 3}, "VersionFlag 3 > 2"},
		{"encrypt_flag 区间", &JT809Config{GNSSCenterId: 1, EncryptFlag: 2}, "EncryptFlag 2 > 1"},
		{"password 超宽", &JT809Config{GNSSCenterId: 1, Password: "123456789"}, "Password length 9 > 8"},
		{"error_code 嵌套锚", &JT809Config{GNSSCenterId: 1, Procedures: []JT809Procedure{{Type: ProcMainDisconnect, ErrorCode: 3}}}, "ErrorCode 3"},
		{"result 区间", &JT809Config{GNSSCenterId: 1, Procedures: []JT809Procedure{{Type: ProcMainLoginResp, Result: 5}}}, "Result 5 > 4"},
		{"未知类型", &JT809Config{GNSSCenterId: 1, Procedures: []JT809Procedure{{Type: "vehicle_register"}}}, "unknown procedure type"},
		{"从链类型混主链", &JT809Config{GNSSCenterId: 1, Procedures: []JT809Procedure{{Type: ProcSlaveConnect}}}, "belongs on the slave link"},
		{"version_bytes 宽度", &JT809Config{GNSSCenterId: 1, VersionBytes: "0100"}, "must be 6 hex chars"},
		{"pr password 超宽", &JT809Config{GNSSCenterId: 1, Procedures: []JT809Procedure{{Type: ProcMainLogout, Password: "123456789"}}}, "procedure Password length 9 > 8"},
		{"pr down_link_ip 超宽", &JT809Config{GNSSCenterId: 1, Procedures: []JT809Procedure{{Type: ProcMainLogin, DownLinkIP: strings.Repeat("a", 33)}}}, "procedure DownLinkIP length 33 > 32"},
		{"nil", nil, "nil config"},
	}
	for _, c := range cases {
		err := ValidateConfig(c.cfg)
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Fatalf("%s: want %q, got %v", c.name, c.want, err)
		}
	}
	if err := ValidateConfig(DefaultJT809Config()); err != nil {
		t.Fatalf("default config must validate: %v", err)
	}
}

// 编排面：主链 login+keepalive 对 → 8 帧=3 握手+3 消息+3 挥手（wait: 2 消息
// 面 login+0x1005+0x1006=3 帧 → 3+3+3=9）；SN 四计数器分链分向独立。
func TestPlanWithConfig_MainSequence(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 291,
		InitialSN:    100,
		VersionFlag:  1,
		Procedures: []JT809Procedure{
			{Type: ProcMainLogin},
			{Type: ProcMainKeepalive},
			{Type: ProcMainKeepaliveResp, VerifyCode: 0},
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02"}
	ch, err := NewPlanner().PlanWithConfig(context.Background(), spec, cfg)
	if err != nil {
		t.Fatalf("PlanWithConfig: %v", err)
	}
	var frames []*ParsedFrame
	var dirs []string
	for pkt := range ch {
		if pkt.Direction == "up" || pkt.Direction == "down" {
			if len(pkt.Payload) > 0 && pkt.Payload[0] == FlagBegin {
				pf, err := ParseFrame(pkt.Payload, 1)
				if err != nil {
					t.Fatalf("parse emitted frame: %v", err)
				}
				frames = append(frames, pf)
				dirs = append(dirs, pkt.Direction)
			}
		}
	}
	// 消息面 3 帧：0x1001 up / 0x1005 up / 0x1006 down。
	if len(frames) != 3 {
		t.Fatalf("message frames %d, want 3", len(frames))
	}
	exp := []struct {
		id  uint16
		sn  uint32
		dir string
	}{
		{MsgMainLogin, 100, "up"},
		{MsgMainKeepalive, 101, "up"},
		{MsgMainKeepaliveResp, 0, "down"}, // PlatformInitialSN=0
	}
	for i, e := range exp {
		if frames[i].MsgID != e.id || frames[i].MsgSN != e.sn || dirs[i] != e.dir {
			t.Fatalf("frame %d: id=%04x sn=%d dir=%s, want %04x/%d/%s",
				i, frames[i].MsgID, frames[i].MsgSN, dirs[i], e.id, e.sn, e.dir)
		}
	}
	if err := frames[1].EmptyBody(); err != nil {
		t.Fatalf("0x1005 empty body: %v", err)
	}
}

// 双链路真子流：SlaveProcedures 非空 → 两条 4 元组同 group_id；从链 3+1+3，
// 时序=主链消息后从链握手（门1 §3 插入位置）。
func TestPlanWithConfig_SlaveLink(t *testing.T) {
	cfg := &JT809Config{
		GNSSCenterId: 291,
		InitialSN:    5,
		VersionFlag:  1,
		Procedures:   []JT809Procedure{{Type: ProcMainLogin}},
		SlaveProcedures: []JT809Procedure{
			{Type: ProcSlaveConnect, VerifyCode: 0x12345678},
		},
	}
	spec := core.FlowSpec{SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcMAC: "02:00:00:00:00:01", DstMAC: "02:00:00:00:00:02"}
	ch, err := NewPlanner().PlanWithConfig(context.Background(), spec, cfg)
	if err != nil {
		t.Fatalf("PlanWithConfig: %v", err)
	}
	main, slave := 0, 0
	groups := map[string]int{}
	slaveGroups := map[string]bool{}
	seenSlaveSYN := false
	for pkt := range ch {
		g, _ := pkt.Metadata["group_id"].(string)
		groups[g]++
		isSlave := pkt.L4.SrcPort == SlaveLinkPort || pkt.L4.DstPort == SlaveLinkPort
		if isSlave {
			slave++
			slaveGroups[g] = true
			if pkt.L4.Flags == 0x02 {
				seenSlaveSYN = true
				if pkt.L4.DstPort != SlaveLinkPort {
					t.Fatalf("slave SYN dst %d, want 8813", pkt.L4.DstPort)
				}
			}
			if len(pkt.Payload) > 0 && pkt.Payload[0] == FlagBegin {
				pf, err := ParseFrame(pkt.Payload, 1)
				if err != nil {
					t.Fatalf("slave frame: %v", err)
				}
				if pf.MsgID != MsgSlaveConnect {
					t.Fatalf("slave msg %04x, want 9001", pf.MsgID)
				}
				vc, err := pf.VerifyCodeBody()
				if err != nil || vc != 0x12345678 {
					t.Fatalf("verify code %x err=%v", vc, err)
				}
				if pf.MsgSN != 5 { // slaveMsgSN starts at InitialSN
					t.Fatalf("slave SN %d, want 5", pf.MsgSN)
				}
			}
		} else {
			main++
		}
	}
	if main != 7 || slave != 7 {
		t.Fatalf("main=%d slave=%d, want 7/7 (各 3 握手+1 消息+3 挥手)", main, slave)
	}
	if !seenSlaveSYN {
		t.Fatal("slave SYN missing")
	}
	if len(groups) != 1 {
		t.Fatalf("group_id count %d, want 1 (两流同 GroupID)", len(groups))
	}
}

// 负路径：ValidateConfig 失败直达 PlanWithConfig 返回（不静默 0 包）。
func TestPlanWithConfig_Negative(t *testing.T) {
	cfg := &JT809Config{GNSSCenterId: 1000000000}
	if _, err := NewPlanner().PlanWithConfig(context.Background(), core.FlowSpec{}, cfg); err == nil {
		t.Fatal("want error for gnss overflow")
	}
	if _, err := NewPlanner().Plan(context.Background(), core.FlowSpec{}); err == nil {
		t.Fatal("Plan must hard-error (唯一入口 PlanWithConfig)")
	}
}

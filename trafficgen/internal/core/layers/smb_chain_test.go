package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	_ "github.com/trafficgen/trafficgen/internal/protocol/smb" // init 注册 smb 终结层生成器+校验器
)

// D-SMB-1 P4 链级红例：①空配置基线（默认单 read 会话 29 包）/②显式 close
// 抑制（CLOSE 恰一对 25 包）/③netbios 载体端口 139 /④非法值同步拒
// （auth_mechanism/op_type 走 validator）/⑤层内未知键同步拒 /⑥carrier
// 五形状（缺 tcp/udp/混合地址族/错端口）/⑦严格解码（顶层未知键与
// operations[] 嵌套未知键）/⑧presence 双形状（M5 必含①②：顶层空 smb 子
// 映射 + 游离键）/⑨IPv6 /⑩用例文件收官自查（非负例顶层键=0）。

const (
	smbCli   = "10.0.0.100"
	smbSrv   = "10.0.0.1"
	smbCli6  = "2001:db8::100"
	smbSrv6  = "2001:db8::1"
	smbSport = 40001
)

func smbLayers(smbCfg, tcpCfg map[string]interface{}) []interface{} {
	if tcpCfg == nil {
		tcpCfg = map[string]interface{}{"src_port": smbSport, "dst_port": 445}
	}
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": smbCli, "dst": smbSrv}},
		map[string]interface{}{"tcp": tcpCfg},
		map[string]interface{}{"smb": smbCfg},
	}
}

func smbJSON(t *testing.T, layersArr []interface{}) []byte {
	t.Helper()
	out, err := json.Marshal(layersArr)
	if err != nil {
		t.Fatalf("marshal layers: %v", err)
	}
	return out
}

func smbPlan(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("smb", smbJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: smbCli, DstIP: smbSrv, SrcPort: smbSport, DstPort: 445}
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

func smbDrive(t *testing.T, smbCfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := smbPlan(t, smbLayers(smbCfg, nil))
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func smbDriveErr(t *testing.T, smbCfg map[string]interface{}) error {
	t.Helper()
	_, err := smbPlan(t, smbLayers(smbCfg, nil))
	return err
}

// smbCmds 抽出全部 SMB2 PDU 的 Command（NBSS 4B 之后 SMB2 头 +8）。
func smbCmds(t *testing.T, pkts []core.PacketConfig) []uint16 {
	t.Helper()
	var out []uint16
	for _, p := range pkts {
		if len(p.Payload) < 4+64 {
			continue
		}
		if p.Payload[0] != 0x00 {
			continue
		}
		body := p.Payload[4:]
		if string(body[0:4]) != "\xfeSMB" {
			continue
		}
		out = append(out, uint16(body[12])|uint16(body[13])<<8)
	}
	return out
}

// ① 空配置基线：3 握手 + 默认单 read 会话 10 对 PDU（NEGOTIATE 1 对 +
// SESSION_SETUP ntlm 3 轮 3 对 + TREE_CONNECT/CREATE/READ/CLOSE/
// TREE_DISCONNECT/LOGOFF 各 1 对）+ 4 挥手 = 29 包（大 blob 经 tcp 层
// MSS 分段时包数不变——分段只切 TCP 段不增 PDU 事件，此处 29 为事件数）。
func TestSMBChain_BaselineDefault(t *testing.T) {
	pkts := smbDrive(t, map[string]interface{}{})
	if len(pkts) != 29 {
		t.Fatalf("want 29 packets, got %d", len(pkts))
	}
	cmds := smbCmds(t, pkts)
	if len(cmds) != 20 {
		t.Fatalf("want 20 SMB2 PDUs, got %d (%v)", len(cmds), cmds)
	}
	if cmds[0] != 0x0000 {
		t.Fatalf("first PDU cmd %04x, want NEGOTIATE(0)", cmds[0])
	}
}

// ② 显式 close：CLOSE 恰一对（无隐式重复），25 包。
func TestSMBChain_ExplicitCloseOnce(t *testing.T) {
	pkts := smbDrive(t, map[string]interface{}{
		"operations": []interface{}{map[string]interface{}{"op_type": "close"}},
	})
	if len(pkts) != 25 {
		t.Fatalf("want 25 packets, got %d", len(pkts))
	}
	n := 0
	for _, c := range smbCmds(t, pkts) {
		if c == 0x0006 {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("want exactly 1 CLOSE pair (2 PDUs), got %d", n)
	}
}

// ③ netbios 载体：端口 139，包数与 direct 同形。
func TestSMBChain_NetbiosCarrier(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": smbCli, "dst": smbSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": smbSport, "dst_port": 139}},
		map[string]interface{}{"smb": map[string]interface{}{"transport": "netbios"}},
	}
	pkts, err := smbPlan(t, arr)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	if len(pkts) != 29 {
		t.Fatalf("want 29 packets, got %d", len(pkts))
	}
	if pkts[3].L4.DstPort != 139 {
		t.Fatalf("dst port %d, want 139", pkts[3].L4.DstPort)
	}
}

// ④ 非法值同步拒（validator 面，非 ValidationErrors 吞没）。
func TestSMBChain_InvalidValuesReject(t *testing.T) {
	if err := smbDriveErr(t, map[string]interface{}{"auth_mechanism": "bogus"}); err == nil ||
		!strings.Contains(err.Error(), "auth_mechanism must be") {
		t.Fatalf("auth_mechanism=bogus err = %v", err)
	}
	if err := smbDriveErr(t, map[string]interface{}{
		"operations": []interface{}{map[string]interface{}{"op_type": "bogus"}},
	}); err == nil || !strings.Contains(err.Error(), "OpType must be") {
		t.Fatalf("op_type=bogus err = %v", err)
	}
	if err := smbDriveErr(t, map[string]interface{}{
		"error_on_command": "close",
	}); err == nil || !strings.Contains(err.Error(), "ErrorResponseStatus must be non-zero") {
		t.Fatalf("error_on_command w/o status err = %v", err)
	}
}

// ⑤ 层内未知键同步拒（V9 未知字段面）。
func TestSMBChain_UnknownLayerKeyReject(t *testing.T) {
	_, err := smbPlan(t, smbLayers(map[string]interface{}{"bogus_key": 1}, nil))
	if err == nil || !strings.Contains(err.Error(), `unknown field "bogus_key"`) {
		t.Fatalf("bogus_key err = %v", err)
	}
}

// ⑥ carrier 形状：缺 tcp / 混 udp / 混合地址族由预检拒。
func TestSMBChain_CarrierShapes(t *testing.T) {
	// 缺 tcp 载体拒（DependsOn 自动补全前拦，裸 smb 层不被补全掩盖）。
	_, err := layers.BuildLayersPlanner("smb", smbJSON(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": smbCli, "dst": smbSrv}},
		map[string]interface{}{"smb": map[string]interface{}{}},
	}))
	if err == nil || !strings.Contains(err.Error(), "missing tcp carrier") {
		t.Fatalf("missing tcp err = %v", err)
	}
	// udp 混入：transport 冲突拒。
	_, err = layers.BuildLayersPlanner("smb", smbJSON(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": smbCli, "dst": smbSrv}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": smbSport, "dst_port": 445}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": smbSport, "dst_port": 445}},
		map[string]interface{}{"smb": map[string]interface{}{}},
	}))
	if err == nil || !strings.Contains(err.Error(), "udp carrier is not supported") {
		t.Fatalf("udp mix err = %v", err)
	}
	// 混合地址族拒。
	_, err = layers.BuildLayersPlanner("smb", smbJSON(t, []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": smbCli, "dst": smbSrv6}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": smbSport, "dst_port": 445}},
		map[string]interface{}{"smb": map[string]interface{}{}},
	}))
	if err == nil || !strings.Contains(err.Error(), "mixed address family") {
		t.Fatalf("mixed family err = %v", err)
	}
}

// ⑦ 严格解码：顶层未知键 + operations[] 嵌套未知键经 CheckProtoFlat/
// TranslateSMBConfigFromMap 拒。
func TestSMBChain_StrictDecode(t *testing.T) {
	if _, err := core.TranslateSMBConfigFromMap(map[string]interface{}{"bogus": 1}); err == nil {
		t.Fatal("top-level unknown key must be rejected")
	}
	if _, err := core.TranslateSMBConfigFromMap(map[string]interface{}{
		"operations": []interface{}{map[string]interface{}{"op_type": "read", "bogus": 1}},
	}); err == nil {
		t.Fatal("nested op unknown key must be rejected")
	}
	// 宽容值（hex 字符串/error 码）必须通过。
	if _, err := core.TranslateSMBConfigFromMap(map[string]interface{}{
		"error_on_command": "create", "error_response_status": "0xC0000034",
	}); err != nil {
		t.Fatalf("hex status must decode: %v", err)
	}
}

// ⑧ presence 双形状（M5 清单①②）。
func TestSMBChain_PresenceAndStrayTopLevelKeys(t *testing.T) {
	cfg := map[string]interface{}{
		"layers": smbLayers(map[string]interface{}{}, nil),
		"smb":    map[string]interface{}{},
	}
	if msg := core.CheckProtoFlat("smb", cfg); msg == "" {
		t.Fatal("CheckProtoFlat(smb, {layers, smb:{}}) = \"\", want presence rejection")
	} else if !strings.Contains(msg, "no longer accepts a top-level smb sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q", msg)
	}
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": cfg["layers"], k: 1}
		if msg := core.CheckProtoFlat("smb", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(smb, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
	_, errs := schema.ValidateStrategy("synth", "smb", map[string]any{
		"layers":  cfg["layers"],
		"src_mac": "aa:bb:cc:dd:ee:01",
	}, nil)
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "src_mac") {
			found = true
		}
	}
	if !found {
		t.Fatalf("schema must reject top-level src_mac alongside layers, errs=%v", errs)
	}
}

// ⑨ IPv6：同 fixture 同包数。
func TestSMBChain_IPv6Carrier(t *testing.T) {
	arr := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": smbCli6, "dst": smbSrv6}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": smbSport, "dst_port": 445}},
		map[string]interface{}{"smb": map[string]interface{}{}},
	}
	p, err := layers.BuildLayersPlanner("smb", smbJSON(t, arr))
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	spec := core.FlowSpec{SrcIP: smbCli6, DstIP: smbSrv6, SrcPort: smbSport, DstPort: 445}
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	n := 0
	for c := range ch {
		if n == 0 && (c.L3.SrcIP != smbCli6 || c.L3.DstIP != smbSrv6) {
			t.Fatalf("addrs %s -> %s", c.L3.SrcIP, c.L3.DstIP)
		}
		n++
	}
	if n != 29 {
		t.Fatalf("want 29 packets, got %d", n)
	}
}

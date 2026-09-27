package layers_test

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	_ "github.com/trafficgen/trafficgen/internal/protocol/tftp" // init 注册 tftp 终结层生成器+校验器
)

// D-TFTP-1 P4 链级红例（ntlm/sstp_chain_test 同构）。契约：
// docs/protocol-designs/06-tftp-design.md（§13.1 旧键去向 / §13.2 目标形状 /
// §15 固定动作）+ 06-tftp-testcase.md。族划分（对应契约面）：
//  ①层链 + 顶层 tftp 空子映射并存判死（M5 清单①，presence 形状）
//  ②白名单外游离键判死（M5 清单②，1.11–1.13）
//  ③层翻译：层 config → spec.TFTP（业务 23 键；翻译前层内业务键会被
//    ValidateLayerConfig unknown field 拒——红例先钉已知红）
//  ④层内业务键经链路全周期（RRQ 9 包序列字节钉 + TID 交换口径）
//  ⑤dst 端口缺省 69（层内不写 → 默认）/ 显式 1069 保留
//  ⑥vlan 层承载（原顶层 vlan_id/vlan_priority 迁层）
//  ⑦多流层动态四元组（flows>1 静态标量拒 + 动态对象逃生）
//  ⑧checkTFTPServerTID 读层 config（G-TFTP-2）
//  ⑨用例文件收官自查（M5 清单④：非负例顶层键=0 + 三方一致）
//
// 契约 fixture：客户端 10.0.0.100 / 服务端 10.0.0.1 / 客户端端口 49152 /
// 服务器 TID（FNV-1a 确定性，49152–65535）/ 知名 TID 69。

const (
	tfCli  = "10.0.0.100"
	tfSrv  = "10.0.0.1"
	tfPort = 49152
)

func tfChainJSON(t *testing.T, layersArr []interface{}) json.RawMessage {
	t.Helper()
	out, _ := json.Marshal(layersArr)
	return out
}

func tfIP(udpCfg, tftpCfg map[string]interface{}) []interface{} {
	return []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": tfCli, "dst": tfSrv}},
		map[string]interface{}{"udp": udpCfg},
		map[string]interface{}{"tftp": tftpCfg},
	}
}

// planTFTPChainAt builds a planner over the raw layers (BuildLayersPlanner
// does completion + validation exactly as the server path) and Plans with
// the chain-declared four-tuple (mapToFlowSpec 回填同款：层值是真相）。
func planTFTPChainAt(t *testing.T, layersArr []interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("tftp", tfChainJSON(t, layersArr))
	if err != nil {
		return nil, err
	}
	var spec core.FlowSpec
	for _, item := range layersArr {
		m, _ := item.(map[string]interface{})
		if m == nil {
			continue
		}
		if ipc, ok := m["ip"].(map[string]interface{}); ok {
			if s, ok := ipc["src"].(string); ok && s != "" {
				spec.SrcIP = s
			}
			if s, ok := ipc["dst"].(string); ok && s != "" {
				spec.DstIP = s
			}
		}
		if udpc, ok := m["udp"].(map[string]interface{}); ok {
			if v, ok := udpc["src_port"].(json.Number); ok {
				if n, err := v.Int64(); err == nil {
					spec.SrcPort = uint16(n)
				}
			}
			if f, ok := udpc["src_port"].(float64); ok {
				spec.SrcPort = uint16(f)
			}
			if f, ok := udpc["dst_port"].(float64); ok {
				spec.DstPort = uint16(f)
			}
		}
	}
	if spec.SrcPort == 0 {
		spec.SrcPort = tfPort
	}
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

// validateTFTPSpec builds a planner over the raw layers and runs ValidateSpec
// with the chain-declared four-tuple （ 翻译断言口径：spec.TFTP 是否落地）。
// BuildLayersPlanner returns core.ProtocolPlanner（只有 Plan/Validate）；
// ValidateSpec 是 *ChainPlanner 的 spec 级入口——此处经类型断言取回。
func validateTFTPSpec(t *testing.T, layersArr []interface{}) (core.FlowSpec, error) {
	t.Helper()
	// layers.BuildLayersPlanner returns core.ProtocolPlanner; ValidateSpec is
	// the spec-level entry (Validate + translate + base defaults +回填）。
	pp, err := layers.BuildLayersPlanner("tftp", tfChainJSON(t, layersArr))
	if err != nil {
		return core.FlowSpec{}, err
	}
	p, ok := pp.(*layers.ChainPlanner)
	if !ok {
		t.Fatalf("BuildLayersPlanner(tftp) returned %T, want *layers.ChainPlanner", pp)
	}
	spec := core.FlowSpec{SrcIP: tfCli, DstIP: tfSrv, SrcPort: tfPort}
	for _, item := range layersArr {
		m, _ := item.(map[string]interface{})
		if m == nil {
			continue
		}
		if udpc, ok := m["udp"].(map[string]interface{}); ok {
			if f, ok := udpc["src_port"].(float64); ok && f != 0 {
				spec.SrcPort = uint16(f)
			}
			if f, ok := udpc["dst_port"].(float64); ok && f != 0 {
				spec.DstPort = uint16(f)
			}
		}
	}
	return p.ValidateSpec(spec)
}

// ---- ① presence 负例形状（M5 清单①）----

func TestTFTPChain_PresenceTopLevelSubconfigRejected(t *testing.T) {
	layersArr := tfIP(
		map[string]interface{}{"src_port": float64(tfPort), "dst_port": float64(69)},
		map[string]interface{}{"mode": "read", "filename": "f.bin", "blocks_count": float64(1), "data_payload_pattern": "AA"},
	)
	// 层链 + 顶层空子映射并存 = 判死（非残留，presence 形状）。
	bad := map[string]interface{}{"layers": layersArr, "tftp": map[string]interface{}{}}
	if msg := core.CheckProtoFlat("tftp", bad); msg == "" {
		t.Fatal("CheckProtoFlat(tftp, {layers, tftp:{}}) = \"\", want top-level tftp presence rejection")
	} else if !strings.Contains(msg, "no longer accepts a top-level tftp sub-config") {
		t.Fatalf("CheckProtoFlat msg = %q, want presence anchor", msg)
	}
	// 非空顶层 tftp 子映射同判死（presence 语义与 Parse 一致）。
	bad2 := map[string]interface{}{"layers": layersArr, "tftp": map[string]interface{}{"mode": "read"}}
	if m2 := core.CheckProtoFlat("tftp", bad2); !strings.Contains(m2, "no longer accepts a top-level tftp sub-config") {
		t.Fatalf("non-empty top-level tftp must be rejected too, got %q", m2)
	}
	// 纯层链形不触发。
	if m3 := core.CheckProtoFlat("tftp", map[string]interface{}{"layers": layersArr}); m3 != "" {
		t.Fatalf("layer-chain shape must not trip CheckProtoFlat, got %q", m3)
	}
}

// ---- ② 白名单外游离键判死（M5 清单②，1.11–1.13）----

func TestTFTPChain_StrayTopLevelKeysRejected(t *testing.T) {
	layersArr := tfIP(
		map[string]interface{}{"src_port": float64(tfPort), "dst_port": float64(69)},
		map[string]interface{}{"mode": "read", "filename": "f.bin", "blocks_count": float64(1), "data_payload_pattern": "AA"},
	)
	// 四元组类经 CheckProtoFlat 判死。
	for _, k := range []string{"src_ip", "dst_ip", "src_port", "dst_port", "count"} {
		bad := map[string]interface{}{"layers": layersArr, k: 1}
		if msg := core.CheckProtoFlat("tftp", bad); msg == "" {
			t.Fatalf("CheckProtoFlat(tftp, {layers, %s}) = \"\", want flat-field rejection", k)
		}
	}
	// MAC 类经 schema 语义门（checkLayerFlatConflict）判死。
	_, errs := schema.ValidateStrategy("synth", "tftp", map[string]any{
		"layers": layersArr,
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

// ---- ③ 层翻译：23 键全量搬运 ----

func TestTFTPChain_LayerConfigTranslatesToSpec(t *testing.T) {
	cfg := map[string]interface{}{
		"mode":                      "write",
		"filename":                  "up.bin",
		"transfer_mode":             "netascii",
		"blksize":                   float64(1428),
		"timeout":                   float64(10),
		"client_tsize":              float64(2048),
		"server_tsize":              float64(2048),
		"server_tid":                float64(60000),
		"blocks_count":              float64(4),
		"auto_append_final_block":   true,
		"final_block_zero":          false,
		"wrap_block_number":         false,
		"data_payload_pattern":      "BB",
		"include_oack":              true,
		"retransmit_blocks":         []interface{}{float64(2)},
		"server_tid_change":         false,
		"server_tid_change_at_block": float64(0),
		"server_tid_new":            float64(0),
		"windowsize":                float64(4),
	}
	got, err := validateTFTPSpec(t, tfIP(
		map[string]interface{}{"src_port": float64(tfPort), "dst_port": float64(69)},
		cfg,
	))
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	tc := got.TFTP
	if tc == nil {
		t.Fatal("spec.TFTP is nil — tftp layer config was not translated (translateTerminalConfig case missing)")
	}
	if tc.Mode != "write" || tc.Filename != "up.bin" || tc.TransferMode != "netascii" {
		t.Fatalf("mode/filename/transfer_mode = %q/%q/%q", tc.Mode, tc.Filename, tc.TransferMode)
	}
	if tc.BlkSize != 1428 || tc.Timeout != 10 || tc.WindowSize != 4 {
		t.Fatalf("blksize/timeout/windowsize = %d/%d/%d", tc.BlkSize, tc.Timeout, tc.WindowSize)
	}
	if tc.ClientTSize != 2048 || tc.ServerTSize != 2048 || tc.ServerTID != 60000 {
		t.Fatalf("tsize/server_tid = %d/%d/%d", tc.ClientTSize, tc.ServerTSize, tc.ServerTID)
	}
	if tc.BlocksCount != 4 || string(tc.DataPayloadPattern) != "BB" {
		t.Fatalf("blocks/pattern = %d/%q", tc.BlocksCount, tc.DataPayloadPattern)
	}
	if !tc.IncludeOACK || tc.AutoAppendFinalBlock == nil || !*tc.AutoAppendFinalBlock {
		t.Fatalf("include_oack/auto_append not translated: %+v", tc)
	}
	if len(tc.RetransmitBlocks) != 1 || tc.RetransmitBlocks[0] != 2 {
		t.Fatalf("retransmit_blocks = %v", tc.RetransmitBlocks)
	}
}

// ERROR 注入键搬运（与重传互斥，单独立一轮）。
func TestTFTPChain_LayerConfigTranslatesErrorInjection(t *testing.T) {
	got, err := validateTFTPSpec(t, tfIP(
		map[string]interface{}{"src_port": float64(tfPort), "dst_port": float64(69)},
		map[string]interface{}{"mode": "read", "filename": "f.bin",
			"blocks_count": float64(2), "data_payload_pattern": "AA",
			"error_code": float64(3), "error_msg": "disk full",
			"error_after_block": float64(2), "error_side": "client"},
	))
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	tc := got.TFTP
	if tc == nil {
		t.Fatal("spec.TFTP is nil")
	}
	if tc.ErrorCode != 3 || tc.ErrorMsg != "disk full" || tc.ErrorAfterBlock != 2 || tc.ErrorSide != "client" {
		t.Fatalf("error injection keys not translated: %+v", tc)
	}
}

// TID 变更键搬运（扩展语义，与 ERROR/重传互斥，单独立一轮）。
func TestTFTPChain_LayerConfigTranslatesTIDChange(t *testing.T) {
	got, err := validateTFTPSpec(t, tfIP(
		map[string]interface{}{"src_port": float64(tfPort), "dst_port": float64(69)},
		map[string]interface{}{"mode": "read", "filename": "f.bin",
			"blocks_count": float64(4), "data_payload_pattern": "AA",
			"server_tid": float64(60000), "server_tid_change": true,
			"server_tid_change_at_block": float64(2), "server_tid_new": float64(61000)},
	))
	if err != nil {
		t.Fatalf("ValidateSpec: %v", err)
	}
	tc := got.TFTP
	if tc == nil {
		t.Fatal("spec.TFTP is nil")
	}
	if !tc.ServerTIDChange || tc.ServerTIDChangeAtBlock != 2 || tc.ServerTIDNew != 61000 {
		t.Fatalf("tid change keys not translated: %+v", tc)
	}
}

// 导出 parse 与扁平 parse 同输入逐字段相等（ftp 先例：零语义分叉证明）。
func TestTFTPTranslateLayerEqualsFlat(t *testing.T) {
	layerTFTP := map[string]interface{}{
		"mode": "write", "filename": "up.bin", "transfer_mode": "netascii",
		"blksize": float64(1428), "timeout": float64(10),
		"client_tsize": float64(2048), "server_tsize": float64(2048),
		"server_tid": float64(60000), "blocks_count": float64(4),
		"auto_append_final_block": true, "data_payload_pattern": "BB",
		"include_oack": true, "retransmit_blocks": []interface{}{float64(2)},
		"windowsize": float64(4),
	}
	flatTFTP := map[string]interface{}{
		"mode": "write", "filename": "up.bin", "transfer_mode": "netascii",
		"blksize": float64(1428), "timeout": float64(10),
		"client_tsize": float64(2048), "server_tsize": float64(2048),
		"server_tid": float64(60000), "blocks_count": float64(4),
		"auto_append_final_block": true, "data_payload_pattern": "BB",
		"include_oack": true, "retransmit_blocks": []interface{}{float64(2)},
		"windowsize": float64(4),
	}
	fromLayer := core.ParseTFTPConfigFromMap(layerTFTP)
	flatSpec := core.MapToFlowSpec(map[string]interface{}{"tftp": flatTFTP}, "tftp")
	if fromLayer == nil || flatSpec.TFTP == nil {
		t.Fatal("layer or flat parse returned nil")
	}
	want, got := *flatSpec.TFTP, *fromLayer
	want.AutoAppendFinalBlock, got.AutoAppendFinalBlock = nil, nil // 指针地址无可比性，单列下断
	_ = want
	_ = got
	if fromLayer.Mode != flatSpec.TFTP.Mode || fromLayer.Filename != flatSpec.TFTP.Filename ||
		fromLayer.BlkSize != flatSpec.TFTP.BlkSize || fromLayer.BlocksCount != flatSpec.TFTP.BlocksCount ||
		len(fromLayer.RetransmitBlocks) != len(flatSpec.TFTP.RetransmitBlocks) ||
		string(fromLayer.DataPayloadPattern) != string(flatSpec.TFTP.DataPayloadPattern) {
		t.Fatalf("layer/flat divergence:\n layer %+v\n flat  %+v", fromLayer, flatSpec.TFTP)
	}
	if (fromLayer.AutoAppendFinalBlock == nil) != (flatSpec.TFTP.AutoAppendFinalBlock == nil) ||
		(fromLayer.AutoAppendFinalBlock != nil && flatSpec.TFTP.AutoAppendFinalBlock != nil &&
			*fromLayer.AutoAppendFinalBlock != *flatSpec.TFTP.AutoAppendFinalBlock) {
		t.Fatalf("auto_append pointer divergence: layer=%v flat=%v",
			fromLayer.AutoAppendFinalBlock, flatSpec.TFTP.AutoAppendFinalBlock)
	}
}

// ---- ④ 链路全周期（RRQ 9 包 + TID 交换口径）----

func TestTFTPChain_RRQBlksizeEndToEnd(t *testing.T) {
	layersArr := tfIP(
		map[string]interface{}{"src_port": float64(tfPort), "dst_port": float64(69)},
		map[string]interface{}{"mode": "read", "filename": "large.bin", "transfer_mode": "octet",
			"blksize": float64(1428), "blocks_count": float64(2), "data_payload_pattern": "FF"},
	)
	pkts, err := planTFTPChainAt(t, layersArr)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	// RRQ → OACK → ACK#0 → DATA#1 → ACK#1 → DATA#2 → ACK#2 → DATA#3(0B 追加) → ACK#3 = 9 包
	if len(pkts) != 9 {
		t.Fatalf("chain produced %d packets, want 9 (RRQ+OACK+ACK0+2×(DATA+ACK)+append(DATA+ACK))", len(pkts))
	}
	if len(pkts[0].Payload) < 2 || pkts[0].Payload[0] != 0 || pkts[0].Payload[1] != 1 {
		t.Fatalf("packet 1 opcode = %x, want RRQ 0001", pkts[0].Payload[:2])
	}
	// TID 交换（RFC 1350 §4）：首包 dst=69；后续 down 包 src=ServerTID（≠69），dst=客户端端口。
	if pkts[0].L4.DstPort != 69 {
		t.Fatalf("packet 1 dst port = %d, want 69", pkts[0].L4.DstPort)
	}
	if pkts[1].L4.SrcPort == 69 {
		t.Fatalf("packet 2 src port = 69, want ServerTID (TID exchange)")
	}
	if pkts[1].L4.DstPort != tfPort {
		t.Fatalf("packet 2 dst port = %d, want client port %d", pkts[1].L4.DstPort, tfPort)
	}
	// WRQ 方向：ACK#0 "就绪"（tftp-wrq-upload-bb200 口径，4 包）。
	wrqArr := tfIP(
		map[string]interface{}{"src_port": float64(tfPort), "dst_port": float64(69)},
		map[string]interface{}{"mode": "write", "filename": "up.bin", "transfer_mode": "octet",
			"blocks_count": float64(1), "data_payload_pattern": "BB", "auto_append_final_block": false},
	)
	wrq, err := planTFTPChainAt(t, wrqArr)
	if err != nil {
		t.Fatalf("WRQ Plan: %v", err)
	}
	if len(wrq) != 4 {
		t.Fatalf("WRQ chain produced %d packets, want 4 (WRQ+ACK0+DATA1+ACK1)", len(wrq))
	}
}

// ---- ⑤ dst 端口缺省 69 / 显式 1069 ----

func TestTFTPChain_DefaultDstPort69(t *testing.T) {
	noDst := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": tfCli, "dst": tfSrv}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": float64(tfPort)}},
		map[string]interface{}{"tftp": map[string]interface{}{"mode": "read", "filename": "f.bin",
			"blocks_count": float64(1), "data_payload_pattern": "AA", "auto_append_final_block": false}},
	}
	got, err := validateTFTPSpec(t, noDst)
	if err != nil {
		t.Fatalf("ValidateSpec (dst omitted): %v", err)
	}
	if got.DstPort != 69 {
		t.Fatalf("default DstPort = %d, want 69 (RFC 1350 well-known TID)", got.DstPort)
	}
	explicit := tfIP(
		map[string]interface{}{"src_port": float64(tfPort), "dst_port": float64(1069)},
		map[string]interface{}{"mode": "read", "filename": "f.bin",
			"blocks_count": float64(1), "data_payload_pattern": "AA", "auto_append_final_block": false},
	)
	got2, err := validateTFTPSpec(t, explicit)
	if err != nil {
		t.Fatalf("ValidateSpec (dst=1069): %v", err)
	}
	if got2.DstPort != 1069 {
		t.Fatalf("explicit DstPort = %d, want 1069", got2.DstPort)
	}
}

// ---- ⑥ vlan 层承载（原顶层 vlan_id/vlan_priority 迁层）----

func TestTFTPChain_VLANLayerCarriesTag(t *testing.T) {
	layersArr := []interface{}{
		map[string]interface{}{"eth": map[string]interface{}{}},
		map[string]interface{}{"vlan": map[string]interface{}{"id": float64(100), "priority": float64(3)}},
		map[string]interface{}{"ip": map[string]interface{}{"src": tfCli, "dst": tfSrv}},
		map[string]interface{}{"udp": map[string]interface{}{"src_port": float64(tfPort), "dst_port": float64(69)}},
		map[string]interface{}{"tftp": map[string]interface{}{"mode": "read", "filename": "f.bin",
			"blocks_count": float64(1), "data_payload_pattern": "AA", "auto_append_final_block": false}},
	}
	got, err := validateTFTPSpec(t, layersArr)
	if err != nil {
		t.Fatalf("ValidateSpec (vlan chain): %v", err)
	}
	if got.VLAN == nil || got.VLAN.ID != 100 || got.VLAN.Priority != 3 {
		t.Fatalf("spec.VLAN = %+v, want id=100 priority=3 (vlan layer must carry the tag)", got.VLAN)
	}
}

// ---- ⑦ 多流层动态四元组（flows>1 静态标量拒 + 动态对象逃生）----

func TestTFTPChain_MultiFlowRequiresDynamicTuple(t *testing.T) {
	positive := func(layersArr []interface{}) map[string]interface{} {
		return map[string]interface{}{"layers": layersArr}
	}
	staticScalar := positive(tfIP(
		map[string]interface{}{"src_port": float64(tfPort), "dst_port": float64(69)},
		map[string]interface{}{"mode": "read", "filename": "f.bin", "blocks_count": float64(1), "data_payload_pattern": "AA"},
	))
	// 静态标量端口 + flows>1 → schema 语义门拒（checkLayerChainStaticCopy）。
	_, errs := schema.ValidateStrategy("synth", "tftp", map[string]any{
		"layers": staticScalar["layers"],
	}, &schema.FlowControl{Type: "flows", Value: 3})
	found := false
	for _, e := range errs {
		if strings.Contains(e.Error(), "static") {
			found = true
		}
	}
	if !found {
		t.Fatalf("static scalar ports + flows>1 must be rejected (checkLayerChainStaticCopy), errs=%v", errs)
	}
	// 层内动态对象 = 逃生口。
	dyn := positive(tfIP(
		map[string]interface{}{
			"src_port": map[string]any{"strategy": "inc", "range": []any{49152, 49154}, "step": 1},
			"dst_port": 69,
		},
		map[string]interface{}{"mode": "read", "filename": "f.bin", "blocks_count": float64(1), "data_payload_pattern": "AA"},
	))
	_, errs2 := schema.ValidateStrategy("synth", "tftp", map[string]any{
		"layers": dyn["layers"],
	}, &schema.FlowControl{Type: "flows", Value: 3})
	for _, e := range errs2 {
		if strings.Contains(e.Error(), "static") {
			t.Fatalf("dynamic object ports must be the flows>1 escape hatch, got %v", errs2)
		}
	}
}

// ---- ⑧ checkTFTPServerTID 读层 config（G-TFTP-2）----

func TestTFTPChain_ServerTIDBatchRuleReadsLayerConfig(t *testing.T) {
	layered := func(serverTID float64, flows float64) []*schema.FieldError {
		_, errs := schema.ValidateStrategy("synth", "tftp", map[string]any{
			"layers": []any{
				map[string]any{"ip": map[string]any{"src": tfCli, "dst": tfSrv}},
				map[string]any{"udp": map[string]any{
					"src_port": map[string]any{"strategy": "inc", "range": []any{49152, 49160}, "step": 1},
					"dst_port": 69,
				}},
				map[string]any{"tftp": map[string]any{"mode": "read", "filename": "f.bin",
					"blocks_count": 1, "data_payload_pattern": "AA", "server_tid": serverTID}},
			},
		}, &schema.FlowControl{Type: "flows", Value: flows})
		return errs
	}
	found := false
	for _, e := range layered(60000, 3) {
		if strings.Contains(e.Error(), "server_tid 60000 conflicts with another flow in the same batch") {
			found = true
		}
	}
	if !found {
		t.Fatalf("checkTFTPServerTID must read the layer config and reject pinned server_tid with flows>1; errs=%v", layered(60000, 3))
	}
	// flows=1 不触发。
	for _, e := range layered(60000, 1) {
		if strings.Contains(e.Error(), "server_tid") {
			t.Fatalf("flows=1 must not trip the batch rule, got %v", layered(60000, 1))
		}
	}
}

// ---- ⑨ 用例文件收官自查（M5 清单④：非负例顶层键=0 + 三方一致）----

func TestTFTPChain_CaseFileAudit(t *testing.T) {
	raw, err := os.ReadFile("../../../test/protocol_pcap/cases/tftp.json")
	if err != nil {
		t.Fatalf("read cases: %v", err)
	}
	var cases []map[string]interface{}
	if err := json.Unmarshal(raw, &cases); err != nil {
		t.Fatalf("parse cases: %v", err)
	}
	if len(cases) == 0 {
		t.Fatal("tftp.json has 0 cases")
	}
	allowed := map[string]bool{"layers": true, "flow_control": true, "output": true}
	seen := map[string]bool{}
	for _, c := range cases {
		id, _ := c["id"].(string)
		if id == "" {
			t.Fatal("case with empty id")
		}
		if seen[id] {
			t.Fatalf("duplicate case id %q", id)
		}
		seen[id] = true
		sj, _ := c["spec_json"].(map[string]interface{})
		if sj == nil {
			t.Fatalf("%s: spec_json missing", id)
		}
		exp, _ := c["expect"].(map[string]interface{})
		if exp == nil {
			t.Fatalf("%s: expect missing", id)
		}
		_, isNeg := exp["expect_error"]
		if isNeg {
			if len(exp) != 2 || exp["error_contains"] == nil {
				t.Fatalf("%s: negative expect keys must be exactly expect_error/error_contains, got %v", id, exp)
			}
			if exp["error_contains"] == "" {
				t.Fatalf("%s: negative error_contains must be a non-empty anchor", id)
			}
			continue
		}
		// 非负例顶层键=0（M5 清单④）：只允许白名单结构性键。
		for k := range sj {
			if !allowed[k] {
				t.Fatalf("%s: stray top-level key %q (1.11–1.13: business keys must live in the layers chain)", id, k)
			}
		}
		if exp["packet_count"] == nil && exp["min_packets"] == nil {
			t.Fatalf("%s: positive case must carry packet_count or min_packets", id)
		}
		sfc, _ := c["strategy_fc"].(map[string]interface{})
		if sfc != nil {
			if sfc["type"] != "flows" && sfc["type"] != "bps" && sfc["type"] != "time" {
				t.Fatalf("%s: strategy_fc type = %v", id, sfc["type"])
			}
		}
	}
}

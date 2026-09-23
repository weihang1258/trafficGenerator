package layers_test

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	_ "github.com/trafficgen/trafficgen/internal/protocol/xmrmining" // init 注册 xmrmining 终结层生成器+校验器
)

// D-XMR-1 P4 链级红例（edp_chain_test/mmse_chain_test 先例同构）：
// ①login 请求/响应字节钉（成员序 id,jsonrpc,method,params）/②login 拒绝错误
// 路径（Closed）/③job 通知省略顶层 id + modern/legacy 两形态/④submit 接受
// 与拒绝两态/⑤keepalived + KEEPALIVED 状态 + keepalive 别名/⑥getjob
// result=job/⑦pack_next 粘连单段/⑧行长公式抽查；负例⑨未知 wire_fault/
// ⑩未知 kind（method_unknown 自然面）/⑪状态机四自然面（first login/
// before login/after reject→Closed）/⑫hex 值域（blob 下界/奇长/seed_hash/
// target/nonce/0x 前缀）/⑬id_reuse/⑭job_unknown/⑮嵌套未知键/
// ⑯会话间端口一致性/⑰空配置缺省基线（9 包）。
// 契约 fixture 常量：钱包 95 字符 / session id 1be0b7b6-…（36）/
// blob 0707…（76B）/ job_id q7PLU…（28）/ target b88d0600 / nonce d0030040。

const xmrWallet = "48edfHu7V9Z84YzzMa6fUueoELZ9ZRXq9VetWzYGzKt52XU5xvqgzYnDK9URnRoJMk1j8nLwEVsaSWJ4fhdUyZijBGUicoD"

// xmrChainJSON builds the layers JSON [ip,tcp,xmrmining] with the given cfg.
func xmrChainJSON(t *testing.T, cfg map[string]interface{}) json.RawMessage {
	t.Helper()
	chain := []interface{}{
		map[string]interface{}{"ip": map[string]interface{}{"src": "192.0.2.74", "dst": "198.51.100.74"}},
		map[string]interface{}{"tcp": map[string]interface{}{"src_port": 4074, "dst_port": 18081}},
		map[string]interface{}{"xmrmining": cfg},
	}
	out, _ := json.Marshal(chain)
	return out
}

func planXMRChain(t *testing.T, cfg map[string]interface{}) ([]core.PacketConfig, error) {
	t.Helper()
	p, err := layers.BuildLayersPlanner("xmrmining", xmrChainJSON(t, cfg))
	if err != nil {
		return nil, err
	}
	spec := core.FlowSpec{SrcIP: "192.0.2.74", DstIP: "198.51.100.74", SrcPort: 4074, DstPort: 18081}
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

func driveXMR(t *testing.T, cfg map[string]interface{}) []core.PacketConfig {
	t.Helper()
	pkts, err := planXMRChain(t, cfg)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	return pkts
}

func driveXMRErr(t *testing.T, cfg map[string]interface{}) error {
	t.Helper()
	_, err := planXMRChain(t, cfg)
	return err
}

func xmrPayload(t *testing.T, pkts []core.PacketConfig, idx int) string {
	t.Helper()
	if idx >= len(pkts) {
		t.Fatalf("packet %d out of range (have %d packets)", idx, len(pkts))
	}
	return string(pkts[idx].Payload)
}

func xmrLoginEv() map[string]interface{} {
	return map[string]interface{}{
		"kind": "login", "id": 1, "login": xmrWallet, "pass": "x",
		"agent":      "XMRig/6.21.0 (Linux x86_64) libuv/1.44.0 gcc/11.3.0",
		"session_id": "1be0b7b6-b15a-47be-a17d-46b2911cf7d0",
		"job": map[string]interface{}{
			"blob": "070780e6b9d60586ba419a0c224e3c6c3e134cc45c4fa04d8ee2d91c2595463c57eef0a4f0796c000000002fcc4d62fa6c77e76c30017c768be5c61d83ec9d3a085d524ba8053ecc3224660d",
			"algo": "rx/0", "height": 2652853,
			"seed_hash": "c9aa8bd62b73d8cb5f956956e3d5cbcf8dd13e17e1c2a1fcfa88c4d26b9815db",
			"job_id":    "q7PLUPL25UV0z5Ij14IyMk8htXbj", "target": "b88d0600",
			"id": "1be0b7b6-b15a-47be-a17d-46b2911cf7d0",
		},
	}
}

// 红例① login 请求/响应字节钉（现代 job；成员序 id,jsonrpc,method,params，
// 紧凑形态；单 LF 收尾）。9 包 = 3 握手 + login up + 响应 down + 4 挥手。
func TestXMRChain_LoginBaseline(t *testing.T) {
	pkts := driveXMR(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{xmrLoginEv()},
		}},
	})
	if len(pkts) != 9 {
		t.Fatalf("expected 9 packets (3 handshake + 2 lines + 4 teardown), got %d", len(pkts))
	}
	req := xmrPayload(t, pkts, 3)
	wantReq := `{"id":1,"jsonrpc":"2.0","method":"login","params":{"login":"` + xmrWallet + `","pass":"x","agent":"XMRig/6.21.0 (Linux x86_64) libuv/1.44.0 gcc/11.3.0"}}` + "\n"
	if req != wantReq {
		t.Fatalf("login request mismatch:\n got %q\nwant %q", req, wantReq)
	}
	// 行长公式 §3.8：login 请求 = 84 + 1(id) + 95 + 1 + 51 = 232（含 LF）。
	if len(req) != 232 {
		t.Fatalf("login request length = %d, want 232", len(req))
	}
	resp := xmrPayload(t, pkts, 4)
	if !strings.HasPrefix(resp, `{"id":1,"jsonrpc":"2.0","error":null,"result":{"id":"1be0b7b6-b15a-47be-a17d-46b2911cf7d0","job":{"blob":"070780e6`) {
		t.Fatalf("login response prefix mismatch: %q", resp[:60])
	}
	if !strings.Contains(resp, `"status":"OK"}`) || !strings.HasSuffix(resp, "\n") {
		t.Fatalf("login response tail mismatch: %q", resp[len(resp)-40:])
	}
}

// 红例② login 拒绝：错误对象 spec verbatim 文案 + 连接关闭（会话仍 9 包）。
func TestXMRChain_LoginReject(t *testing.T) {
	pkts := driveXMR(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "login", "id": 1, "login": "bad-wallet", "pass": "x", "agent": "XMRig/6.21.0", "status": "error", "err_code": -1, "err_msg": "Invalid payment address provided"},
			},
		}},
	})
	if len(pkts) != 9 {
		t.Fatalf("expected 9 packets, got %d", len(pkts))
	}
	resp := xmrPayload(t, pkts, 4)
	want := `{"id":1,"jsonrpc":"2.0","error":{"code":-1,"message":"Invalid payment address provided"}}` + "\n"
	if resp != want {
		t.Fatalf("login reject mismatch:\n got %q\nwant %q", resp, want)
	}
}

// 红例③ job 通知：顶层省略 id 成员（modern 形态含 params.id；行首 jsonrpc）。
// legacy 形态仅 blob,job_id,target 三成员。
func TestXMRChain_JobNotifyOmitsID(t *testing.T) {
	pkts := driveXMR(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				xmrLoginEv(),
				map[string]interface{}{
					"kind": "job", "job_id": "4BiGm3/RgGQzgkTI/xV0smdA+EGZ",
					"blob": "0707d5efb9d6057e95a35f868231780b3a8649c4e57f3c77eaf437329243eef0b9f4b6987d05b900000000cae7754cb85a0ad8eebf3e0bf55f3ec5e754a1d6b05d46e5c358f907dbcbb72b01",
					"algo": "rx/0", "height": 2652854,
					"seed_hash": "c9aa8bd62b73d8cb5f956956e3d5cbcf8dd13e17e1c2a1fcfa88c4d26b9815db",
					"target":    "b88d0600",
				},
			},
		}},
	})
	if len(pkts) != 10 {
		t.Fatalf("expected 10 packets (3 + 2 login + 1 notify + 4), got %d", len(pkts))
	}
	notify := xmrPayload(t, pkts, 5)
	if !strings.HasPrefix(notify, `{"jsonrpc":"2.0","method":"job","params":{"blob":"0707d5ef`) {
		t.Fatalf("job notify prefix mismatch: %q", notify[:50])
	}
	// 顶层无 "id": 成员（params.id 不受限——notify 对象无 id 回带时整行
	// "id": 只出现在 params 成员内）。
	topLevelID := `"params":{"` // 顶层 id 只可能出现在 params 之前
	if strings.Contains(notify[:strings.Index(notify, topLevelID)], `"id":`) {
		t.Fatalf("job notify must omit top-level id member: %q", notify[:60])
	}
	if !strings.HasSuffix(notify, "\n") {
		t.Fatalf("job notify must end with LF")
	}
}

// 红例④ submit 两态：接受（result {"status":"OK"}）与拒绝（error 对象，
// 会话继续——拒绝后 keepalived 仍合法）。
func TestXMRChain_SubmitTwoStates(t *testing.T) {
	cfg := func(status string) map[string]interface{} {
		submit := map[string]interface{}{
			"kind": "submit", "id": 2, "session_id": "1be0b7b6-b15a-47be-a17d-46b2911cf7d0",
			"job_id": "q7PLUPL25UV0z5Ij14IyMk8htXbj", "nonce": "d0030040",
			"result": "e1364b8782719d7683e2ccd3d8f724bc59dfa780a9e960e7c0e0046acdb40100",
		}
		if status != "" {
			submit["status"] = status
			submit["err_msg"] = "Low difficulty share"
		}
		return map[string]interface{}{
			"sessions": []interface{}{map[string]interface{}{
				"events": []interface{}{xmrLoginEv(), submit},
			}},
		}
	}
	pkts := driveXMR(t, cfg(""))
	if len(pkts) != 11 {
		t.Fatalf("submit accept: expected 11 packets, got %d", len(pkts))
	}
	req := xmrPayload(t, pkts, 5)
	if !strings.HasPrefix(req, `{"id":2,"jsonrpc":"2.0","method":"submit","params":{"id":"1be0b7b6`) {
		t.Fatalf("submit request prefix mismatch: %q", req[:60])
	}
	if got := xmrPayload(t, pkts, 6); got != `{"id":2,"jsonrpc":"2.0","error":null,"result":{"status":"OK"}}`+"\n" {
		t.Fatalf("submit accept response mismatch: %q", got)
	}
	pkts = driveXMR(t, cfg("error"))
	if len(pkts) != 11 {
		t.Fatalf("submit reject: expected 11 packets, got %d", len(pkts))
	}
	if got := xmrPayload(t, pkts, 6); got != `{"id":2,"jsonrpc":"2.0","error":{"code":-1,"message":"Low difficulty share"}}`+"\n" {
		t.Fatalf("submit reject response mismatch: %q", got)
	}
}

// 红例⑤ keepalived：status KEEPALIVED 响应 + keepalive 别名 method。
func TestXMRChain_KeepalivedAndAlias(t *testing.T) {
	cfg := func(alias bool) map[string]interface{} {
		ev := map[string]interface{}{"kind": "keepalived", "id": 3, "session_id": "1be0b7b6-b15a-47be-a17d-46b2911cf7d0"}
		if alias {
			ev["keepalive_alias"] = true
		}
		return map[string]interface{}{
			"sessions": []interface{}{map[string]interface{}{
				"events": []interface{}{xmrLoginEv(), ev},
			}},
		}
	}
	pkts := driveXMR(t, cfg(false))
	if got := xmrPayload(t, pkts, 5); got != `{"id":3,"jsonrpc":"2.0","method":"keepalived","params":{"id":"1be0b7b6-b15a-47be-a17d-46b2911cf7d0"}}`+"\n" {
		t.Fatalf("keepalived request mismatch: %q", got)
	}
	if got := xmrPayload(t, pkts, 6); got != `{"id":3,"jsonrpc":"2.0","error":null,"result":{"status":"KEEPALIVED"}}`+"\n" {
		t.Fatalf("keepalived response mismatch: %q", got)
	}
	if got := xmrPayload(t, pkts, 5); !strings.Contains(got, `"method":"keepalived"`) {
		t.Fatal("expected keepalived method")
	}
	pkts = driveXMR(t, cfg(true))
	if got := xmrPayload(t, pkts, 5); !strings.Contains(got, `"method":"keepalive"`) {
		t.Fatalf("keepalive alias method missing: %q", got)
	}
}

// 红例⑥ getjob：请求 + result 直接为 job 对象。
func TestXMRChain_Getjob(t *testing.T) {
	pkts := driveXMR(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				xmrLoginEv(),
				map[string]interface{}{"kind": "getjob", "id": 4, "session_id": "1be0b7b6-b15a-47be-a17d-46b2911cf7d0"},
			},
		}},
	})
	if len(pkts) != 11 {
		t.Fatalf("expected 11 packets, got %d", len(pkts))
	}
	if got := xmrPayload(t, pkts, 5); !strings.HasPrefix(got, `{"id":4,"jsonrpc":"2.0","method":"getjob","params":{"id":"1be0b7b6`) {
		t.Fatalf("getjob request mismatch: %q", got)
	}
	resp := xmrPayload(t, pkts, 6)
	if !strings.HasPrefix(resp, `{"id":4,"jsonrpc":"2.0","error":null,"result":{"blob":"070780e6`) {
		t.Fatalf("getjob response must carry job object directly: %q", resp[:60])
	}
}

// 红例⑦ pack_next 粘连：job 通知 + submit 请求合并单段（段内恰 2 个 LF，
// 契约 §8 段边界≠行边界），submit 自动响应独立成段。
func TestXMRChain_LinePacking(t *testing.T) {
	pkts := driveXMR(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				xmrLoginEv(),
				map[string]interface{}{
					"kind": "job", "job_id": "4BiGm3/RgGQzgkTI/xV0smdA+EGZ",
					"blob": "0707d5efb9d6057e95a35f868231780b3a8649c4e57f3c77eaf437329243eef0b9f4b6987d05b900000000cae7754cb85a0ad8eebf3e0bf55f3ec5e754a1d6b05d46e5c358f907dbcbb72b01",
					"algo": "rx/0", "height": 2652854,
					"seed_hash": "c9aa8bd62b73d8cb5f956956e3d5cbcf8dd13e17e1c2a1fcfa88c4d26b9815db",
					"target":    "b88d0600",
					"pack_next": true,
				},
				map[string]interface{}{
					"kind": "submit", "id": 2, "session_id": "1be0b7b6-b15a-47be-a17d-46b2911cf7d0",
					"job_id": "4BiGm3/RgGQzgkTI/xV0smdA+EGZ", "nonce": "d0030040",
					"result": "e1364b8782719d7683e2ccd3d8f724bc59dfa780a9e960e7c0e0046acdb40100",
				},
			},
		}},
	})
	// 3 握手 + login 2 行 + 粘连段 1 + submit 响应 1 + 4 挥手 = 11。
	if len(pkts) != 11 {
		t.Fatalf("expected 11 packets, got %d", len(pkts))
	}
	merged := xmrPayload(t, pkts, 5)
	if n := strings.Count(merged, "\n"); n != 2 {
		t.Fatalf("packed segment must contain exactly 2 LF-terminated lines, got %d", n)
	}
	if !strings.HasPrefix(merged, `{"jsonrpc":"2.0","method":"job"`) ||
		!strings.Contains(merged, `"method":"submit"`) {
		t.Fatalf("packed segment must carry job notify + submit request: %q", merged[:60])
	}
}

// 红例⑧ 行长公式抽查（§3.8 三条小公式）：submit 响应 63 / keepalived 响应
// 71 / getjob 请求 98（=61+1+36）。
func TestXMRChain_LineLengthFormulas(t *testing.T) {
	// submit 响应（红例④已钉 63B）；此处抽查 getjob 请求行。
	pkts := driveXMR(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				xmrLoginEv(),
				map[string]interface{}{"kind": "getjob", "id": 4, "session_id": "1be0b7b6-b15a-47be-a17d-46b2911cf7d0"},
			},
		}},
	})
	if got := len(xmrPayload(t, pkts, 5)); got != 98 {
		t.Fatalf("getjob request length = %d, want 98 (61+1+36)", got)
	}
}

// 红例⑨ 未知 wire_fault kind 拒（39 值枚举外即拒）。
func TestXMRChain_UnknownWireFault(t *testing.T) {
	err := driveXMRErr(t, map[string]interface{}{
		"wire_fault": "not_a_known_negative_path_kind",
		"sessions":   []interface{}{map[string]interface{}{"events": []interface{}{xmrLoginEv()}}},
	})
	if err == nil || !strings.Contains(err.Error(), "unknown wire_fault kind") {
		t.Fatalf("unknown wire_fault should be rejected, got %v", err)
	}
	// 39 值之一（注入通道）带锚词拒。
	err = driveXMRErr(t, map[string]interface{}{
		"wire_fault": "json_truncated",
		"sessions":   []interface{}{map[string]interface{}{"events": []interface{}{xmrLoginEv()}}},
	})
	if err == nil || !strings.Contains(err.Error(), "json") {
		t.Fatalf("sanctioned wire_fault should reject with anchor, got %v", err)
	}
}

// 红例⑩ 未知 kind（method_unknown 自然面——kind 白名单）。
func TestXMRChain_UnknownKind(t *testing.T) {
	err := driveXMRErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				xmrLoginEv(),
				map[string]interface{}{"kind": "block_template", "id": 2},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "method_unknown") {
		t.Fatalf("unknown kind should be rejected (method_unknown), got %v", err)
	}
}

// 红例⑪ 状态机自然面：首事件非 login / 未登录先 submit / login 拒绝后
// 继续排事件（Closed 终态——勘误 B6 死代码，真拒绝）。
func TestXMRChain_StateMachineNatural(t *testing.T) {
	// 首事件非 login。
	err := driveXMRErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{"kind": "job", "job_id": "j1"}},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "first application message must be login") {
		t.Fatalf("non-login first event should be rejected, got %v", err)
	}
	// login 拒绝后继续排 keepalived → Closed 拒（错误含 login/state 双锚词）。
	err = driveXMRErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				map[string]interface{}{"kind": "login", "id": 1, "login": "w", "status": "error", "err_code": -1, "err_msg": "Invalid payment address provided"},
				map[string]interface{}{"kind": "keepalived", "id": 2, "session_id": "s"},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "login") || !strings.Contains(err.Error(), "state") {
		t.Fatalf("events after rejected login should be rejected (login/state), got %v", err)
	}
}

// 红例⑫ hex 值域自然面：blob 下界（<43B）/奇长/seed_hash 非 64/target 非
// 4|8B/nonce 非 8/0x 前缀。
func TestXMRChain_HexDomains(t *testing.T) {
	blob43 := "ab" // 1B — 远低于 43B 下界
	cases := []struct {
		name string
		ev   map[string]interface{}
		want string
	}{
		{"blob_short", map[string]interface{}{"kind": "job", "job_id": "j1", "blob": blob43, "target": "b88d0600", "seed_hash": strings.Repeat("a", 64)}, "below the 43-byte lower bound"},
		{"blob_odd", map[string]interface{}{"kind": "job", "job_id": "j1", "blob": "070", "target": "b88d0600", "seed_hash": strings.Repeat("a", 64)}, "odd"},
		{"blob_nonhex", map[string]interface{}{"kind": "job", "job_id": "j1", "blob": strings.Repeat("g", 86), "target": "b88d0600", "seed_hash": strings.Repeat("a", 64)}, "non-hex"},
		{"seed_hash", map[string]interface{}{"kind": "job", "job_id": "j1", "blob": strings.Repeat("ab", 76), "target": "b88d0600", "seed_hash": "zz"}, "seed_hash"},
		{"target_len", map[string]interface{}{"kind": "job", "job_id": "j1", "blob": strings.Repeat("ab", 76), "target": "b88d06", "seed_hash": strings.Repeat("a", 64)}, "target length"},
		{"hex_prefix", map[string]interface{}{"kind": "job", "job_id": "j1", "blob": "0x" + strings.Repeat("ab", 76), "target": "b88d0600", "seed_hash": strings.Repeat("a", 64)}, "0x prefix"},
	}
	for _, tc := range cases {
		err := driveXMRErr(t, map[string]interface{}{
			"sessions": []interface{}{map[string]interface{}{
				"events": []interface{}{xmrLoginEv(), tc.ev},
			}},
		})
		if err == nil {
			t.Fatalf("%s: expected rejection", tc.name)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Fatalf("%s: want anchor %q in %v", tc.name, tc.want, err)
		}
	}
	// submit nonce 非 8 hex（经 hex_blob 通道外的 nonce 守卫）。
	err := driveXMRErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				xmrLoginEv(),
				map[string]interface{}{"kind": "submit", "id": 2, "job_id": "q7PLUPL25UV0z5Ij14IyMk8htXbj", "nonce": "d00300", "result": strings.Repeat("a", 64)},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "nonce") {
		t.Fatalf("short nonce should be rejected, got %v", err)
	}
}

// 红例⑬ id_reuse：同会话请求 id 复用拒。
func TestXMRChain_IDReuse(t *testing.T) {
	err := driveXMRErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				xmrLoginEv(),
				map[string]interface{}{"kind": "keepalived", "id": 1, "session_id": "1be0b7b6-b15a-47be-a17d-46b2911cf7d0"},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "id_reuse") {
		t.Fatalf("id reuse should be rejected, got %v", err)
	}
}

// 红例⑭ job_unknown：submit 引用未收过的 job_id 拒。
func TestXMRChain_JobUnknown(t *testing.T) {
	err := driveXMRErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				xmrLoginEv(),
				map[string]interface{}{"kind": "submit", "id": 2, "job_id": "never-seen-job-id", "nonce": "d0030040", "result": strings.Repeat("a", 64)},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "not from this session's jobs") {
		t.Fatalf("unknown job_id should be rejected, got %v", err)
	}
}

// 红例⑮ 嵌套级未知键严格拒（DisallowUnknownFields 三级递归——edp 红例⑲
// 同款）。
func TestXMRChain_NestedUnknownKeys(t *testing.T) {
	_, err := planXMRChain(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"bogus_sess_key": 1,
			"events":         []interface{}{xmrLoginEv()},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "bogus_sess_key") {
		t.Fatalf("session-level unknown key should be rejected, got %v", err)
	}
	_, err = planXMRChain(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{map[string]interface{}{
				"kind": "login", "id": 1, "login": "w",
				"bogus_ev_key": 1,
			}},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "bogus_ev_key") {
		t.Fatalf("event-level unknown key should be rejected, got %v", err)
	}
}

// 红例⑯ 会话间 dst_port 一致性（裁定2：port_conflict 自然面——edp 修轮
// F10 同款守卫）。
func TestXMRChain_SessionPortConflict(t *testing.T) {
	err := driveXMRErr(t, map[string]interface{}{
		"sessions": []interface{}{
			map[string]interface{}{"src_port": 4074, "dst_port": 18081, "events": []interface{}{xmrLoginEv()}},
			map[string]interface{}{"src_port": 4075, "dst_port": 3333, "events": []interface{}{xmrLoginEv()}},
		},
	})
	if err == nil || !strings.Contains(err.Error(), "port") {
		t.Fatalf("conflicting session dst_ports should be rejected, got %v", err)
	}
}

// 红例⑰ 空配置缺省基线：bare {"xmrmining":{}} 层 → 缺省单 login 会话
// （9 包；端口继承链级 18081）。
func TestXMRChain_EmptyConfigBaseline(t *testing.T) {
	pkts := driveXMR(t, map[string]interface{}{})
	if len(pkts) != 9 {
		t.Fatalf("empty config: expected 9 packets (default login baseline), got %d", len(pkts))
	}
	if got := xmrPayload(t, pkts, 3); !strings.HasPrefix(got, `{"id":1,"jsonrpc":"2.0","method":"login"`) {
		t.Fatalf("empty config baseline must emit default login, got %q", got[:40])
	}
}

// 红例⑱ 请求 id 会话内迭代（终审 H1：缺省派生收进单解析权威——同会话双
// submit 线上 id 必须递增，契约 §3.1"由矿机迭代、会话内唯一"）。
func TestXMRChain_RequestIDIterates(t *testing.T) {
	pkts := driveXMR(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				xmrLoginEv(), // id 恒 1（声明）
				map[string]interface{}{
					"kind": "submit", "job_id": "q7PLUPL25UV0z5Ij14IyMk8htXbj",
					"nonce": "00000000", "result": strings.Repeat("a", 64),
				},
				map[string]interface{}{
					"kind": "submit", "job_id": "q7PLUPL25UV0z5Ij14IyMk8htXbj",
					"nonce": "ffffffff", "result": strings.Repeat("b", 64),
				},
			},
		}},
	})
	// 3 握手 + login 2 + submit1 2 + submit2 2 + 4 挥手 = 13。
	if len(pkts) != 13 {
		t.Fatalf("expected 13 packets, got %d", len(pkts))
	}
	first := xmrPayload(t, pkts, 5)
	second := xmrPayload(t, pkts, 7)
	if !strings.HasPrefix(first, `{"id":2,"jsonrpc":"2.0","method":"submit"`) {
		t.Fatalf("first submit (undeclared id) must take id=2, got %q", first[:40])
	}
	if !strings.HasPrefix(second, `{"id":3,"jsonrpc":"2.0","method":"submit"`) {
		t.Fatalf("second submit (undeclared id) must iterate to id=3, got %q", second[:40])
	}
	// 响应同值回带（迭代值）。
	if got := xmrPayload(t, pkts, 8); !strings.HasPrefix(got, `{"id":3,`) {
		t.Fatalf("second submit response must echo id=3, got %q", got[:30])
	}
}

// 红例⑲ keepalived 会话 id 等值守卫（终审 H2：契约 §7 负例 59 明文含
// keepalived——params.id ≠ 本会话 session id 自然拒）。
func TestXMRChain_KeepalivedSessionMismatch(t *testing.T) {
	err := driveXMRErr(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				xmrLoginEv(),
				map[string]interface{}{"kind": "keepalived", "id": 2, "session_id": "ffff-bogus-session"},
			},
		}},
	})
	if err == nil || !strings.Contains(err.Error(), "session") {
		t.Fatalf("keepalived with mismatched session id should be rejected, got %v", err)
	}
}

// 红例⑳ getjob 响应 job 登记 validator 已收集合（终审 M1：合法
// getjob→submit 新 job_id 不得被 job_unknown 误拒）。
func TestXMRChain_GetjobJobRegistered(t *testing.T) {
	pkts := driveXMR(t, map[string]interface{}{
		"sessions": []interface{}{map[string]interface{}{
			"events": []interface{}{
				xmrLoginEv(),
				map[string]interface{}{"kind": "getjob", "id": 2, "session_id": "1be0b7b6-b15a-47be-a17d-46b2911cf7d0"},
				map[string]interface{}{
					"kind": "submit", "id": 3, "session_id": "1be0b7b6-b15a-47be-a17d-46b2911cf7d0",
					"job_id": "q7PLUPL25UV0z5Ij14IyMk8htXbj", "nonce": "d0030040",
					"result": strings.Repeat("a", 64),
				},
			},
		}},
	})
	if len(pkts) != 13 {
		t.Fatalf("expected 13 packets (3+2+2+2+4), got %d", len(pkts))
	}
}

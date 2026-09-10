package ftp

import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// T-FTP-10..14（D-FTP-2 §7 步骤4）：FTP 会话/事务/负载动态。
func ftpDynSpec(fcCount int, mutate func(*core.FTPConfig)) core.FlowSpec {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 20000, DstPort: 21,
		Count: fcCount,
		FTP: &core.FTPConfig{
			Sessions: []core.FTPSession{{
				Transactions: []core.FTPTransaction{{
					Commands: []core.FTPCommand{
						{Cmd: "USER anonymous", Response: "331"},
					},
				}},
			}},
		},
	}
	if mutate != nil {
		mutate(spec.FTP)
	}
	return spec
}

// T-FTP-10：会话级动态 src_port/banner 按流序号解析；独立四元组与横幅逐流。
func TestFTPSessionDynamicPortBanner(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 21,
		Count: 2,
		FTP: &core.FTPConfig{
			Sessions: []core.FTPSession{{
				Transactions: []core.FTPTransaction{{
					Commands: []core.FTPCommand{{Cmd: "QUIT", Response: "221"}},
				}},
			}},
		},
	}
	spec.FTP.Sessions[0].SrcPortDyn = &core.StrategyConfig{Strategy: "inc", Range: []interface{}{21000, 21001}}
	spec.FTP.Sessions[0].BannerDyn = &core.StrategyConfig{Strategy: "list", List: []string{"220 a", "220 b"}}

	for i, wantPort := range []uint16{21000, 21001} {
		wantBanner := []string{"220 a", "220 b"}[i]
		oneSpec := spec
		oneSpec.FlowIndex = i
		pkts := collectFTP(t, oneSpec)
		flowID := "10.0.0.1-20.0.0.1-21000-21"
		if i == 1 {
			flowID = "10.0.0.1-20.0.0.1-21001-21"
		}
		_ = wantPort // flowID 串里已含端口（21000/21001），存在性即端口断言
		var sawFlow, sawBanner bool
		for _, p := range pkts {
			if p.FlowID == flowID {
				sawFlow = true
				if strings.Contains(string(p.Payload), wantBanner) {
					sawBanner = true
				}
			}
		}
		if !sawFlow {
			t.Errorf("flow %d: %q absent", i, flowID)
		}
		if !sawBanner {
			t.Errorf("flow %d: banner %q not found", i, wantBanner)
		}
	}
}

// T-FTP-11：cmd pattern 逐流解析 + PASV 端口推导取已解析响应。
func TestFTPDynCommands(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 22000, DstPort: 21,
		Count: 2,
		FTP: &core.FTPConfig{
			Sessions: []core.FTPSession{{
				Transactions: []core.FTPTransaction{
					{
						Commands: []core.FTPCommand{
							{Response: "331", CmdDyn: &core.StrategyConfig{Strategy: "pattern", Pattern: "USER user{n}", Range: []interface{}{1, 2}}},
						},
					},
					{
						Commands: []core.FTPCommand{
							{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,73)"},
							{Response: "150", EmitDataChannel: true, CmdDyn: &core.StrategyConfig{Strategy: "pattern", Pattern: "RETR f{n}", Range: []interface{}{1, 3}}},
						},
						DataChannel: &core.FTPDataChannel{Payload: "D"},
					},
				},
			}},
		},
	}
	expect := map[int]map[string]bool{
		0: {"USER user1": true, "RETR f1": true},
		1: {"USER user2": true, "RETR f2": true},
	}
	for i, wants := range expect {
		oneSpec := spec
		oneSpec.FlowIndex = i
		pkts := collectFTP(t, oneSpec)
		for want := range wants {
			found := false
			for _, p := range pkts {
				if p.Direction == "up" && strings.Contains(string(p.Payload), want) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("flow %d: up payload %q not found", i, want)
			}
		}
		if i == 0 {
			// PASV derivation from RESOLVED (here static) response: data flow server port 49993.
			var dPort uint16
			for _, p := range pkts {
				if strings.Contains(p.FlowID, ":sub-") && p.Direction == "down" && p.L4.SrcPort != 0 && dPort == 0 {
					dPort = p.L4.SrcPort
				}
			}
			if dPort != 49993 {
				t.Errorf("flow 0 data port = %d, want 49993", dPort)
			}
		}
	}
}

// T-FTP-12：payload 动态逐流 + FileSource 优先级（文件内容压过动态/静态文本）。
func TestFTPDynPayload(t *testing.T) {
	// ① dynamic payload per flow
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 24000, DstPort: 21,
		Count: 2,
		FTP: &core.FTPConfig{
			Sessions: []core.FTPSession{{
				Transactions: []core.FTPTransaction{{
					Commands: []core.FTPCommand{
						{Cmd: "RETR", Response: "150", EmitDataChannel: true},
					},
					DataChannel: &core.FTPDataChannel{
						PayloadDyn: &core.StrategyConfig{Strategy: "pattern", Pattern: "FILE-{n}", Range: []interface{}{1, 3}},
					},
				}},
			}},
		},
	}
	for i, want := range []string{"FILE-1", "FILE-2"} {
		oneSpec := spec
		oneSpec.FlowIndex = i
		pkts := collectFTP(t, oneSpec)
		found := false
		for _, p := range pkts {
			if strings.Contains(p.FlowID, ":sub-") && strings.Contains(string(p.Payload), want) {
				found = true
			}
		}
		if !found {
			t.Errorf("flow %d: data payload %q not found", i, want)
		}
	}

	// ② Static wins when present (D-FTP-2 §4 priority: 静态非空 > 动态) —
	// STATIC emitted, resolved FILE-1 not. FileSource>dynamic priority is
	// covered by the payload-cache harness in ftp_filesource_test.go.
	spec2 := spec
	spec2.FTP.Sessions[0].Transactions[0].DataChannel.Payload = "STATIC"
	oneSpec := spec2
	oneSpec.FlowIndex = 0
	pkts := collectFTP(t, oneSpec)
	var sawStatic, sawDyn bool
	for _, p := range pkts {
		if strings.Contains(p.FlowID, ":sub-") {
			if strings.Contains(string(p.Payload), "STATIC") {
				sawStatic = true
			}
			if strings.Contains(string(p.Payload), "FILE-") {
				sawDyn = true
			}
		}
	}
	if !sawStatic || sawDyn {
		t.Errorf("static-present priority violated: static=%v dynLeak=%v", sawStatic, sawDyn)
	}
}

// T-FTP-13：FTP 字段 rand 同 seed+序号两次 Plan 序列一致。
func TestFTPDynReproducible(t *testing.T) {
	mk := func() core.FlowSpec {
		spec := core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 25000, DstPort: 21,
			Count: 3,
			FTP: &core.FTPConfig{
				Sessions: []core.FTPSession{{
					Transactions: []core.FTPTransaction{{
						Commands: []core.FTPCommand{{Cmd: "QUIT", Response: "221"}},
					}},
				}},
			},
		}
		spec.FTP.Sessions[0].BannerDyn = &core.StrategyConfig{Strategy: "rand", Range: []interface{}{1, 100}, Seed: 7}
		return spec
	}
	run := func() [][]string {
		out := [][]string{}
		for i := 0; i < 3; i++ {
			spec := mk()
			spec.FlowIndex = i
			pkts := collectFTP(t, spec)
			var pay []string
			for _, p := range pkts {
				if len(p.Payload) > 0 {
					pay = append(pay, string(p.Payload))
				}
			}
			out = append(out, pay)
		}
		return out
	}
	a, b := run(), run()
	for i := range a {
		if strings.Join(a[i], "|") != strings.Join(b[i], "|") {
			t.Fatalf("flow %d diverges:\n%v\n%v", i, a[i], b[i])
		}
	}
}

// T-FTP-14：畸形动态配置拒绝——Validate 返回 error（锚词：strategy/range/list）。
func TestFTPDynInvalid(t *testing.T) {
	p := NewPlanner()
	cases := []struct {
		name   string
		mutate func(*core.FTPConfig)
		anchor string
	}{
		{"inc_no_range", func(c *core.FTPConfig) {
			c.Sessions[0].SrcPortDyn = &core.StrategyConfig{Strategy: "inc"}
		}, "range"},
		{"unknown_strategy", func(c *core.FTPConfig) {
			c.Sessions[0].BannerDyn = &core.StrategyConfig{Strategy: "nope"}
		}, "unknown dynamic strategy"},
		{"empty_list", func(c *core.FTPConfig) {
			c.Sessions[0].Transactions[0].Commands[0].CmdDyn = &core.StrategyConfig{Strategy: "list", List: []string{}}
		}, "non-empty list"},
		{"pattern_no_range", func(c *core.FTPConfig) {
			c.Sessions[0].Transactions[0].Commands[0].CmdDyn = &core.StrategyConfig{Strategy: "pattern", Pattern: "CMD {n}"}
		}, "2-element range"},
		{"inc_end_before_start", func(c *core.FTPConfig) {
			c.Sessions[0].Transactions[0].Commands[0].ResponseDyn = &core.StrategyConfig{Strategy: "inc", Range: []interface{}{100, 50}}
		}, "start must not exceed end"},
		{"list_port_end_before_start", func(c *core.FTPConfig) {
			c.Sessions[0].SrcPortDyn = &core.StrategyConfig{Strategy: "inc", Range: []interface{}{60000, 20000}}
		}, "start must not exceed end"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			spec := ftpDynSpec(2, tc.mutate)
			err := p.Validate(spec)
			if err == nil {
				t.Fatalf("want error, got clean (malformed dyn silently accepted)")
			}
			if !strings.Contains(err.Error(), tc.anchor) {
				t.Errorf("error %q missing anchor %q", err.Error(), tc.anchor)
			}
		})
	}
}

// T-FTP-16：FTP sessions 静态复制拒绝——Count>1 + 全静态端口（或显式 spec
// 端口+全继承）→ Validate error；任一会话动态端口 / Count=1 → 通过。
func TestFTPStaticCopyRejection(t *testing.T) {
	p := NewPlanner()
	mk := func(count int, mutate func(*core.FTPConfig)) core.FlowSpec {
		return ftpDynSpec(count, mutate)
	}
	// ① two pinned sessions + Count=2 → reject
	spec := mk(2, func(c *core.FTPConfig) {
		c.Sessions = append(c.Sessions, c.Sessions[0])
		c.Sessions[0].SrcPort, c.Sessions[1].SrcPort = 21000, 21001
	})
	if err := p.Validate(spec); err == nil || !strings.Contains(err.Error(), "static copy") {
		t.Errorf("① want static-copy reject, got %v", err)
	}
	// ② same shape but one session port dynamic → pass
	spec2 := mk(2, func(c *core.FTPConfig) {
		c.Sessions = append(c.Sessions, c.Sessions[0])
		c.Sessions[0].SrcPort, c.Sessions[1].SrcPort = 21000, 21001
		c.Sessions[0].SrcPortDyn = &core.StrategyConfig{Strategy: "inc", Range: []interface{}{21000, 21001}}
		c.Sessions[1].SrcPortDyn = &core.StrategyConfig{Strategy: "inc", Range: []interface{}{21000, 21001}}
	})
	if err := p.Validate(spec2); err != nil {
		t.Errorf("② dynamic session port must pass, got %v", err)
	}
	// ③ single inherit session + Count=1 → pass
	spec3 := mk(1, nil)
	if err := p.Validate(spec3); err != nil {
		t.Errorf("③ Count=1 inherit must pass, got %v", err)
	}
	// ④ explicit spec src_port + inherit session + Count=2 → reject
	spec4 := mk(2, nil)
	spec4.SrcPort = 24000
	spec4.HasExplicitSrcPort = true
	if err := p.Validate(spec4); err == nil || !strings.Contains(err.Error(), "static copy") {
		t.Errorf("④ want static-copy reject, got %v", err)
	}
	// ⑤ single pinned session + Count=2 → reject
	spec5 := mk(2, func(c *core.FTPConfig) {
		c.Sessions[0].SrcPort = 25000
	})
	if err := p.Validate(spec5); err == nil || !strings.Contains(err.Error(), "static copy") {
		t.Errorf("⑤ want static-copy reject, got %v", err)
	}
}

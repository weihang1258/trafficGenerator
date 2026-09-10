package ftp

import (
	"context"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// collect drains the planner output channel into a slice.
func collectFTP(t *testing.T, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	p := NewPlanner()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	var out []core.PacketConfig
	for cfg := range ch {
		out = append(out, cfg)
	}
	return out
}

func ftpMultiSessionSpec() core.FlowSpec {
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 21000, DstPort: 21,
		FTP: &core.FTPConfig{
			Sessions: []core.FTPSession{
				{
					SrcPort: 20000, Banner: "220 s1",
					Transactions: []core.FTPTransaction{
						{
							Commands: []core.FTPCommand{
								{Cmd: "USER anonymous", Response: "331"},
								{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,73)"},
								{Cmd: "RETR /a.bin", Response: "150", EmitDataChannel: true},
								{Cmd: "", Response: "226"},
							},
							DataChannel: &core.FTPDataChannel{Payload: "FILE-A"},
						},
					},
				},
				{
					SrcPort: 20001, Banner: "220 s2",
					Transactions: []core.FTPTransaction{
						{
							Commands: []core.FTPCommand{
								{Cmd: "CWD /pub", Response: "250"},
								{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,74)"},
								{Cmd: "LIST", Response: "150", EmitDataChannel: true},
								{Cmd: "", Response: "226"},
							},
							DataChannel: &core.FTPDataChannel{Payload: "DIR-LIST"},
						},
					},
				},
			},
		},
	}
}

func ftpPayloadOf(cfg core.PacketConfig) string {
	return string(cfg.Payload)
}

// T-FTP-2（D-FTP-1 §3）：双会话操作序列——独立四元组、序号隔离、命令归属。
func TestFTPMultiSession(t *testing.T) {
	spec := ftpMultiSessionSpec()
	pkts := collectFTP(t, spec)
	if len(pkts) == 0 {
		t.Fatal("no packets")
	}
	// 每会话 flowID 独立（四元组拼串，SrcPort 覆盖生效）
	s1Flow := "10.0.0.1-20.0.0.1-20000-21"
	s2Flow := "10.0.0.1-20.0.0.1-20001-21"
	flows := map[string]int{}
	for _, p := range pkts {
		if p.Direction == "up" || p.Direction == "down" {
			flows[p.FlowID]++
		}
	}
	if flows[s1Flow] == 0 {
		t.Errorf("session1 flow %q absent; got flows %v", s1Flow, flows)
	}
	if flows[s2Flow] == 0 {
		t.Errorf("session2 flow %q absent; got flows %v", s2Flow, flows)
	}
	// 命令归属：RETR 只在会话1（控制流或其数据流前缀），LIST 只在会话2
	// （数据流 FlowID = {parent}:sub-{i}，按 parent 前缀判定归属）
	for _, p := range pkts {
		if strings.Contains(ftpPayloadOf(p), "RETR") && !strings.HasPrefix(p.FlowID, s1Flow) {
			t.Errorf("RETR leaked to %q", p.FlowID)
		}
		if strings.Contains(ftpPayloadOf(p), "LIST") && !strings.HasPrefix(p.FlowID, s2Flow) {
			t.Errorf("LIST leaked to %q", p.FlowID)
		}
	}
	// 每会话独立握手：两个 flowID 各有至少一个 SYN（flags 0x02）
	syn := map[string]bool{}
	for _, p := range pkts {
		if p.L4.Flags == 0x02 {
			syn[p.FlowID] = true
		}
	}
	if !syn[s1Flow] || !syn[s2Flow] {
		t.Errorf("each session needs own SYN: %v", syn)
	}
	// 首个 SYN 的 clientSeq：两会话各自起始（可复现性由 rand 保证，这里只断言握手起点=SYN seq）
	firstSeq := map[string]uint32{}
	for _, p := range pkts {
		if p.L4.Flags == 0x02 {
			if _, ok := firstSeq[p.FlowID]; !ok {
				firstSeq[p.FlowID] = p.L4.Seq
			}
		}
	}
	if firstSeq[s1Flow] == firstSeq[s2Flow] {
		t.Errorf("two sessions share clientSeq %d (ISN collision)", firstSeq[s1Flow])
	}
}

// T-FTP-3（D-FTP-1 §3）：数据流挂载事务索引——sub-0/sub-1 区分。
func TestFTPDataChannelTxIndex(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 22000, DstPort: 21,
		FTP: &core.FTPConfig{
			Sessions: []core.FTPSession{{
				Banner: "220 s",
				Transactions: []core.FTPTransaction{
					{
						Commands: []core.FTPCommand{
							{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,91)"},
							{Cmd: "RETR", Response: "150", EmitDataChannel: true},
						},
						DataChannel: &core.FTPDataChannel{Payload: "D0"},
					},
					{
						Commands: []core.FTPCommand{
							{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,92)"},
							{Cmd: "LIST", Response: "150", EmitDataChannel: true},
						},
						DataChannel: &core.FTPDataChannel{Payload: "D1"},
					},
				},
			}},
		},
	}
	pkts := collectFTP(t, spec)
	parent := "10.0.0.1-20.0.0.1-22000-21"
	sub0, sub1 := parent+":sub-0", parent+":sub-1"
	var s0, s1 bool
	var d0Port, d1Port uint16
	for _, p := range pkts {
		switch p.FlowID {
		case sub0:
			s0 = true
			if p.Direction == "down" && p.L4.SrcPort != 0 && d0Port == 0 {
				d0Port = p.L4.SrcPort
			}
		case sub1:
			s1 = true
			if p.Direction == "down" && p.L4.SrcPort != 0 && d1Port == 0 {
				d1Port = p.L4.SrcPort
			}
		}
	}
	if !s0 {
		t.Errorf("data flow %q absent", sub0)
	}
	if !s1 {
		t.Errorf("data flow %q absent", sub1)
	}
	// PASV 端口推导：195,73→50001? 实际 195*256+91=50011、195*256+92=50012
	if d0Port != 50011 || d1Port != 50012 {
		t.Errorf("data ports = %d/%d, want 50011/50012 (per-tx PASV)", d0Port, d1Port)
	}
}

// T-FTP-4（D-FTP-1 §1）：跨事务 PASV 端口不串扰——全局扫描旧实现会让
// 事务2 的数据流也用 50011；收窄后事务2 取自己的 50012。
func TestFTPPASVIsolation(t *testing.T) {
	spec := core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 21000, DstPort: 21,
		FTP: &core.FTPConfig{
			Sessions: []core.FTPSession{{
				Banner: "220 s",
				Transactions: []core.FTPTransaction{
					{
						Commands: []core.FTPCommand{
							{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,73)"},
							{Cmd: "RETR", Response: "150", EmitDataChannel: true},
						},
						DataChannel: &core.FTPDataChannel{Payload: "F1"},
					},
					{
						Commands: []core.FTPCommand{
							{Cmd: "PASV", Response: "227 Entering Passive Mode (20,0,0,1,195,74)"},
							{Cmd: "LIST", Response: "150", EmitDataChannel: true},
						},
						DataChannel: &core.FTPDataChannel{Payload: "F2"},
					},
				},
			}},
		},
	}
	pkts := collectFTP(t, spec)
	parent := "10.0.0.1-20.0.0.1-21000-21"
	var d0Port, d1Port uint16
	for _, p := range pkts {
		switch p.FlowID {
		case parent + ":sub-0":
			if p.Direction == "down" && p.L4.SrcPort != 0 && d0Port == 0 {
				d0Port = p.L4.SrcPort
			}
		case parent + ":sub-1":
			if p.Direction == "down" && p.L4.SrcPort != 0 && d1Port == 0 {
				d1Port = p.L4.SrcPort
			}
		}
	}
	if d0Port != 49993 || d1Port != 49994 {
		t.Errorf("data ports = %d/%d, want 49993/49994 (PASV isolation)", d0Port, d1Port)
	}
}

// T-FTP-5（D-FTP-1 §5 边界）：空会话合法——仅握手3+teardown4=7 包。
// （评审中从边界探针转正：设计 §5 "会话无事务→仅握手+banner+teardown"。）
func TestFTPEmptySession(t *testing.T) {
	pkts := collectFTP(t, core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 23000, DstPort: 21,
		FTP: &core.FTPConfig{Sessions: []core.FTPSession{{SrcPort: 23001}}},
	})
	if len(pkts) != 7 {
		t.Fatalf("empty session pkts=%d, want 7 (3 handshake + 4 teardown)", len(pkts))
	}
}

// T-FTP-6（D-FTP-1 §5 边界）：DataChannel 存在但无 EmitDataChannel 标记
// 不发射数据流（与老路径 cmd.EmitDataChannel && dc != nil 判定同语义）。
func TestFTPDataChannelNoFlag(t *testing.T) {
	pkts := collectFTP(t, core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 24000, DstPort: 21,
		FTP: &core.FTPConfig{Sessions: []core.FTPSession{{
			Transactions: []core.FTPTransaction{{
				Commands:    []core.FTPCommand{{Cmd: "RETR", Response: "150"}},
				DataChannel: &core.FTPDataChannel{Payload: "X"},
			}},
		}}},
	})
	for _, p := range pkts {
		if strings.Contains(p.FlowID, ":sub-") {
			t.Fatalf("unexpected subflow %q without EmitDataChannel", p.FlowID)
		}
	}
}

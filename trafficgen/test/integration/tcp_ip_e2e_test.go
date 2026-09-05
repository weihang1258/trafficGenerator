package integration_test

// T5.2 tcp_ip_e2e：TCP 重传状态机 + IP checksum 经全引擎产线的端到端
// 验证（Engine → ChainPlanner → PacketWorker → Builder → PCAPWriter →
// pcap → gopacket/逐字节断言）。
//
// 与 internal/core/layers/tcp_retransmit_wire_test.go 的分工：wire 测试只
// 走 Plan() 通道（PacketConfig 层，未建帧）；本文件断言的是产线产物——
// pcap 里真实以太网帧的 TCP flag/seq 序列（重传 dup 段 + 恢复 ACK 落盘）
// 与 IPv4 头校验和（builder writeL3 填的 checksum 对每帧重算必须吻合，
// CLAUDE.md 测试政策 §4：跨层功能必须有全路径测试；§5：断言可观察产物）。
//
// Run: go test ./test/integration/ -run TestTCPIPE2E -count=1 -timeout 60s

import (
	"encoding/binary"
	"path/filepath"
	"testing"

	"github.com/google/gopacket"
	gplayers "github.com/google/gopacket/layers"
	gpcap "github.com/google/gopacket/pcap"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/output"
)

// TestTCPIPE2E_RetransmitOnWire 全引擎跑 [tcp{retransmit:true}] 任务（补全后 [eth→ip→tcp]）
// （3×MSS 载荷），断言 pcap 落盘的完整 15 帧序列含重传 dup 段：
//
//	SYN / SYN-ACK / ACK                     （握手 3）
//	PSH-ACK×3 + ACK×3                       （数据 6，末段对端 ACK 模拟丢失）
//	dup PSH-ACK(尾段 seq 重发) + 恢复 ACK    （RTO 重传轮 2）
//	FIN / ACK / FIN / ACK                    （挥手 4）
func TestTCPIPE2E_RetransmitOnWire(t *testing.T) {
	e := newLayerChainEngine(t, "tcp")
	taskID := "tcpip-retrans"
	pcapPath := filepath.Join(t.TempDir(), "retrans.pcap")

	pw, err := output.NewPCAPWriter(pcapPath)
	if err != nil {
		t.Fatalf("create pcap writer: %v", err)
	}
	e.RegisterOutputWriter(taskID, &timedPcapWriter{w: pw})
	t.Cleanup(func() { e.UnregisterOutputWriter(taskID) })

	payload := make([]byte, 3*1460) // 3 full-MSS segments at mss=1460
	for i := range payload {
		payload[i] = byte(i)
	}
	if err := e.SubmitTask(core.Task{
		ID: taskID, Name: "tcpip-e2e-retrans", Protocol: "tcp",
		ClassID: taskID, ParentTaskID: taskID,
		Spec: core.FlowSpec{
			Count: 1, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 80,
			Payload: payload,
		},
		Layers: []byte(`[{"tcp": {"mss": 1460, "retransmit": true}}]`),
	}); err != nil {
		t.Fatalf("submit task: %v", err)
	}
	waitTaskTerminal(t, e, taskID)
	if err := pw.Close(); err != nil {
		t.Fatalf("close pcap writer: %v", err)
	}

	tcps := parsePcapTCP(t, pcapPath)
	if len(tcps) != 15 {
		t.Fatalf("pcap packet count = %d, want 15 (3 handshake + 6 data + 2 retransmit + 4 teardown)", len(tcps))
	}

	var syn, synack, dataSegs, plainAcks, dupSeq uint32
	seqSeen := map[uint32]int{}
	for _, p := range tcps {
		if !p.hasTCP {
			t.Fatalf("non-TCP packet in tcp retransmit pcap")
		}
		f := p.tcp
		switch {
		case f.SYN && !f.ACK:
			syn++
		case f.SYN && f.ACK:
			synack++
		case f.PSH:
			dataSegs++
			seqSeen[f.Seq]++
		case f.FIN:
			// teardown FINs counted implicitly via total
		case f.ACK && len(f.Payload) == 0 && !f.SYN && !f.FIN:
			plainAcks++
		}
	}
	// 第 3+1 数据段（dup 尾段）：同一 seq 出现 2 次。
	for _, n := range seqSeen {
		if n == 2 {
			dupSeq++
		}
	}
	if syn != 1 || synack != 1 {
		t.Errorf("handshake: SYN=%d SYN-ACK=%d, want 1/1", syn, synack)
	}
	if dataSegs != 4 {
		t.Errorf("data segments (PSH-ACK) = %d, want 4 (3 original + 1 retransmit)", dataSegs)
	}
	if dupSeq != 1 {
		t.Errorf("retransmitted seqs (seq emitted twice) = %d, want exactly 1 (tail-loss segment)", dupSeq)
	}
	// plain ACK（无 SYN/FIN/PSH）：握手第 3 帧 1 + 数据 ACK 3 + 恢复 ACK 1 + 挥手 ACK 2 = 7
	if plainAcks != 7 {
		t.Errorf("plain ACKs = %d, want 7 (1 handshake-final + 3 data + 1 recovery + 2 teardown)", plainAcks)
	}

	// 校验和逐帧重算由 TestTCPIPE2E_IPChecksum 独立断言；此处固定 15 帧
	// 形状已由上方的 flag/seq 计数覆盖。
}

// TestTCPIPE2E_IPChecksum 对同一引擎产线产出的多协议帧（tcp 链 + udp 链
// 双任务）逐帧重算 IPv4 头校验和：RFC 791 §3.1 —— 头部字段（含已填
// checksum）按 16-bit 字累加（含进位折叠）必须得 0xFFFF。断言的是
// builder writeL3 → calculateIPChecksum 的真实落盘字节，而非 Plan 期
// PacketConfig（测试政策 §5：断言可观察产物）。
func TestTCPIPE2E_IPChecksum(t *testing.T) {
	e := newLayerChainEngine(t, "tcp", "dns")
	dir := t.TempDir()

	type sub struct {
		taskID, path string
		layersJSON   []byte
		spec         core.FlowSpec
	}
	subs := []sub{
		{
			taskID: "cksum-tcp", path: filepath.Join(dir, "cksum-tcp.pcap"),
			layersJSON: []byte(`[{"tcp": {"mss": 1460}}]`),
			spec: core.FlowSpec{Count: 1, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 12345, DstPort: 80,
				Payload: []byte("checksum-e2e-payload")},
		},
		{
			taskID: "cksum-udp", path: filepath.Join(dir, "cksum-udp.pcap"),
			layersJSON: []byte(`[{"udp": {}}, {"dns": {}}]`),
			spec:       core.FlowSpec{Count: 1, SrcIP: "10.0.0.1", DstIP: "20.0.0.1", SrcPort: 40069, DstPort: 53},
		},
	}
	for _, s := range subs {
		pw, err := output.NewPCAPWriter(s.path)
		if err != nil {
			t.Fatalf("create pcap writer: %v", err)
		}
		e.RegisterOutputWriter(s.taskID, &timedPcapWriter{w: pw})
		if err := e.SubmitTask(core.Task{
			ID: s.taskID, Name: "tcpip-e2e-cksum-" + s.taskID, Protocol: map[string]string{"cksum-tcp": "tcp", "cksum-udp": "dns"}[s.taskID],
			ClassID: s.taskID, ParentTaskID: s.taskID, Spec: s.spec, Layers: s.layersJSON,
		}); err != nil {
			e.UnregisterOutputWriter(s.taskID)
			t.Fatalf("submit %s: %v", s.taskID, err)
		}
		waitTaskTerminal(t, e, s.taskID)
		if err := pw.Close(); err != nil {
			t.Fatalf("close writer %s: %v", s.taskID, err)
		}
		e.UnregisterOutputWriter(s.taskID)

		// 逐帧重算：读原始以太网帧 → 提取 IPv4 头 → 头部和（含 checksum）
		// 折叠后必须为 0xFFFF（RFC 791 §3.1 校验和自验性质）。
		pkts := readRawFrames(t, s.path)
		if len(pkts) == 0 {
			t.Fatalf("%s: pcap empty — engine→chain→worker→writer path broken", s.taskID)
		}
		for i, frame := range pkts {
			if len(frame) < 14+20 {
				t.Fatalf("%s pkt[%d]: frame too short for eth+ipv4 (%d bytes)", s.taskID, i, len(frame))
			}
			if binary.BigEndian.Uint16(frame[12:14]) != 0x0800 {
				t.Fatalf("%s pkt[%d]: not IPv4 ethertype", s.taskID, i)
			}
			hdrLen := int(frame[14]&0x0f) * 4
			if hdrLen < 20 || 14+hdrLen > len(frame) {
				t.Fatalf("%s pkt[%d]: bad ihl %d", s.taskID, i, hdrLen)
			}
			sum := ipHeaderSum(frame[14 : 14+hdrLen])
			if sum != 0xFFFF {
				t.Errorf("%s pkt[%d]: IPv4 header checksum invalid — folded sum=%#x (want 0xFFFF), pkt bytes %d", s.taskID, i, sum, len(frame))
			}
		}
		t.Logf("%s: %d frames, all IPv4 header checksums verify", s.taskID, len(pkts))
	}
}

// ipHeaderSum sums an IPv4 header (checksum field included) as 16-bit
// one's-complement words with carry folding — the verification identity is
// sum == 0xFFFF for a header whose checksum was computed per RFC 791 §3.1.
func ipHeaderSum(hdr []byte) uint16 {
	var sum uint32
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	if len(hdr)%2 == 1 { // pad odd byte (defensive; ihl is always even)
		sum += uint32(hdr[len(hdr)-1]) << 8
	}
	sum = (sum >> 16) + (sum & 0xffff)
	sum += sum >> 16
	return uint16(sum)
}

// readRawFrames reads all raw Ethernet frames from a pcap file (raw
// packet.Data() bytes, no layer decoding, so checksum verification runs on
// the exact on-disk bytes).
func readRawFrames(t *testing.T, path string) [][]byte {
	t.Helper()
	handle, err := gpcap.OpenOffline(path)
	if err != nil {
		t.Fatalf("open pcap %s: %v", path, err)
	}
	defer handle.Close()
	var out [][]byte
	packetSource := gopacket.NewPacketSource(handle, gplayers.LinkTypeEthernet)
	for packet := range packetSource.Packets() {
		out = append(out, packet.Data())
	}
	return out
}

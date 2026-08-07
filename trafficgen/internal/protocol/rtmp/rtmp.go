// Package rtmp implements the Adobe RTMP (Real-Time Messaging Protocol) planner.
// RTMP 是基于 TCP 的流媒体协议 (默认端口 1935),用于音视频流的推拉.
// 参考 pcap: llcj_mirror/IP-TCP-20.7.1.84-30.7.1.84-50216-1935-379-500-29190-729154.pcap
//
// 会话流程 (session flow):
//  1. TCP 三次握手 (SYN/SYN-ACK/ACK) + TCP 选项 (MSS/WinScale/SACK)
//  2. RTMP 握手 (handshake):
//     a. C0+C1 (客户端→服务端): 1字节版本(0x03) + 1536字节时间戳/随机数据
//     b. S0+S1+S2 (服务端→客户端): 1字节版本(0x03) + 1536字节时间戳/随机数据
//        + 1536字节C1回显 (echo of C1 random bytes)
//     c. C2 (客户端→服务端): 1536字节S1回显 (echo of S1 random bytes)
//  3. 命令阶段 (command phase), 所有消息使用 AMF0 编码封装在 RTMP chunk 中:
//     a. connect() (客户端→服务端): AMF0 "connect" + txnID=0.0 + 命令对象 {app, tcUrl, ...}
//     b. 服务端响应 (服务端→客户端): Window Ack Size + Set Peer Bandwidth +
//        Stream Begin + Set Chunk Size + _result()
//     c. Window Ack Size (客户端→服务端): 客户端回显窗口确认大小
//     d. createStream() (客户端→服务端): 创建媒体流
//     e. Set Buffer Length (客户端→服务端): 设置缓冲长度
//     f. _result() (服务端→客户端): createStream 成功响应
//     g. play()/publish() (客户端→服务端): 开始拉流/推流
//  4. 数据阶段 (data phase, 可选): 音视频 chunk,
//     MsgType=8 音频, MsgType=9 视频
//  5. TCP 四次挥手 (FIN/FIN-ACK/ACK)
//
// RTMP chunk 格式 (chunk format):
//   - 基本头部 (basic header): 1字节, fmt(2位) + chunk stream ID(6位)
//   - 消息头部 (message header, type 0): 11字节
//     [时间戳(3字节)] + [消息长度(3字节)] + [消息类型ID(1字节)] + [流ID(4字节,小端)]
//   - chunk 数据: 最多 chunk_size 字节的 AMF 消息数据
//
// 本 planner 所有 chunk 使用 type 0 头部 (12字节完整头部),
// chunk stream ID 分配: 3=协议控制/命令, 4=音频, 6=视频 (参考 pcap).
package rtmp

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

const (
	// DefaultPort (默认端口) is the canonical RTMP port.
	DefaultPort = 1935

	// DefaultTTL (默认TTL) used when spec.TTL is zero.
	DefaultTTL = 64

	// DefaultMSS (默认MSS) mirrors internal/protocol/tcp.DefaultMSS (1460).
	DefaultMSS = 1460

	// MinMSS (最小MSS) per RFC 879.
	MinMSS = 536

	// RTMPVersion (RTMP版本) is fixed 0x03 per Adobe RTMP specification.
	RTMPVersion = 0x03

	// HandshakeSize (握手数据大小) per RTMP specification.
	C0Size = 1   // C0: 1字节版本号
	C1Size = 1536 // C1: 4字节时间戳 + 4字节零 + 1528字节随机
	S0Size = 1   // S0: 1字节版本号
	S1Size = 1536 // S1: 4字节时间戳 + 4字节零 + 1528字节随机
	S2Size = 1536 // S2: 4字节时间戳(回显S1) + 4字节时间戳 + 1528字节随机(C1回显)
	C2Size = 1536 // C2: 4字节时间戳(回显S1) + 4字节时间戳 + 1528字节随机(S1回显)

	// RTMP chunk stream IDs (chunk 流 ID 分配, 参考 pcap):
	// 服务端响应 chunk (Window Ack, Set Peer Bandwidth, Stream Begin, Set Chunk Size, _result)
	// 使用 CSID 2; 客户端命令 (connect, Window Ack, createStream, play) 使用 CSID 3.
	CSIDProtocol = 2 // 服务端协议控制消息和 _result (参考 pcap 服务端响应 csid=2)
	CSIDCommand  = 3 // 客户端 AMF 命令 (connect, createStream, play, publish)
	CSIDAudio    = 4 // 音频数据
	CSIDVideo    = 6 // 视频数据

	// RTMP message type IDs (消息类型 ID, RTMP 规范 §11.4):
	MsgTypeSetChunkSize     = 1  // Set Chunk Size (设置 chunk 大小)
	MsgTypeWindowAckSize    = 5  // Window Acknowledgement Size (窗口确认大小)
	MsgTypeSetPeerBandwidth = 6  // Set Peer Bandwidth (设置对端带宽)
	MsgTypeStreamBegin      = 4  // User Control: Stream Begin (流开始)
	MsgTypeAMF0Command      = 20 // AMF0 Command (connect, createStream, play, etc.)
	MsgTypeAudio            = 8  // Audio Data (音频数据)
	MsgTypeVideo            = 9  // Video Data (视频数据)

	// ChunkType0 (chunk 头部类型 0): 完整 12字节头部.
	// 基本头部 1字节 + 消息头部 11字节 = 12字节.
	ChunkType0 = 0x00 // fmt=0 in basic header

	// AMF0 type markers (AMF0 类型标记):
	AMF0Number  = 0x00 // IEEE 754 双精度浮点 (8字节)
	AMF0String  = 0x02 // UTF-8 字符串 (2字节长度 + 数据)
	AMF0Object  = 0x03 // 对象 (键值对序列, 以 00 00 09 结束)
	AMF0Null    = 0x05 // null 值
	AMF0Bool    = 0x01 // 布尔值 (1字节)

	// MaxAppLen (应用名最大长度) for safe AMF0 encoding.
	MaxAppLen = 255

	// DefaultWinAckSize (默认窗口确认大小) — 参考 pcap 值 2500000.
	DefaultWinAckSize = 2500000

	// DefaultChunkSize (默认 chunk 大小) — 参考 pcap 值 4096.
	DefaultChunkSize = 4096

	// DefaultBufferLen (默认缓冲长度, 毫秒) — 参考 pcap 值 3000.
	DefaultBufferLen = 3000
)

// Planner implements the RTMP protocol planner.
type Planner struct{}

// NewPlanner creates a new RTMP planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name.
func (p *Planner) Name() string { return "rtmp" }

// Validate validates an RTMP flow spec.
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("rtmp: invalid SrcIP %q", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("rtmp: invalid DstIP %q", spec.DstIP)
		}
	}

	r := spec.RTMP
	if r == nil {
		return fmt.Errorf("rtmp: RTMPConfig is required")
	}

	// App (应用名) validation.
	if len(r.App) > MaxAppLen {
		return fmt.Errorf("rtmp: App exceeds %d bytes", MaxAppLen)
	}

	// Command (命令类型) validation.
	cmd := normalizeCmd(r.Command)
	if cmd != "" && cmd != "play" && cmd != "publish" {
		return fmt.Errorf("rtmp: invalid Command %q (supported: play, publish)", r.Command)
	}

	// MSS (最大分段大小) validation.
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		if spec.TCP.MSS < MinMSS {
			return fmt.Errorf("rtmp: TCP.MSS %d too small (min %d)", spec.TCP.MSS, MinMSS)
		}
	}

	// Data chunk MsgType validation.
	for i, dc := range r.Data {
		mt := dc.MsgType
		if mt != 0 && mt != MsgTypeAudio && mt != MsgTypeVideo {
			return fmt.Errorf("rtmp: Data[%d].MsgType %d invalid (supported: 8=audio, 9=video)", i, mt)
		}
	}

	return nil
}

// Plan generates packet configs for an RTMP flow.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		r := spec.RTMP
		if r == nil {
			r = &core.RTMPConfig{}
		}

		// Default values (默认值).
		app := r.App
		if app == "" {
			app = "live"
		}
		tcURL := r.TcURL
		if tcURL == "" {
			tcURL = fmt.Sprintf("rtmp://%s/%s", spec.DstIP, app)
		}
		cmd := normalizeCmd(r.Command)
		if cmd == "" {
			cmd = "play"
		}
		streamName := r.StreamName
		if streamName == "" {
			streamName = "stream"
		}

		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}

		// Resolve MSS (最大分段大小).
		mss := uint16(DefaultMSS)
		if spec.TCP != nil && spec.TCP.MSS > 0 {
			mss = spec.TCP.MSS
		}
		synOpts := synOptions(mss)

		now := time.Now()
		packetIndex := uint64(0)
		ipID := uint16(0)
		nextIPID := func() uint16 {
			id := ipID
			ipID++
			return id
		}

		// Random ISN per RFC 6528 (随机初始序列号).
		clientSeq := uint32(0)
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = randUint32()
		}
		serverSeq := randUint32()

		winSize := uint16(65535)

		// emit (发送包) sends a TCP packet config to the channel.
		emit := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
			if payload == nil {
				payload = []byte{}
			}
			l3 := core.L3Base(srcIP, dstIP, 6, effectiveTTL, nextIPID(), spec)
			l4 := core.L4Config{
				Protocol:   "tcp",
				SrcPort:    srcPort,
				DstPort:    dstPort,
				Seq:        seq,
				Ack:        ack,
				Flags:      flags,
				WindowSize: winSize,
			}
			if flags == 0x02 || flags == 0x12 {
				l4.TCPOptions = synOpts
			}
			cfg := core.PacketConfig{
				FlowID:      flowID,
				PacketIndex: packetIndex,
				Direction:   direction,
				Timestamp:   now,
				L2: core.L2Config{
					SrcMAC:    srcMAC,
					DstMAC:    dstMAC,
					EtherType: core.EtherTypeFor(spec.SrcIP),
				},
				L3:       l3,
				L4:       l4,
				Payload:  payload,
				Metadata: groupIDMeta(spec),
			}
			select {
			case <-ctx.Done():
				return
			case configChan <- cfg:
			}
			packetIndex++
		}

		// emitData (发送数据段) segments payload by MSS and emits each chunk
		// as a PSH-ACK in the given direction, advancing the sender's seq.
		emitData := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, senderSeq, peerSeq uint32, payload []byte) (newSenderSeq uint32) {
			for _, seg := range segmentByMSS(payload, int(mss)) {
				select {
				case <-ctx.Done():
					return senderSeq
				default:
				}
				emit(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, senderSeq, peerSeq, 0x18, seg)
				senderSeq += uint32(len(seg))
			}
			return senderSeq
		}

		// --- TCP 三次握手 (TCP 3-way handshake) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

		// --- RTMP 握手 (RTMP handshake) ---

		// C0+C1 (客户端→服务端): 版本(0x03) + 时间戳(4B) + 零(4B) + 随机(1528B)
		c0c1 := buildC0C1()
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, c0c1)

		// S0+S1+S2 (服务端→客户端): 版本(0x03) + S1(1536B) + S2(1536B, C1回显)
		s0s1s2 := buildS0S1S2(c0c1)
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, s0s1s2)

		// C2 (客户端→服务端): S1回显 (echo of S1 random bytes)
		c2 := buildC2(s0s1s2)
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, c2)

		// --- 命令阶段 (command phase) ---

		// connect() (客户端→服务端, CSID=3)
		connectMsg := buildAMF0Chunk(CSIDCommand, MsgTypeAMF0Command, 0, buildConnectAMF0(app, tcURL))
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, connectMsg)

		// 服务端响应 (server response, CSID=2):
		// Window Ack Size + Set Peer Bandwidth + Stream Begin + Set Chunk Size + _result()
		serverResp := buildServerResponse()
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, serverResp)

		// Window Ack Size (客户端→服务端, CSID=2): 客户端回显
		clientWinAck := buildAMF0Chunk(CSIDProtocol, MsgTypeWindowAckSize, 0, buildWinAckSizePayload(DefaultWinAckSize))
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, clientWinAck)

		// createStream() (客户端→服务端, CSID=3)
		createStreamMsg := buildAMF0Chunk(CSIDCommand, MsgTypeAMF0Command, 0, buildCreateStreamAMF0())
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, createStreamMsg)

		// Set Buffer Length (客户端→服务端, CSID=3): User Control Message
		setBufLen := buildSetBufferLength(1, DefaultBufferLen)
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, setBufLen)

		// _result() (服务端→客户端, CSID=2): createStream 成功响应
		createStreamResult := buildAMF0Chunk(CSIDProtocol, MsgTypeAMF0Command, 0, buildCreateStreamResult())
		serverSeq = emitData("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, createStreamResult)

		// play()/publish() (客户端→服务端, CSID=3)
		var playPublish []byte
		if cmd == "publish" {
			playPublish = buildAMF0Chunk(CSIDCommand, MsgTypeAMF0Command, 1, buildPublishAMF0(streamName))
		} else {
			playPublish = buildAMF0Chunk(CSIDCommand, MsgTypeAMF0Command, 1, buildPlayAMF0(streamName))
		}
		clientSeq = emitData("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, playPublish)

		// --- 数据阶段 (data phase, 可选) ---
		if len(r.Data) > 0 {
			for _, dc := range r.Data {
				select {
				case <-ctx.Done():
					return
				default:
				}
				dir := normalizeDirection(dc.Direction)
				if dir == "" {
					dir = "down" // 默认: 服务端→客户端 (play 拉流)
				}

				mt := dc.MsgType
				if mt == 0 {
					if dir == "down" {
						mt = MsgTypeVideo // 默认视频
					} else {
						mt = MsgTypeAudio // 默认音频 (publish 推流)
					}
				}

				csid := dc.ChunkStreamID
				if csid == 0 {
					if mt == MsgTypeAudio {
						csid = CSIDAudio
					} else {
						csid = CSIDVideo
					}
				}

				payload := dc.Payload
				if len(payload) == 0 {
					payload = make([]byte, 100) // 默认 100 字节模拟帧
				}

				chunk := buildAMF0Chunk(csid, mt, 1, payload)

				var srcMAC, dstMAC, srcIP, dstIP string
				var srcPort, dstPort uint16
				if dir == "down" {
					srcMAC, dstMAC = spec.DstMAC, spec.SrcMAC
					srcIP, dstIP = spec.DstIP, spec.SrcIP
					srcPort, dstPort = spec.DstPort, spec.SrcPort
					serverSeq = emitData("down", srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, serverSeq, clientSeq, chunk)
				} else {
					srcMAC, dstMAC = spec.SrcMAC, spec.DstMAC
					srcIP, dstIP = spec.SrcIP, spec.DstIP
					srcPort, dstPort = spec.SrcPort, spec.DstPort
					clientSeq = emitData("up", srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort, clientSeq, serverSeq, chunk)
				}
			}
		}

		// --- TCP 四次挥手 (TCP 4-way teardown) ---
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
		clientSeq++
		emit("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP, spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
		serverSeq++
		emit("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
	}()

	return configChan, nil
}

// --- 握手构建函数 (handshake builders) ---

// buildC0C1 builds the client handshake C0+C1 (1537字节).
// C0: 版本 0x03 (1字节).
// C1: 时间戳(4字节) + 零(4字节) + 随机数据(1528字节).
func buildC0C1() []byte {
	buf := make([]byte, C0Size+C1Size)
	buf[0] = RTMPVersion // C0: 版本号
	// C1: 4字节时间戳 (随机), 4字节零, 1528字节随机
	ts := randUint32()
	binary.BigEndian.PutUint32(buf[1:5], ts)
	// buf[5:9] already zero
	// Fill 1528 bytes of random data at buf[9:1537]
	_, _ = rand.Read(buf[9:])
	return buf
}

// buildS0S1S2 builds the server handshake S0+S1+S2 (3073字节).
// S0: 版本 0x03 (1字节).
// S1: 时间戳(4字节) + 零(4字节) + 随机(1528字节).
// S2: 时间戳(4字节, 回显C1时间戳) + 时间戳2(4字节) + C1随机回显(1528字节).
// c0c1 is the client's C0+C1 bytes (用于 S2 回显 C1 随机数据).
func buildS0S1S2(c0c1 []byte) []byte {
	buf := make([]byte, S0Size+S1Size+S2Size)
	buf[0] = RTMPVersion // S0: 版本号

	// S1: 4字节时间戳 + 4字节零 + 1528字节随机
	s1TS := randUint32()
	binary.BigEndian.PutUint32(buf[1:5], s1TS)
	// buf[5:9] already zero
	_, _ = rand.Read(buf[9 : 9+1528])

	// S2: echo of C1
	// S2[0:4] = C1 timestamp (echo of C1's timestamp)
	copy(buf[1537:1541], c0c1[1:5])
	// S2[4:8] = server timestamp
	binary.BigEndian.PutUint32(buf[1541:1545], s1TS)
	// S2[8:1536] = echo of C1 random bytes (C1[9:1537])
	copy(buf[1545:], c0c1[9:9+1528])

	return buf
}

// buildC2 builds the client C2 (1536字节), echo of S1.
// s0s1s2 is the server's S0+S1+S2 bytes (用于 S1 回显).
func buildC2(s0s1s2 []byte) []byte {
	buf := make([]byte, C2Size)
	// C2[0:4] = S1 timestamp (echo of S1's timestamp)
	copy(buf[0:4], s0s1s2[1:5])
	// C2[4:8] = client timestamp
	c2TS := randUint32()
	binary.BigEndian.PutUint32(buf[4:8], c2TS)
	// C2[8:1536] = echo of S1 random bytes (S1[9:1537])
	copy(buf[8:], s0s1s2[9:9+1528])
	return buf
}

// --- AMF0 编码函数 (AMF0 encoding) ---

// amf0String encodes an AMF0 UTF-8 string: 0x02 + 2字节长度 + 数据.
func amf0String(s string) []byte {
	buf := make([]byte, 3+len(s))
	buf[0] = AMF0String
	binary.BigEndian.PutUint16(buf[1:3], uint16(len(s)))
	copy(buf[3:], s)
	return buf
}

// amf0Number encodes an AMF0 number: 0x00 + 8字节 IEEE 754 双精度.
func amf0Number(v float64) []byte {
	buf := make([]byte, 9)
	buf[0] = AMF0Number
	binary.BigEndian.PutUint64(buf[1:9], uint64(floatToUint64(v)))
	return buf
}

// amf0Object builds an AMF0 object with the given key-value properties.
// 对象格式: 0x03 + 属性序列(key=AMF string without 0x02 marker, value=AMF data) + 00 00 09 (对象结束标记).
// 使用有序键值对切片 (非 map) 保证编码顺序稳定 (Go map 迭代顺序不确定).
type amf0Prop struct {
	Key   string
	Value []byte
}

func amf0Object(props []amf0Prop) []byte {
	var buf []byte
	buf = append(buf, AMF0Object)
	for _, p := range props {
		// 属性键: 2字节长度前缀 + UTF-8 字符串 (无 0x02 类型标记).
		keyBytes := make([]byte, 2+len(p.Key))
		binary.BigEndian.PutUint16(keyBytes[0:2], uint16(len(p.Key)))
		copy(keyBytes[2:], p.Key)
		buf = append(buf, keyBytes...)
		buf = append(buf, p.Value...)
	}
	// 对象结束标记: 0x00 0x00 0x09
	buf = append(buf, 0x00, 0x00, 0x09)
	return buf
}

// amf0Null encodes an AMF0 null: 0x05.
func amf0Null() []byte {
	return []byte{AMF0Null}
}

// --- RTMP chunk 构建函数 (chunk builders) ---

// buildAMF0Chunk wraps AMF data in an RTMP chunk (type 0 header, 12字节头部).
// basic header: 0x40|csid (fmt=0, chunk stream ID).
// message header: timestamp(3B) + length(3B) + typeID(1B) + streamID(4B, little-endian).
func buildAMF0Chunk(csid uint8, msgType uint8, streamID uint32, amfData []byte) []byte {
	msgLen := len(amfData)
	// 基本头部: fmt=0 (2位) + csid (6位)
	basicHeader := byte(ChunkType0<<6) | (csid & 0x3F)
	ts := uint32(0) // 时间戳=0 (握手后第一个消息)

	buf := make([]byte, 0, 12+msgLen)
	buf = append(buf, basicHeader)
	// 消息头部 (11字节):
	// 时间戳 (3字节, 大端)
	buf = append(buf, byte(ts>>16), byte(ts>>8), byte(ts))
	// 消息长度 (3字节, 大端)
	buf = append(buf, byte(msgLen>>16), byte(msgLen>>8), byte(msgLen))
	// 消息类型 ID (1字节)
	buf = append(buf, msgType)
	// 流 ID (4字节, 小端 per RTMP spec)
	buf = append(buf, byte(streamID), byte(streamID>>8), byte(streamID>>16), byte(streamID>>24))
	// chunk 数据
	buf = append(buf, amfData...)
	return buf
}

// --- 命令构建函数 (command builders) ---

// buildConnectAMF0 builds the AMF0 payload for the connect() command.
// 格式: "connect"(AMF string) + 1.0(AMF number, transaction ID, 参考 pcap) + 命令对象(AMF object).
// 命令对象包含: app, tcUrl (参考 pcap).
func buildConnectAMF0(app, tcURL string) []byte {
	var buf []byte
	// 命令名: "connect"
	buf = append(buf, amf0String("connect")...)
	// Transaction ID: 1.0 (参考 pcap)
	buf = append(buf, amf0Number(1.0)...)
	// 命令对象: {app, tcUrl}
	props := []amf0Prop{
		{"app", amf0String(app)},
		{"tcUrl", amf0String(tcURL)},
	}
	buf = append(buf, amf0Object(props)...)
	return buf
}

// buildServerResponse builds the server's bundled response to connect():
// Window Ack Size (type 5) + Set Peer Bandwidth (type 6) + Stream Begin (type 4)
// + Set Chunk Size (type 1) + _result() (type 20).
// 参考 pcap frame 15: 所有消息顺序封装为连续 chunk.
func buildServerResponse() []byte {
	var buf []byte

	// 1. Window Ack Size (窗口确认大小, 4字节值)
	buf = append(buf, buildAMF0Chunk(CSIDProtocol, MsgTypeWindowAckSize, 0, buildWinAckSizePayload(DefaultWinAckSize))...)

	// 2. Set Peer Bandwidth (设置对端带宽, 4字节大小 + 1字节限制类型)
	bwPayload := make([]byte, 5)
	binary.BigEndian.PutUint32(bwPayload[0:4], DefaultWinAckSize)
	bwPayload[4] = 0x02 // Dynamic (动态限制)
	buf = append(buf, buildAMF0Chunk(CSIDProtocol, MsgTypeSetPeerBandwidth, 0, bwPayload)...)

	// 3. Stream Begin (流开始, User Control Message).
	// User Control 消息格式: 2字节事件类型 + 事件数据.
	// Stream Begin (event type 0) 数据为 4字节流ID, 总 payload = 6字节.
	streamBeginPayload := make([]byte, 6)
	binary.BigEndian.PutUint16(streamBeginPayload[0:2], 0x00) // Event type: Stream Begin
	binary.BigEndian.PutUint32(streamBeginPayload[2:6], 0x00) // Stream ID = 0
	buf = append(buf, buildAMF0Chunk(CSIDProtocol, MsgTypeStreamBegin, 0, streamBeginPayload)...)

	// 4. Set Chunk Size (设置 chunk 大小, 4字节值)
	chunkSizePayload := make([]byte, 4)
	binary.BigEndian.PutUint32(chunkSizePayload, DefaultChunkSize)
	buf = append(buf, buildAMF0Chunk(CSIDProtocol, MsgTypeSetChunkSize, 0, chunkSizePayload)...)

	// 5. _result() (AMF0 命令, connect 成功响应)
	buf = append(buf, buildAMF0Chunk(CSIDProtocol, MsgTypeAMF0Command, 0, buildConnectResult())...)

	return buf
}

// buildWinAckSizePayload builds the Window Ack Size payload (4字节大端值).
func buildWinAckSizePayload(size int) []byte {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, uint32(size))
	return buf
}

// buildConnectResult builds the AMF0 payload for the _result() response to connect().
// 格式: "_result"(AMF string) + 1.0(AMF number, 回显 connect 的 txnID) + null + 信息对象(AMF object).
func buildConnectResult() []byte {
	var buf []byte
	buf = append(buf, amf0String("_result")...)
	buf = append(buf, amf0Number(1.0)...) // transaction ID (回显 connect 的 1.0)
	buf = append(buf, amf0Null()...)       // properties (null, 参考 pcap)
	// 信息对象: {level, code, description}
	props := []amf0Prop{
		{"level", amf0String("status")},
		{"code", amf0String("NetConnection.Connect.Success")},
		{"description", amf0String("Connection succeeded.")},
	}
	buf = append(buf, amf0Object(props)...)
	return buf
}

// buildCreateStreamAMF0 builds the AMF0 payload for createStream().
// 格式: "createStream"(AMF string) + 2.0(AMF number, txnID) + null.
func buildCreateStreamAMF0() []byte {
	var buf []byte
	buf = append(buf, amf0String("createStream")...)
	buf = append(buf, amf0Number(2.0)...) // transaction ID = 2.0
	buf = append(buf, amf0Null()...)
	return buf
}

// buildCreateStreamResult builds the _result() for createStream.
// 格式: "_result"(AMF string) + 2.0(AMF number) + null + streamID(AMF number, 1.0).
func buildCreateStreamResult() []byte {
	var buf []byte
	buf = append(buf, amf0String("_result")...)
	buf = append(buf, amf0Number(2.0)...) // echo transaction ID
	buf = append(buf, amf0Null()...)
	buf = append(buf, amf0Number(1.0)...) // stream ID = 1.0
	return buf
}

// buildPlayAMF0 builds the AMF0 payload for play().
// 格式: "play"(AMF string) + 3.0(AMF number, txnID) + null + streamName(AMF string).
func buildPlayAMF0(streamName string) []byte {
	var buf []byte
	buf = append(buf, amf0String("play")...)
	buf = append(buf, amf0Number(3.0)...) // transaction ID = 3.0
	buf = append(buf, amf0Null()...)
	buf = append(buf, amf0String(streamName)...)
	return buf
}

// buildPublishAMF0 builds the AMF0 payload for publish().
// 格式: "publish"(AMF string) + 3.0(AMF number, txnID) + null + streamName + type("live").
func buildPublishAMF0(streamName string) []byte {
	var buf []byte
	buf = append(buf, amf0String("publish")...)
	buf = append(buf, amf0Number(3.0)...) // transaction ID = 3.0
	buf = append(buf, amf0Null()...)
	buf = append(buf, amf0String(streamName)...)
	buf = append(buf, amf0String("live")...) // 发布类型
	return buf
}

// buildSetBufferLength builds the User Control: Set Buffer Length message.
// RTMP chunk: type 0 header, msg type 4 (User Control), stream 0.
// Payload: 2字节事件类型(0x0003=SetBufferLength) + 4字节流ID + 4字节缓冲长度(毫秒).
func buildSetBufferLength(streamID uint32, bufferLenMs int) []byte {
	payload := make([]byte, 10)
	binary.BigEndian.PutUint16(payload[0:2], 0x03) // Event type: Set Buffer Length (2 bytes)
	binary.BigEndian.PutUint32(payload[2:6], streamID)
	binary.BigEndian.PutUint32(payload[6:10], uint32(bufferLenMs))
	// Set Buffer Length uses message type 4 (User Control), not AMF0 Command.
	// 复用 buildAMF0Chunk 的头部结构, 但消息类型为 User Control (4).
	// 客户端 User Control 消息使用 CSID=3 (参考 pcap).
	chunk := buildAMF0Chunk(CSIDCommand, 4, 0, payload)
	return chunk
}

// --- 辅助函数 (helper functions) ---

// groupIDMeta returns the group_id metadata for routing.
func groupIDMeta(spec core.FlowSpec) map[string]interface{} {
	if spec.GroupID != nil && spec.GroupID.Strategy != "" {
		if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
			return map[string]interface{}{"group_id": g}
		}
	}
	return nil
}

// normalizeCmd normalizes the command string.
func normalizeCmd(c string) string { return strings.ToLower(strings.TrimSpace(c)) }

// normalizeDirection normalizes a direction string to lowercase.
func normalizeDirection(d string) string { return strings.ToLower(strings.TrimSpace(d)) }

// randUint32 returns a cryptographically random uint32.
func randUint32() uint32 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return 42 // fallback
	}
	return uint32(n.Uint64())
}

// floatToUint64 converts a float64 to its IEEE 754 uint64 bit representation.
func floatToUint64(f float64) uint64 {
	return math.Float64bits(f)
}

// segmentByMSS splits payload into chunks of at most mss bytes.
func segmentByMSS(payload []byte, mss int) [][]byte {
	if mss <= 0 {
		return [][]byte{payload}
	}
	if len(payload) == 0 {
		return [][]byte{{}}
	}
	chunks := make([][]byte, 0, (len(payload)+mss-1)/mss)
	for len(payload) > 0 {
		n := len(payload)
		if n > mss {
			n = mss
		}
		chunks = append(chunks, payload[:n])
		payload = payload[n:]
	}
	return chunks
}

// synOptions builds TCP options for SYN packets (MSS + WinScale + SACK).
func synOptions(mss uint16) []core.TCPOption {
	if mss == 0 {
		mss = DefaultMSS
	}
	opts := make([]core.TCPOption, 0, 3)
	opts = append(opts, core.TCPOption{Kind: core.TCPOptMSS, Data: []byte{byte(mss >> 8), byte(mss)}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptWinScale, Data: []byte{0x07}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptSACKPermit})
	return opts
}

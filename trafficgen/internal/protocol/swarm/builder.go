// Package swarm implements the Swarm storage/discovery terminal layer (B5)：
// 本项目 Swarm wire profile——UDP discovery（SWD1 datagram）与 TCP storage
// （SWS1 frame）两种承载。builder.go 只做线格式编码（纯函数），状态机校验/
// 事件折叠在 layer_gen.go。帧布局见 docs/protocol-designs/52-swarm-design.md §3：
//
//	Discovery: Magic "SWD1"(4) | Length(2) | Version(1) | Kind(1) | Nonce(8)
//	           | NodeID(32) | EndpointCount(1) | Endpoint* | FrameEnd(2)
//	Storage:   Magic "SWS1"(4) | Length(4) | Version(1) | Kind(1) | Flags(2)
//	           | SessionID(8) | StreamID(4) | CorrelationID(8) | Payload(N)
//	           | FrameEnd(2)
//
// Discovery Length 为 Version..FrameEnd（45+endpoints）；storage Length =
// 26+N；FrameEnd 恒 ae 5a。TLV 为 FieldID(2)|FieldLength(4)|Value（4 字节
// 长度，与 AMS 的 2 字节不同）。tshark 无本协议 dissector，断言走 TCP/UDP
// 字段与帧字节。
package swarm

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// discovery kind（设计 §3.1）。
const (
	discPing = 0x01
	discPong = 0x02
	discAnnounce = 0x03
)

// storage kind（设计 §3.2 Type 表）。
const (
	kindHello       = 0x10
	kindHelloOK     = 0x11
	kindAuth        = 0x12
	kindAuthOK      = 0x13
	kindOpenSession = 0x14
	kindOpenOK      = 0x15
	kindClose       = 0x16
	kindCloseOK     = 0x17
	kindStore       = 0x20
	kindStoreOK     = 0x21
	kindRetrieve    = 0x22
	kindChunk       = 0x23
	kindManifest    = 0x24
	kindMessageAck  = 0x25
	kindPing        = 0x30
	kindPong        = 0x31
	kindError       = 0x7f
)

// flags bit 语义（设计 §3.2）。
const (
	flagRequest     = 0x0001
	flagResponse    = 0x0002
	flagAckRequired = 0x0004
	flagFragment    = 0x0008
)

// TLV FieldID（设计 §4）。
const (
	fieldProfile      = 0x0001
	fieldCapability   = 0x0002
	fieldNodeID       = 0x0003
	fieldNonce        = 0x0004
	fieldSessionLimit = 0x0010
	fieldMaxFrame     = 0x0011
	fieldHeartbeat    = 0x0012
	fieldChunkAddress = 0x0020
	fieldChunkSize    = 0x0021
	fieldChunkOffset  = 0x0022
	fieldChunkPayload = 0x0023
	fieldManifestRoot = 0x0030
	fieldManifestEntry = 0x0031
	fieldMessageID    = 0x0040
	fieldSequence     = 0x0041
	fieldAckFor       = 0x0042
	fieldAckStatus    = 0x0043
	fieldFragmentIndex = 0x0044
	fieldFragmentCount = 0x0045
	fieldErrorCode    = 0x00f0
	fieldErrorText    = 0x00f1
)

// 线格式常量。
const (
	frameVersion = 0x01
	frameEndHi   = 0xae
	frameEndLo   = 0x5a
	// discHeaderBytes = Version(1)+Kind(1)+Nonce(8)+NodeID(32)
	// +EndpointCount(1)+FrameEnd(2) = 45；discovery Length = 45 + 8×endpoints。
	discHeaderBytes = 45
	// storHeaderBytes = Version(1)+Kind(1)+Flags(2)+SessionID(8)+StreamID(4)
	// +CorrelationID(8)+FrameEnd(2) = 26；storage Length = 26 + N。
	storHeaderBytes = 26

	magicSWD1 = "SWD1"
	magicSWS1 = "SWS1"

	defaultProfile       = "swarm_storage_v1"
	defaultDiscProfile   = "swarm_discovery_v1"
	defaultSessionLimit  = 8
	defaultMaxFrame      = 4096
	defaultFrameMax      = 4096
	defaultDstPort       = 1634
	defaultCapability    = "chunks,manifest"
	defaultChunkAddr     = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	defaultNodeID        = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
	defaultManifestRoot  = "f000f000f000f000f000f000f000f000f000f000f000f000f000f000f000f000"
)

// tlv is one encoded payload field。
type tlv struct {
	id    uint16
	value []byte
}

// tlvsBytes serialises [FieldID(2)|FieldLength(4)|Value] fields。
func tlvsBytes(fields []tlv) []byte {
	var out []byte
	for _, t := range fields {
		out = binary.BigEndian.AppendUint16(out, t.id)
		out = binary.BigEndian.AppendUint32(out, uint32(len(t.value)))
		out = append(out, t.value...)
	}
	return out
}

func u16tlv(id uint16, v uint16) tlv {
	return tlv{id: id, value: binary.BigEndian.AppendUint16(nil, v)}
}
func u32tlv(id uint16, v uint32) tlv {
	return tlv{id: id, value: binary.BigEndian.AppendUint32(nil, v)}
}
func u64tlv(id uint16, v uint64) tlv {
	return tlv{id: id, value: binary.BigEndian.AppendUint64(nil, v)}
}
func strtlv(id uint16, s string) tlv {
	return tlv{id: id, value: []byte(s)}
}
func rawtlv(id uint16, v []byte) tlv {
	return tlv{id: id, value: v}
}

// resolveNodeID decodes the 32-byte node identity from hex（validator 保证
// 合法，此处失败返回 nil 由上层兜底）。
func resolveNodeID(cfg *core.SwarmConfig) []byte {
	id := cfg.NodeIDHex
	if id == "" {
		id = defaultNodeID
	}
	b, err := hex.DecodeString(id)
	if err != nil || len(b) != 32 {
		return nil
	}
	return b
}

// resolveChunkAddress decodes a chunk/manifest 32-byte address from hex；
// 空串用 fixture 默认（validator 对非空值校验长度）。
func resolveChunkAddress(s string) ([]byte, error) {
	if s == "" {
		s = defaultChunkAddr
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, fmt.Errorf("swarm: chunk address %q is not valid hex (chunk/address)", s)
	}
	if len(b) != 32 {
		return nil, fmt.Errorf("swarm: chunk address must be 32 bytes, got %d (chunk/address)", len(b))
	}
	return b, nil
}

// encodeEndpoint is AddressFamily(1)|Port(2)|Address(4 或 16)。
func encodeEndpoint(e core.SwarmEndpoint) ([]byte, error) {
	ip := []byte(e.Address)
	var out []byte
	switch e.AddressFamily {
	case 1:
		if len(ip) != 4 {
			return nil, fmt.Errorf("swarm: IPv4 endpoint %q must be 4 address bytes (endpoint)", e.Address)
		}
		out = append(out, 1)
	case 2:
		if len(ip) != 16 {
			return nil, fmt.Errorf("swarm: IPv6 endpoint %q must be 16 address bytes (endpoint)", e.Address)
		}
		out = append(out, 2)
	default:
		return nil, fmt.Errorf("swarm: endpoint address_family %d is invalid (want 1=IPv4 or 2=IPv6) (endpoint)", e.AddressFamily)
	}
	out = binary.BigEndian.AppendUint16(out, e.Port)
	return append(out, ip...), nil
}

// BuildDiscoveryFrame encodes one SWD1 datagram。kind 0x01/0x02/0x03。
func BuildDiscoveryFrame(kind byte, nonce uint64, nodeID []byte, endpoints []core.SwarmEndpoint) ([]byte, error) {
	if len(nodeID) != 32 {
		return nil, fmt.Errorf("swarm: node_id must be 32 bytes, got %d (node)", len(nodeID))
	}
	var eps []byte
	for i := range endpoints {
		b, err := encodeEndpoint(endpoints[i])
		if err != nil {
			return nil, err
		}
		eps = append(eps, b...)
	}
	length := discHeaderBytes + len(eps)
	out := []byte(magicSWD1)
	out = binary.BigEndian.AppendUint16(out, uint16(length))
	out = append(out, frameVersion, kind)
	out = binary.BigEndian.AppendUint64(out, nonce)
	out = append(out, nodeID...)
	out = append(out, byte(len(endpoints)))
	out = append(out, eps...)
	return append(out, frameEndHi, frameEndLo), nil
}

// BuildStorageFrame encodes one SWS1 frame。
func BuildStorageFrame(kind byte, flags uint16, sessionID uint64, streamID uint32, correlationID uint64, fields []tlv) []byte {
	payload := tlvsBytes(fields)
	out := []byte(magicSWS1)
	out = binary.BigEndian.AppendUint32(out, uint32(storHeaderBytes+len(payload)))
	out = append(out, frameVersion, kind)
	out = binary.BigEndian.AppendUint16(out, flags)
	out = binary.BigEndian.AppendUint64(out, sessionID)
	out = binary.BigEndian.AppendUint32(out, streamID)
	out = binary.BigEndian.AppendUint64(out, correlationID)
	out = append(out, payload...)
	return append(out, frameEndHi, frameEndLo)
}

// eventDefaults resolves the storage kind-derived (typeByte, flags,
// direction)。方向缺省：_ok/pong/chunk/store_ok/message_ack/error→s2c。
func eventDefaults(e *core.SwarmEvent) (byte, uint16, string, bool) {
	switch e.Kind {
	case "hello":
		return kindHello, flagRequest, "c2s", true
	case "hello_ok":
		return kindHelloOK, flagResponse, "s2c", true
	case "auth":
		return kindAuth, flagRequest, "c2s", true
	case "auth_ok":
		return kindAuthOK, flagResponse, "s2c", true
	case "open_session":
		return kindOpenSession, flagRequest, "c2s", true
	case "open_ok":
		return kindOpenOK, flagResponse, "s2c", true
	case "close":
		return kindClose, flagRequest, "c2s", true
	case "close_ok":
		return kindCloseOK, flagResponse, "s2c", true
	case "store":
		return kindStore, flagRequest, "c2s", true
	case "store_ok":
		return kindStoreOK, flagResponse, "s2c", true
	case "retrieve":
		return kindRetrieve, flagRequest, "c2s", true
	case "chunk":
		return kindChunk, flagResponse, "s2c", true
	case "manifest":
		return kindManifest, flagRequest, "c2s", true
	case "message_ack":
		return kindMessageAck, flagResponse, "s2c", true
	case "ping":
		return kindPing, flagRequest, "c2s", true
	case "pong":
		return kindPong, flagResponse, "s2c", true
	case "error":
		return kindError, flagResponse, "c2s", true
	}
	return 0, 0, "", false
}

// discoveryKind maps the discovery kind strings。
func discoveryKind(kind string) (byte, bool) {
	switch kind {
	case "ping":
		return discPing, true
	case "pong":
		return discPong, true
	case "announce":
		return discAnnounce, true
	}
	return 0, false
}

// IsStorageKind reports whether the event belongs to the TCP storage plane。
func IsStorageKind(kind string) bool {
	_, _, _, ok := eventDefaults(&core.SwarmEvent{Kind: kind})
	return ok
}

// eventFlags resolves the wire flags: kind default + ack-required/
// fragment bits；显式 Flags 整体覆盖。
func eventFlags(e *core.SwarmEvent, def uint16) uint16 {
	if e.Flags != 0 {
		return uint16(e.Flags)
	}
	if e.Kind == "store" || e.Kind == "chunk" {
		if e.DeliveryMode == 1 {
			def |= flagAckRequired
		}
	}
	if e.Kind == "chunk" && e.FragmentCount > 0 {
		def |= flagFragment
	}
	return def
}

// storageEventFrame encodes one storage event into its SWS1 frame。
func storageEventFrame(e *core.SwarmEvent, cfg *core.SwarmConfig, sessionID uint64, streamID uint32) ([]byte, error) {
	typeByte, flags, _, ok := eventDefaults(e)
	if !ok {
		return nil, fmt.Errorf("swarm: unknown frame type %q (frame/type)", e.Kind)
	}
	if e.Type != 0 {
		typeByte = byte(e.Type)
	}
	flags = eventFlags(e, flags)
	profile := cfg.Profile
	if profile == "" {
		profile = defaultProfile
	}
	nodeID := resolveNodeID(cfg)
	if nodeID == nil {
		return nil, fmt.Errorf("swarm: node_id_hex must decode to 32 bytes (node)")
	}
	sessionLimit := cfg.SessionLimit
	if sessionLimit == 0 {
		sessionLimit = defaultSessionLimit
	}
	maxFrame := cfg.MaxFrame
	if maxFrame == 0 {
		maxFrame = defaultMaxFrame
	}
	capability := cfg.Capability
	if capability == "" {
		capability = defaultCapability
	}

	var fields []tlv
	switch e.Kind {
	case "hello":
		fields = []tlv{strtlv(fieldProfile, profile), strtlv(fieldCapability, capability), rawtlv(fieldNodeID, nodeID), u64tlv(fieldNonce, e.Nonce)}
	case "hello_ok":
		fields = []tlv{strtlv(fieldProfile, profile), u32tlv(fieldMaxFrame, maxFrame), u16tlv(fieldSessionLimit, sessionLimit), u16tlv(fieldHeartbeat, cfg.Heartbeat)}
	case "auth":
		fields = []tlv{rawtlv(fieldNodeID, nodeID)}
	case "auth_ok", "open_session", "close", "close_ok", "ping", "pong", "store_ok":
		// 空 payload：storage Length=26 最小帧（设计 §7 边界）。
	case "open_ok":
		fields = []tlv{u16tlv(fieldSessionLimit, sessionLimit), u32tlv(fieldMaxFrame, maxFrame)}
	case "store":
		addr, err := resolveChunkAddress(e.ChunkAddress)
		if err != nil {
			return nil, err
		}
		size := e.ChunkSize
		if size == 0 {
			size = uint32(len(e.Payload))
		}
		if uint64(len(e.Payload)) != uint64(size) {
			return nil, fmt.Errorf("swarm: store chunk_payload length %d does not equal chunk_size %d (chunk/length)", len(e.Payload), size)
		}
		fields = []tlv{rawtlv(fieldChunkAddress, addr), u32tlv(fieldChunkSize, size), rawtlv(fieldChunkPayload, e.Payload)}
	case "retrieve":
		addr, err := resolveChunkAddress(e.ChunkAddress)
		if err != nil {
			return nil, err
		}
		fields = []tlv{rawtlv(fieldChunkAddress, addr)}
	case "chunk":
		addr, err := resolveChunkAddress(e.ChunkAddress)
		if err != nil {
			return nil, err
		}
		fields = []tlv{rawtlv(fieldChunkAddress, addr)}
		if e.FragmentCount > 0 {
			fields = append(fields, u16tlv(fieldFragmentIndex, uint16(e.FragmentIndex)), u16tlv(fieldFragmentCount, uint16(e.FragmentCount)))
		}
		if e.ChunkOffset > 0 {
			fields = append(fields, u32tlv(fieldChunkOffset, e.ChunkOffset))
		}
		if len(e.Payload) > 0 {
			fields = append(fields, u64tlv(fieldSequence, e.Sequence), rawtlv(fieldChunkPayload, e.Payload))
		}
	case "manifest":
		root := e.ManifestRoot
		if root == "" {
			root = defaultManifestRoot
		}
		rootBytes, err := resolveChunkAddress(root)
		if err != nil {
			return nil, err
		}
		fields = []tlv{rawtlv(fieldManifestRoot, rootBytes)}
		if len(e.ManifestEntry) > 0 {
			fields = append(fields, rawtlv(fieldManifestEntry, e.ManifestEntry))
		}
		if len(e.Payload) > 0 {
			fields = append(fields, rawtlv(fieldManifestEntry, e.Payload))
		}
	case "message_ack":
		fields = []tlv{u64tlv(fieldAckFor, e.AckFor), u16tlv(fieldAckStatus, uint16(e.AckStatus))}
	case "error":
		fields = []tlv{u16tlv(fieldErrorCode, uint16(e.ErrorCode)), strtlv(fieldErrorText, e.ErrorText)}
	}
	return BuildStorageFrame(typeByte, flags, sessionID, streamID, e.CorrelationID, fields), nil
}

// BuildDiscoveryEvent encodes one discovery-plane event（UDP plane 专用
// ——ping/pong 双平面歧义由调用方按配置平面路由，见 Generate 的载体检查）。
func BuildDiscoveryEvent(e *core.SwarmEvent, cfg *core.SwarmConfig) ([]byte, error) {
	k, ok := discoveryKind(e.Kind)
	if !ok {
		return nil, fmt.Errorf("swarm: kind %q is not a discovery frame (frame/transport)", e.Kind)
	}
	nodeID := resolveNodeID(cfg)
	if nodeID == nil {
		return nil, fmt.Errorf("swarm: node_id_hex must decode to 32 bytes (node)")
	}
	return BuildDiscoveryFrame(k, e.Nonce, nodeID, e.Endpoints)
}

// BuildEventFrame encodes one storage-plane event into its SWS1 frame。
func BuildEventFrame(e *core.SwarmEvent, cfg *core.SwarmConfig, sessionID uint64, streamID uint32) ([]byte, error) {
	return storageEventFrame(e, cfg, sessionID, streamID)
}

// CheckFrameMax guards the storage frame size against frame_max。
func CheckFrameMax(frame []byte, frameMax uint32) error {
	limit := frameMax
	if limit == 0 {
		limit = defaultFrameMax
	}
	if uint64(len(frame)) > uint64(limit) {
		return fmt.Errorf("swarm: frame length %d exceeds frame_max %d (length)", len(frame), limit)
	}
	return nil
}

package jt809

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/trafficgen/trafficgen/internal/protocol/jtcommon"
)

// buildFrame assembles one complete JT809 wire frame（D-JT809-1 裁定1+P4 勘误）:
//
//	5B + Escape809( 消息头 + 消息体 + CRC16(2) ) + 5D
//
// 消息头 22B（2011/2013）/ 30B（2019，尾增 Time 8B UTC 秒）；CRC 先对未转义
// 头+体 计算（init 0xFFFF poly 0x1021），再对标识间整体单遍转义（CRC 字节
// 参与转义——库 WriteEncode 实录）；MsgLength=整帧总长 5B+头+体+CRC+5D
// （勘误1：金向量 0x48=72 实证，非"头+体"字面读法）。
func buildFrame(cfg *JT809Config, sn uint32, msgID uint16, body []byte) ([]byte, error) {
	ver, err := versionBytes(cfg)
	if err != nil {
		return nil, err
	}
	return buildFrameVer(cfg, ver, sn, msgID, body)
}

// buildFrameVer is buildFrame with pre-resolved version bytes（编排路径
// 一次解析复用；解析失败在 ValidateConfig/versionBytes 前置拦截）.
func buildFrameVer(cfg *JT809Config, ver []byte, sn uint32, msgID uint16, body []byte) ([]byte, error) {
	headerLen := HeaderLenLegacy
	if cfg.VersionFlag == 2 {
		headerLen = HeaderLen2019
	}
	content := make([]byte, 0, headerLen+len(body))
	content = appendUint32(content, 0) // MsgLength 占位，CRC 前回填
	content = appendUint32(content, sn)
	content = appendUint16(content, msgID)
	content = appendUint32(content, cfg.GNSSCenterId)
	content = append(content, ver...)
	content = append(content, cfg.EncryptFlag)
	content = appendUint32(content, cfg.EncryptKey)
	if cfg.VersionFlag == 2 {
		ts := cfg.TimeSec
		if ts == 0 {
			ts = uint64(time.Now().Unix())
		}
		content = appendUint64(content, ts)
	}
	content = append(content, body...)

	msgLength := 1 + len(content) + CRCLen + 1 // 整帧总长（勘误1）
	binary.BigEndian.PutUint32(content[0:4], uint32(msgLength))

	crc := jtcommon.CRC809(content)
	content = appendUint16(content, crc)

	frame := make([]byte, 0, msgLength)
	frame = append(frame, FlagBegin)
	frame = append(frame, jtcommon.Escape809(content)...)
	frame = append(frame, FlagEnd)
	return frame, nil
}

// versionBytes resolves the 3-byte version literal: cfg.VersionBytes
// (6 hex chars) or DefaultVersionHex "010000"（金向量库缺省）。
func versionBytes(cfg *JT809Config) ([]byte, error) {
	hx := cfg.VersionBytes
	if hx == "" {
		hx = DefaultVersionHex
	}
	if len(hx) != 6 {
		return nil, fmt.Errorf("jt809: version_bytes %q must be 6 hex chars (3 bytes)", hx)
	}
	b, err := hex.DecodeString(hx)
	if err != nil {
		return nil, fmt.Errorf("jt809: version_bytes %q not hex: %w", hx, err)
	}
	return b, nil
}

// --- 16 型消息体（裁定3）---

// buildLoginBody 0x1001 主链路登录请求：
// UserId(4)+Password(pad8)+[2019: GNSSCenterId(4)]+DownLinkIP(pad32)+Port(2)
// = 46B（2011/2013）/ 50B（2019，勘误4 双形实证）。
func buildLoginBody(cfg *JT809Config, pr *JT809Procedure) []byte {
	b := make([]byte, 0, 50)
	b = appendUint32(b, cfg.UserId)
	b = append(b, padRight([]byte(cfg.Password), PasswordLen)...)
	if cfg.VersionFlag == 2 {
		b = appendUint32(b, cfg.GNSSCenterId)
	}
	ip := cfg.DownLinkIP
	port := cfg.DownLinkPort
	if pr != nil {
		if pr.DownLinkIP != "" {
			ip = pr.DownLinkIP
		}
		if pr.DownLinkPort != 0 {
			port = pr.DownLinkPort
		}
	}
	b = append(b, padRight([]byte(ip), DownLinkIPLen)...)
	b = appendUint16(b, port)
	return b
}

// buildLoginRespBody 0x1002 主链路登录应答：Result(1)+VerifyCode(4)。
func buildLoginRespBody(result uint8, verifyCode uint32) []byte {
	b := make([]byte, 0, 5)
	b = append(b, result)
	return appendUint32(b, verifyCode)
}

// buildVerifyCodeBody 0x9001 从链路登录请求：VerifyCode(4)。
func buildVerifyCodeBody(verifyCode uint32) []byte {
	return appendUint32(make([]byte, 0, 4), verifyCode)
}

// buildLogoutBody 0x1003/0x9003 注销请求：UserId(4)+Password(pad8)。
func buildLogoutBody(userId uint32, password string) []byte {
	b := make([]byte, 0, 12)
	b = appendUint32(b, userId)
	return append(b, padRight([]byte(password), PasswordLen)...)
}

// buildCodeBody 0x1007/0x9007 ErrorCode(1) / 0x1008/0x9008 ReasonCode(1)。
func buildCodeBody(code uint8) []byte {
	return []byte{code}
}

// padRight zero-pads right (truncates) to n bytes — lib WriteStringPadRight
// 0x00 填充实录（金向量 DownLinkIP "127.0.0.1"+23×00 实证）。
func padRight(b []byte, n int) []byte {
	if len(b) >= n {
		return b[:n]
	}
	out := make([]byte, n)
	copy(out, b)
	return out
}

func appendUint16(b []byte, v uint16) []byte { return append(b, byte(v>>8), byte(v)) }
func appendUint32(b []byte, v uint32) []byte {
	return append(b, byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}
func appendUint64(b []byte, v uint64) []byte {
	return append(b, byte(v>>56), byte(v>>48), byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16), byte(v>>8), byte(v))
}

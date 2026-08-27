package http_flv

import (
	"encoding/binary"
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ---- FLV wire encoding (Adobe Video File Format Specification) ----

const (
	flvSignature  = "FLV"
	flvVersion    = 1
	flvDataOffset = 9
	flvTagHeader  = 11 // TagType(1) + DataSize(3) + Timestamp(4) + StreamID(3)
	flvPrevSize   = 4

	tagScript = 18 // 0x12
	tagAudio  = 8  // 0x08
	tagVideo  = 9  // 0x09

	amf0StringMarker    = 0x02
	amf0ObjectMarker    = 0x03
	amf0ECMAArrayMarker = 0x08
	amf0NumericMarker   = 0x00
	amf0BooleanMarker   = 0x01
	amf0ObjectEnd       = 0x09
	amf0NullMarker      = 0x05

	audioAAC = 10 // SoundFormat: AAC

	videoAVC = 7 // CodecID: AVC / H.264
)

// flvFlags 从配置解析音频/视频标志（audio bit2=0x04、video bit0=0x01）。
// 两标志同置时 FLV 标准以 0x05 字节表示（bit2|bit0）。
func flvFlags(c *core.HTTPFLVConfig) uint8 {
	if c != nil && c.Flags != 0 {
		return c.Flags
	}
	return 0x05 // 默认同时声明音频+视频
}

// buildFLVHeader 产出 9-byte FLV header：Signature+Version+Flags+DataOffset。
func buildFLVHeader(flags uint8) []byte {
	b := make([]byte, 9)
	copy(b[0:3], flvSignature)
	b[3] = flvVersion
	b[4] = flags
	binary.BigEndian.PutUint32(b[5:9], flvDataOffset)
	return b
}

// buildFLVTag 产出一个完整 tag（含 11-byte tag header 和 4-byte
// PreviousTagSize）。timestamp 是 32-bit 毫秒值（TimestampExtended<<24 |
// TimestampLower）。dataSizeOverride 与 previousSizeOverride 仅负例注入。
func buildFLVTag(tagType byte, data []byte, timestamp uint32, dataSizeOverride, previousSizeOverride *uint32) []byte {
	size := uint32(len(data))
	if dataSizeOverride != nil {
		size = *dataSizeOverride
	}
	prev := uint32(flvTagHeader + len(data))
	if previousSizeOverride != nil {
		prev = *previousSizeOverride
	}
	b := make([]byte, flvTagHeader+len(data)+flvPrevSize)
	b[0] = tagType
	b[1] = byte(size >> 16)
	b[2] = byte(size >> 8)
	b[3] = byte(size)
	ts := timestamp & 0x00ffffff
	b[4] = byte(ts >> 16)
	b[5] = byte(ts >> 8)
	b[6] = byte(ts)
	b[7] = byte(timestamp >> 24) // TimestampExtended
	copy(b[8:11], []byte{0, 0, 0}) // StreamID 恒 0
	copy(b[11:11+len(data)], data)
	binary.BigEndian.PutUint32(b[11+len(data):], prev)
	return b
}

// ---- AMF0 encoding（script tag 元数据；长度均为 big-endian）----

// buildAMF0String 产出 AMF0 string：marker 0x02 + UI16 length + bytes。
func buildAMF0String(s string) []byte {
	b := make([]byte, 1+2+len(s))
	b[0] = amf0StringMarker
	binary.BigEndian.PutUint16(b[1:3], uint16(len(s)))
	copy(b[3:], s)
	return b
}

// buildAMF0ECMAArray 产出 AMF0 ECMA array：marker 0x08 + UI32 count +
// 按序 (UI16 key_len + key + value) + 00 00 09 结束。值支持 string、数值、
// bool、nil。
func buildAMF0ECMAArray(pairs [][2]interface{}) []byte {
	b := []byte{amf0ECMAArrayMarker}
	b = append(b, 0, 0, 0, 0) // count 占位
	count := 0
	for _, p := range pairs {
		key, ok := p[0].(string)
		if !ok {
			continue
		}
		val := p[1]
		switch v := val.(type) {
		case string:
			b = append(b, buildAMF0KeyValue(key, buildAMF0String(v))...)
			count++
		case float64, int, uint8, uint32, int64:
			b = append(b, buildAMF0KeyValue(key, buildAMF0Number(toFloat64(v)))...)
			count++
		case bool:
			b = append(b, buildAMF0KeyValue(key, buildAMF0Bool(v))...)
			count++
		case nil:
			b = append(b, buildAMF0KeyValue(key, []byte{amf0NullMarker})...)
			count++
		case []byte:
			b = append(b, buildAMF0KeyValue(key, buildAMF0String(string(v)))...)
			count++
		}
	}
	binary.BigEndian.PutUint32(b[1:5], uint32(count))
	b = append(b, 0, 0, amf0ObjectEnd)
	return b
}

func buildAMF0KeyValue(key string, value []byte) []byte {
	b := make([]byte, 2+len(key))
	binary.BigEndian.PutUint16(b[0:2], uint16(len(key)))
	copy(b[2:], key)
	return append(b, value...)
}

func buildAMF0Number(f float64) []byte {
	b := []byte{amf0NumericMarker}
	b = append(b, 0, 0, 0, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint64(b[1:9], uint64(f))
	return b
}

func buildAMF0Bool(v bool) []byte {
	if v {
		return []byte{amf0BooleanMarker, 1}
	}
	return []byte{amf0BooleanMarker, 0}
}

func toFloat64(v interface{}) float64 {
	switch n := v.(type) {
	case float64:
		return n
	case int:
		return float64(n)
	case uint8:
		return float64(n)
	case uint32:
		return float64(n)
	case int64:
		return float64(n)
	}
	return 0
}

// ---- AAC / AVC payload 编码 ----

// buildAudioAACData 产出音频 tag data：首字节 SoundFormat=10(AAC)+SoundRate+
// SoundSize+SoundType，随后 AACPacketType（0=sequence header，1=raw）与
// 配置字节。示例首字节 0xa0：SoundFormat=10、SoundRate=3（44kHz）、
// SoundSize=1（16-bit）、SoundType=0（mono）。
func buildAudioAACData(aacPacketType byte, audioConfig []byte, flagsByte byte) []byte {
	first := byte(audioAAC<<4) | flagsByte
	if first == 0xa0 {
		first = 0xa0
	} else if first == 0xa8 {
		first = 0xa8
	} else if first == 0xa4 {
		first = 0xa4
	} else if first == 0xac {
		first = 0xac
	} else if first == 0xa1 {
		first = 0xa1
	}
	data := []byte{first, aacPacketType}
	return append(data, audioConfig...)
}

// buildVideoAVCData 产出视频 tag data：首字节 FrameType(4bits)+CodecID(4bits)=
// 0x17（keyframe+AVC），随后 AVCPacketType（0=sequence header，1=NALU，
// 2=end of sequence）与 signed 24-bit CompositionTime，最后配置字节。
func buildVideoAVCData(avcPacketType byte, compositionTime int32, videoConfig []byte) []byte {
	data := []byte{0x17, avcPacketType}
	ct := uint32(compositionTime) & 0x00ffffff
	data = append(data, byte(ct>>16), byte(ct>>8), byte(ct))
	return append(data, videoConfig...)
}

// ---- FLV body assembly ----

// buildFLVBody 把配置的 tag 序列装配成 FLV body（header + PreviousTagSize0
// + 逐 tag）。wireFault 注入负例字节破坏。
func buildFLVBody(c *core.HTTPFLVConfig) ([]byte, error) {
	body := buildFLVHeader(flvFlags(c))
	body = append(body, 0, 0, 0, 0) // PreviousTagSize0 = 0
	for _, t := range c.Tags {
		tagType, data, err := resolveTag(t)
		if err != nil {
			return nil, err
		}
		body = append(body, buildFLVTag(tagType, data, t.Timestamp, t.DataSizeOverride, t.PreviousSizeOverride)...)
	}
	if c.WireFault == "truncated" {
		if len(body) <= 16 {
			return nil, fmt.Errorf("http_flv: truncated tag: FLV body too short (%d bytes) to truncate", len(body))
		}
		body = body[:len(body)-5]
	}
	return body, nil
}

// resolveTag 把配置 tag 映射为线上类型与 data 字节。
func resolveTag(t core.FLVTag) (byte, []byte, error) {
	switch t.Type {
	case "script":
		if len(t.Data) > 0 {
			return tagScript, t.Data, nil
		}
		meta := [][2]interface{}{
			{"onMetaData", buildAMF0ECMAArray([][2]interface{}{
				{"width", float64(1280)},
				{"height", float64(720)},
				{"framerate", float64(25)},
				{"videocodecid", float64(7)},
				{"audiocodecid", float64(10)},
				{"duration", float64(0)},
			})},
		}
		if len(meta) == 0 {
			return tagScript, nil, fmt.Errorf("http_flv: script tag: empty data")
		}
		b := []byte{amf0StringMarker}
		name := "onMetaData"
		b = append(b, byte(len(name)>>8), byte(len(name)))
		b = append(b, name...)
		b = append(b, meta[0][1].([]byte)...)
		return tagScript, b, nil
	case "audio":
		first := byte(audioAAC<<4) | 0x05 // SoundRate=3(44kHz) + 16-bit + stereo
		data := []byte{first, 0x00}       // AACPacketType=0 sequence header
		return tagAudio, append(data, t.Data...), nil
	case "video":
		data := []byte{0x17, 0x00, 0x00, 0x00, 0x00} // keyframe+AVC, seq header, CT=0
		return tagVideo, append(data, t.Data...), nil
	default:
		return 0, nil, fmt.Errorf("http_flv: unknown tag type %q", t.Type)
	}
}
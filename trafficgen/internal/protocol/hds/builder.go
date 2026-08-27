package hds

import (
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ---- F4M manifest builder (XML) ----

// buildF4MManifest builds an F4M XML manifest from config.
func buildF4MManifest(m *core.HDSManifest, profile string) (string, error) {
	if m == nil {
		return "", fmt.Errorf("hds: manifest config is nil")
	}
	if m.ID == "" {
		return "", fmt.Errorf("hds: manifest id is required")
	}
	if m.StreamType == "" {
		return "", fmt.Errorf("hds: manifest stream_type is required")
	}
	if len(m.Media) == 0 {
		return "", fmt.Errorf("hds: manifest must have at least one media entry")
	}

	var sb strings.Builder
	sb.WriteString("<?xml version=\"1.0\" encoding=\"utf-8\"?>\n")
	sb.WriteString("<manifest xmlns=\"http://ns.adobe.com/f4m/1.0\">\n")
	sb.WriteString(fmt.Sprintf("  <id>%s</id>\n", xmlEscape(m.ID)))
	sb.WriteString(fmt.Sprintf("  <streamType>%s</streamType>\n", xmlEscape(m.StreamType)))

	for _, media := range m.Media {
		attrs := fmt.Sprintf(" bitrate=\"%d\"", media.Bitrate)
		if media.Href != "" {
			attrs += fmt.Sprintf(" href=\"%s\"", xmlEscape(media.Href))
		}
		if media.URL != "" {
			attrs += fmt.Sprintf(" url=\"%s\"", xmlEscape(media.URL))
		}
		if media.StreamID != "" {
			attrs += fmt.Sprintf(" streamId=\"%s\"", xmlEscape(media.StreamID))
		}
		if media.BootstrapInfoID != "" {
			attrs += fmt.Sprintf(" bootstrapInfoId=\"%s\"", xmlEscape(media.BootstrapInfoID))
		}
		sb.WriteString(fmt.Sprintf("  <media%s/>\n", attrs))
	}

	for _, bi := range m.BootstrapInfos {
		attrs := fmt.Sprintf(" id=\"%s\"", xmlEscape(bi.ID))
		if bi.Profile != "" {
			attrs += fmt.Sprintf(" profile=\"%s\"", xmlEscape(bi.Profile))
		}
		body := bi.Base64
		sb.WriteString(fmt.Sprintf("  <bootstrapInfo%s>%s</bootstrapInfo>\n", attrs, body))
	}

	sb.WriteString("</manifest>\n")
	return sb.String(), nil
}

// xmlEscape escapes special XML characters.
func xmlEscape(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	s = strings.ReplaceAll(s, "\"", "&quot;")
	s = strings.ReplaceAll(s, "'", "&apos;")
	return s
}

// ---- Bootstrap box builder (abst, asrt, afrt) ----

// buildBootstrapBox builds the full bootstrap box set (abst + asrt + afrt).
func buildBootstrapBox(media *core.HDSMedia, profile string) ([]byte, error) {
	if media == nil {
		return nil, fmt.Errorf("hds: media config is nil for bootstrap")
	}
	asrtBytes := buildASRTBox(media)
	afrtBytes := buildAFRTBox(media)
	abstBytes := buildABSTBox(media, asrtBytes, afrtBytes, profile)
	return abstBytes, nil
}

// buildABSTBox builds the abst (Adobe bootstrap) box.
func buildABSTBox(media *core.HDSMedia, asrtBytes, afrtBytes []byte, profile string) []byte {
	version := uint8(0)
	flags := []byte{0x00, 0x00, 0x00}
	bootstrapVersion := uint32(1)
	profileByte := uint8(0)
	live := uint8(0)
	update := uint8(0)
	timescale := uint32(1000)
	currentMediaTime := uint64(0)
	smpteTimeCodeOffset := int64(0)
	movieIdentifier := ""
	serverEntryCount := uint8(0)
	qualityEntryCount := uint8(0)
	drmData := ""
	metadata := ""

	payload := []byte{}
	payload = append(payload, version)
	payload = append(payload, flags...)
	payload = append(payload, uint32Bytes(bootstrapVersion)...)
	payload = append(payload, profileByte)
	payload = append(payload, live)
	payload = append(payload, update)
	payload = append(payload, uint32Bytes(timescale)...)
	payload = append(payload, uint64Bytes(currentMediaTime)...)
	payload = append(payload, int64Bytes(smpteTimeCodeOffset)...)
	payload = append(payload, lengthPrefixedString(movieIdentifier)...)
	payload = append(payload, serverEntryCount)
	payload = append(payload, qualityEntryCount)
	payload = append(payload, lengthPrefixedString(drmData)...)
	payload = append(payload, lengthPrefixedString(metadata)...)
	payload = append(payload, uint8(1)) // segment run table count
	payload = append(payload, asrtBytes...)
	payload = append(payload, uint8(1)) // fragment run table count
	payload = append(payload, afrtBytes...)

	size := uint32(8 + len(payload))
	box := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(box[0:4], size)
	copy(box[4:8], "abst")
	copy(box[8:], payload)
	return box
}

// buildASRTBox builds the asrt (Adobe segment run table) box.
func buildASRTBox(media *core.HDSMedia) []byte {
	version := uint8(0)
	flags := []byte{0x00, 0x00, 0x00}
	qualityEntryCount := uint8(0)

	payload := []byte{}
	payload = append(payload, version)
	payload = append(payload, flags...)
	payload = append(payload, qualityEntryCount)

	segMap := make(map[uint32]int)
	for _, f := range media.Fragments {
		segMap[f.Segment]++
	}
	segCount := uint32(len(segMap))
	payload = append(payload, uint32Bytes(segCount)...)

	segs := make([]uint32, 0, len(segMap))
	for s := range segMap {
		segs = append(segs, s)
	}
	for i := 0; i < len(segs); i++ {
		for j := i + 1; j < len(segs); j++ {
			if segs[i] > segs[j] {
				segs[i], segs[j] = segs[j], segs[i]
			}
		}
	}
	for _, seg := range segs {
		payload = append(payload, uint32Bytes(seg)...)
		payload = append(payload, uint32Bytes(uint32(segMap[seg]))...)
	}

	size := uint32(8 + len(payload))
	box := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(box[0:4], size)
	copy(box[4:8], "asrt")
	copy(box[8:], payload)
	return box
}

// buildAFRTBox builds the afrt (Adobe fragment run table) box.
func buildAFRTBox(media *core.HDSMedia) []byte {
	version := uint8(0)
	flags := []byte{0x00, 0x00, 0x00}
	timescale := uint32(1000)
	qualityEntryCount := uint8(0)

	payload := []byte{}
	payload = append(payload, version)
	payload = append(payload, flags...)
	payload = append(payload, uint32Bytes(timescale)...)
	payload = append(payload, qualityEntryCount)

	fragCount := uint32(len(media.Fragments))
	payload = append(payload, uint32Bytes(fragCount)...)

	for _, f := range media.Fragments {
		payload = append(payload, uint32Bytes(f.Fragment)...)
		payload = append(payload, uint64Bytes(f.Timestamp)...)
		payload = append(payload, uint32Bytes(f.Duration)...)
	}

	size := uint32(8 + len(payload))
	box := make([]byte, 8+len(payload))
	binary.BigEndian.PutUint32(box[0:4], size)
	copy(box[4:8], "afrt")
	copy(box[8:], payload)
	return box
}

// ---- F4F fragment builder ----

// buildF4FFragment builds an F4F fragment box containing an mdat payload.
func buildF4FFragment(body []byte) []byte {
	mdatSize := uint32(8 + len(body))
	mdat := make([]byte, 8+len(body))
	binary.BigEndian.PutUint32(mdat[0:4], mdatSize)
	copy(mdat[4:8], "mdat")
	copy(mdat[8:], body)
	return mdat
}

// ---- byte helpers ----

func uint32Bytes(v uint32) []byte {
	b := make([]byte, 4)
	binary.BigEndian.PutUint32(b, v)
	return b
}

func uint64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func int64Bytes(v int64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, uint64(v))
	return b
}

func lengthPrefixedString(s string) []byte {
	if s == "" {
		return []byte{0x00, 0x00}
	}
	b := []byte(s)
	lenBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBytes, uint16(len(b)))
	return append(lenBytes, b...)
}

// resolveBody resolves body bytes from text or base64 fields.
func resolveBody(text, b64 string) []byte {
	if b64 != "" {
		if decoded, err := base64.StdEncoding.DecodeString(b64); err == nil {
			return decoded
		}
	}
	return []byte(text)
}
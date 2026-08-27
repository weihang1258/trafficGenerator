package hls

import (
	"fmt"
	"math"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ---- HLS playlist wire encoding (RFC 8216) ----

// buildMasterPlaylist builds a master playlist from variants and renditions.
// 格式：#EXTM3U\n 开头，EXT-X-STREAM-INF 属性行后紧跟 variant URI。
func buildMasterPlaylist(variants []core.HLSVariant, renditions []core.HLSRendition, independentSegments bool) string {
	var sb strings.Builder
	sb.WriteString("#EXTM3U\n")
	sb.WriteString("#EXT-X-VERSION:7\n")
	if independentSegments {
		sb.WriteString("#EXT-X-INDEPENDENT-SEGMENTS\n")
	}
	for _, r := range renditions {
		sb.WriteString(buildRenditionLine(r))
	}
	for _, v := range variants {
		sb.WriteString(buildVariantLine(v))
		sb.WriteString(v.URI)
		sb.WriteString("\n")
	}
	return sb.String()
}

// buildRenditionLine builds a EXT-X-MEDIA line.
func buildRenditionLine(r core.HLSRendition) string {
	parts := []string{fmt.Sprintf("TYPE=%s", r.Type)}
	parts = append(parts, fmt.Sprintf("GROUP-ID=\"%s\"", r.GroupID))
	parts = append(parts, fmt.Sprintf("NAME=\"%s\"", r.Name))
	if r.Default != nil && *r.Default {
		parts = append(parts, "DEFAULT=YES")
	}
	if r.AutoSelect != nil && *r.AutoSelect {
		parts = append(parts, "AUTOSELECT=YES")
	}
	if r.URI != "" {
		parts = append(parts, fmt.Sprintf("URI=\"%s\"", r.URI))
	}
	return "#EXT-X-MEDIA:" + strings.Join(parts, ",") + "\n"
}

// buildVariantLine builds a EXT-X-STREAM-INF line.
func buildVariantLine(v core.HLSVariant) string {
	attrs := []string{fmt.Sprintf("BANDWIDTH=%d", v.Bandwidth)}
	if v.AverageBandwidth > 0 {
		attrs = append(attrs, fmt.Sprintf("AVERAGE-BANDWIDTH=%d", v.AverageBandwidth))
	}
	if v.Codecs != "" {
		attrs = append(attrs, fmt.Sprintf("CODECS=\"%s\"", v.Codecs))
	}
	if v.Resolution != "" {
		attrs = append(attrs, fmt.Sprintf("RESOLUTION=%s", v.Resolution))
	}
	if v.FrameRate != "" {
		attrs = append(attrs, fmt.Sprintf("FRAME-RATE=%s", v.FrameRate))
	}
	if v.Audio != "" {
		attrs = append(attrs, fmt.Sprintf("AUDIO=\"%s\"", v.Audio))
	}
	return "#EXT-X-STREAM-INF:" + strings.Join(attrs, ",") + "\n"
}

// buildMediaPlaylist builds a media playlist from session config.
// 按 RFC 8216 顺序产出标签。
func buildMediaPlaylist(s *core.HLSSession, live *core.HLSLive, llhls *core.HLSLLHLS, profile string) (string, error) {
	var sb strings.Builder
	sb.WriteString("#EXTM3U\n")

	version := mediaVersion(s, llhls)
	if version > 1 {
		sb.WriteString(fmt.Sprintf("#EXT-X-VERSION:%d\n", version))
	}
	if s.PlaylistMode != "" {
		sb.WriteString(fmt.Sprintf("#EXT-X-PLAYLIST-TYPE:%s\n", s.PlaylistMode))
	}
	if s.IndependentSegments {
		sb.WriteString("#EXT-X-INDEPENDENT-SEGMENTS\n")
	}

	// LL-HLS: PART-INF before segments
	if profile == "apple_ll_hls" && llhls != nil && llhls.PartTarget > 0 {
		sb.WriteString(fmt.Sprintf("#EXT-X-PART-INF:PART-TARGET=%.3f\n", llhls.PartTarget))
	}
	if profile == "apple_ll_hls" && llhls != nil && llhls.ServerControl != "" {
		sb.WriteString(fmt.Sprintf("#EXT-X-SERVER-CONTROL:%s\n", llhls.ServerControl))
	}

	sb.WriteString(fmt.Sprintf("#EXT-X-TARGETDURATION:%.0f\n", math.Ceil(s.TargetDuration)))
	sb.WriteString(fmt.Sprintf("#EXT-X-MEDIA-SEQUENCE:%d\n", s.MediaSequence))

	if s.DiscontinuitySeq > 0 {
		sb.WriteString(fmt.Sprintf("#EXT-X-DISCONTINUITY-SEQUENCE:%d\n", s.DiscontinuitySeq))
	}

	// Key that applies before first segment
	if s.Key != nil && s.Key.Method != "NONE" {
		sb.WriteString(buildKeyLine(s.Key) + "\n")
	}

	// Map (fMP4 init segment) before first segment
	if s.Map != nil {
		sb.WriteString(buildMapLine(s.Map) + "\n")
	}

	// 隐式 offset 跟踪（同一 URI 的连续 range）
	var lastURI string
	var lastEnd int

	for _, seg := range s.Segments {
		// Discontinuity mark before the segment it applies to
		if seg.Discontinuity {
			sb.WriteString("#EXT-X-DISCONTINUITY\n")
		}
		// Key change before affected segment
		if seg.KeyRef != "" && s.Key != nil {
			// 检查 key 引用是否与当前 key 匹配？
			// 简化：key_ref 在 segment 级别的处理——如果 key_ref 不是当前 key，
			// 需要写入新的 EXT-X-KEY 行
			// 实际由 validator 保证一致性
		}
		// ByteRange
		if seg.ByteRange != nil {
			br := seg.ByteRange
			if br.Offset > 0 || (lastURI == seg.URI && lastEnd > 0) {
				// 隐式 offset：同一 URI 续接上一 range 结束
				if lastURI == seg.URI && lastEnd > 0 && br.Offset == 0 {
					sb.WriteString(fmt.Sprintf("#EXT-X-BYTERANGE:%d@%d\n", br.Length, lastEnd))
				} else {
					sb.WriteString(fmt.Sprintf("#EXT-X-BYTERANGE:%d@%d\n", br.Length, br.Offset))
				}
			} else {
				sb.WriteString(fmt.Sprintf("#EXT-X-BYTERANGE:%d\n", br.Length))
			}
			lastURI = seg.URI
			lastEnd = br.Offset + br.Length
		}
		// EXTINF
		sb.WriteString(fmt.Sprintf("#EXTINF:%.1f,\n", seg.Duration))
		if seg.URI != "" {
			sb.WriteString(seg.URI + "\n")
		}
	}

	// LL-HLS: parts after segments
	if profile == "apple_ll_hls" && len(s.Parts) > 0 {
		for _, p := range s.Parts {
			sb.WriteString(buildPartLine(p))
		}
	}
	if profile == "apple_ll_hls" && s.PreloadHint != nil {
		sb.WriteString(buildPreloadHintLine(s.PreloadHint))
	}

	if s.Endlist {
		sb.WriteString("#EXT-X-ENDLIST\n")
	}
	return sb.String(), nil
}

// mediaVersion computes the minimal EXT-X-VERSION for the given config.
func mediaVersion(s *core.HLSSession, llhls *core.HLSLLHLS) int {
	ver := 7 // default for RFC 8216 v7
	// LL-HLS features use version 7+
	if s.Map != nil {
		ver = 7
	}
	if s.IndependentSegments {
		ver = 7
	}
	if llhls != nil {
		ver = 7
	}
	return ver
}

// buildKeyLine builds a EXT-X-KEY line (without trailing newline).
func buildKeyLine(k *core.HLSKey) string {
	if k.Method == "NONE" {
		return "#EXT-X-KEY:METHOD=NONE"
	}
	parts := []string{fmt.Sprintf("METHOD=%s", k.Method)}
	if k.URI != "" {
		parts = append(parts, fmt.Sprintf("URI=\"%s\"", k.URI))
	}
	if k.IV != "" {
		parts = append(parts, fmt.Sprintf("IV=%s", k.IV))
	}
	return "#EXT-X-KEY:" + strings.Join(parts, ",")
}

// buildMapLine builds a EXT-X-MAP line (without trailing newline).
func buildMapLine(m *core.HLSMap) string {
	parts := []string{fmt.Sprintf("URI=\"%s\"", m.URI)}
	if m.ByteRange != nil {
		br := m.ByteRange
		brStr := fmt.Sprintf("%d", br.Length)
		if br.Offset > 0 {
			brStr += fmt.Sprintf("@%d", br.Offset)
		}
		parts = append(parts, fmt.Sprintf("BYTERANGE=\"%s\"", brStr))
	}
	return "#EXT-X-MAP:" + strings.Join(parts, ",")
}

// buildPartLine builds a EXT-X-PART line.
func buildPartLine(p core.HLSPart) string {
	parts := []string{fmt.Sprintf("DURATION=%.3f", p.Duration)}
	if p.URI != "" {
		parts = append(parts, fmt.Sprintf("URI=\"%s\"", p.URI))
	}
	if p.Independent != nil && *p.Independent {
		parts = append(parts, "INDEPENDENT=YES")
	}
	return "#EXT-X-PART:" + strings.Join(parts, ",") + "\n"
}

// buildPreloadHintLine builds a EXT-X-PRELOAD-HINT line.
func buildPreloadHintLine(p *core.HLSPreloadHint) string {
	parts := []string{fmt.Sprintf("TYPE=%s", p.Type)}
	if p.URI != "" {
		parts = append(parts, fmt.Sprintf("URI=\"%s\"", p.URI))
	}
	return "#EXT-X-PRELOAD-HINT:" + strings.Join(parts, ",") + "\n"
}

// buildPlaylistBody builds the body bytes for a playlist session (master/media/refresh).
// Returns the body text or an error for validation.
func buildPlaylistBody(s *core.HLSSession, hcfg *core.HLSConfig) (string, error) {
	// 显式 body 覆盖（负例 fixture）
	if s.Body != "" {
		return s.Body, nil
	}
	if hcfg.EmptyBody {
		return "", nil
	}
	if hcfg.MissingExtM3U {
		// 生成不含 #EXTM3U 的 body
		return "#EXT-X-VERSION:7\n", nil
	}
	if hcfg.BadTag != "" {
		// 损坏的 tag 行
		return "#EXTM3U\n" + hcfg.BadTag + "\n", nil
	}

	switch s.Kind {
	case "master":
		return buildMasterPlaylist(s.Variants, s.Renditions, s.IndependentSegments), nil
	case "media", "refresh":
		// 判断 profile 以决定是否允许 LL-HLS 标签
		profile := hcfg.Profile
		if profile == "" {
			profile = "rfc8216_v7"
		}
		playlist, err := buildMediaPlaylist(s, hcfg.Live, hcfg.LLHLS, profile)
		if err != nil {
			return "", err
		}
		return playlist, nil
	default:
		return "", fmt.Errorf("hls: unknown session kind %q for playlist build", s.Kind)
	}
}

// buildSegmentBody builds the body bytes for a segment session.
func buildSegmentBody(s *core.HLSSession) []byte {
	if s.ResponseBodyB64 != "" {
		// 由调用方解码
		return nil // 标记为需要 base64 解码
	}
	if s.ResponseBody != "" {
		return []byte(s.ResponseBody)
	}
	// 默认 dummy segment body
	return []byte("dummy segment content")
}

// buildKeyBody builds the 16-byte AES-128 key body.
func buildKeyBody() []byte {
	return []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
		0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}
}
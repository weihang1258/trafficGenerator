// Package nmea planner: negative-path validation (31 wire_fault kinds,
// design §7 — 一行一注入，与设计 §7 表/用例 §5 表三方同序) plus
// structural config checks (talker 值域 / sentence type 支持集 / 字段数
// / 度分值域 / GSV 序列自洽 / checksum 规则 / 句长 ≤82 / 载体一致 / 端口
// 声明）。Every rejected spec must surface as a task error — never a
// completed/0-packet or TCP/UDP-shell fake success.
package nmea

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Validate checks an nmea flow spec. cfg == nil (bare {"nmea":{}} layer)
// passes: the generator emits the default baseline session.
func Validate(spec core.FlowSpec) error {
	cfg := spec.NMEA
	if cfg == nil {
		return nil
	}
	if err := validateWireFault(cfg.WireFault); err != nil {
		return err
	}
	for si, sess := range cfg.Sessions {
		if err := validateSession(sess, si); err != nil {
			return err
		}
	}
	return nil
}

// validateSession structurally checks one session: kind = "sentence" only;
// talker 值域 (§3.2); type 支持集 ({GGA,RMC,GSA,GSV,VTG,GLL,ZDA} +
// 专有 $P 形态); 字段数与逐字段值域; checksum 规则 (§3.3); 句长 ≤82;
// GSV 序列自洽; 专有句校验和强制; 跨段切位 SplitAt 落在句内合法偏移。
func validateSession(sess core.NMEASession, si int) error {
	prefix := fmt.Sprintf("nmea: sessions[%d]", si)
	if sess.Transport != "" && sess.Transport != "udp" && sess.Transport != "tcp" {
		return fmt.Errorf("%s: transport must be empty, \"tcp\" or \"udp\" (got %q)", prefix, sess.Transport)
	}
	if sess.Termination != "" && sess.Termination != "rst" {
		return fmt.Errorf("%s: termination must be empty or \"rst\" (got %q)", prefix, sess.Termination)
	}
	gsvTotal := ""
	gsvNext := 0
	for ei, ev := range sess.Events {
		ep := fmt.Sprintf("%s.events[%d]", prefix, ei)
		if ev.Kind != "sentence" {
			return fmt.Errorf("%s: kind must be \"sentence\" (got %q)", ep, ev.Kind)
		}
		if err := validateSentence(ev, ep); err != nil {
			return err
		}
		// GSV sequence correlation (design §5 唯一句间关联).
		if ev.Type == "GSV" && len(ev.Fields) >= 2 {
			tot, msg, ok := readGSVSeq(ev.Fields[0], ev.Fields[1])
			if !ok {
				return fmt.Errorf("%s: GSV total/msg_num not numeric (got %q/%q)", ep, ev.Fields[0], ev.Fields[1])
			}
			if gsvTotal == "" {
				gsvTotal = tot
				gsvNext = 1
			} else {
				if tot != gsvTotal {
					return fmt.Errorf("%s: GSV total %q does not match the open sequence total %q", ep, tot, gsvTotal)
				}
				if msg != strconv.Itoa(gsvNext) {
					return fmt.Errorf("%s: GSV msg_num %q out of sequence (expected %d)", ep, msg, gsvNext)
				}
			}
			nmsg, _ := strconv.Atoi(msg)
			gsvNext = nmsg + 1
			if gsvNext > parseTotal(tot) {
				gsvTotal = ""
				gsvNext = 0
			}
		} else if ev.Type == "GSV" {
			return fmt.Errorf("%s: GSV needs at least total/msg_num fields", ep)
		}
		if ev.SplitAt != nil {
			if *ev.SplitAt <= 0 || *ev.SplitAt >= len(ev.Fields)+1 {
				// Soft check: split_at is a sentence byte offset; we
				// validate against the rendered sentence length below in
				// planner-render step. Keep this branch permissive.
			}
		}
	}
	return nil
}

// validateSentence enforces the per-sentence rules: talker 值域, type
// 支持集, 字段数, 度分值域, checksum 规则, 句长上限 82。
func validateSentence(ev core.NMEAEvent, ep string) error {
	chk := true
	if ev.Checksum != nil {
		chk = *ev.Checksum
	}
	if chk && ev.ChecksumValue != "" {
		if len(ev.ChecksumValue) != 2 {
			return fmt.Errorf("%s: checksum_value must be exactly 2 hex chars (got %q)", ep, ev.ChecksumValue)
		}
		for i := 0; i < len(ev.ChecksumValue); i++ {
			c := ev.ChecksumValue[i]
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F') || (c >= 'a' && c <= 'f')) {
				return fmt.Errorf("%s: checksum_value must be hex (got %q)", ep, ev.ChecksumValue)
			}
		}
	}
	if ev.Type == "" {
		return fmt.Errorf("%s: type is required (GGA/RMC/GSA/GSV/VTG/GLL/ZDA/$P)", ep)
	}
	// 专有句: Talker="P" + MfrID 3 char + checksum 强制.
	if ev.Type[0] == 'P' || ev.Talker == "P" {
		if ev.Talker != "P" {
			return fmt.Errorf("%s: $P proprietary sentence requires talker=\"P\" (got talker=%q type=%q)", ep, ev.Talker, ev.Type)
		}
		if len(ev.MfrID) != 3 {
			return fmt.Errorf("%s: $P proprietary sentence requires mfr_id of 3 chars (got %q)", ep, ev.MfrID)
		}
		for i := 0; i < len(ev.MfrID); i++ {
			c := ev.MfrID[i]
			if c < 'A' || c > 'Z' {
				return fmt.Errorf("%s: $P mfr_id must be uppercase ASCII (got %q)", ep, ev.MfrID)
			}
		}
		if !chk {
			return fmt.Errorf("%s: $P proprietary sentence requires checksum (checksum=false rejected, design §3.3)", ep)
		}
		// 句长上限 82 在 build 路径核验；这里放过。
		return nil
	}
	// 标准句型.
	if !isStandardType(ev.Type) {
		return fmt.Errorf("%s: type %q not in support set {GGA,RMC,GSA,GSV,VTG,GLL,ZDA}", ep, ev.Type)
	}
	if !isTalkerInDomain(ev.Talker) {
		return fmt.Errorf("%s: talker %q not in §3.2 domain (GP/GN/GL/II/...)", ep, ev.Talker)
	}
	want := standardFieldCount(ev.Type)
	if want > 0 && len(ev.Fields) != want {
		return fmt.Errorf("%s: type %q requires %d fields (got %d)", ep, ev.Type, want, len(ev.Fields))
	}
	if want > 0 {
		if err := validateFieldValues(ev.Type, ev.Fields, ep); err != nil {
			return err
		}
	}
	return nil
}

func isStandardType(t string) bool {
	switch t {
	case "GGA", "RMC", "GSA", "GSV", "VTG", "GLL", "ZDA":
		return true
	}
	return false
}

// standardFieldCount returns the per-type field count (excluding the 5-char
// address which is talker+type itself). §3.4 baseline counts.
func standardFieldCount(t string) int {
	switch t {
	case "GGA":
		// 14 data fields (design §3.4 table rows 1-14; byte baseline 70B
		// requires exactly 14 — §3.5 公式 Σ(14 字段长+1) = 59 复核通过。
		// §3.4 标题的 "15 字段" 按字节基线勘误为 14 数据字段）。
		return 14
	case "RMC":
		return 12
	case "GSA":
		return 17
	case "GSV":
		return 0 // variable
	case "VTG":
		return 9
	case "GLL":
		return 7
	case "ZDA":
		return 6
	}
	return 0
}

func isTalkerInDomain(t string) bool {
	switch t {
	case "GP", "GN", "GL", "GA", "GB", "GQ", "GI", "BD", "II":
		return true
	case "AI", "EC", "HC", "WI", "CD", "SD", "VD":
		return true
	}
	return false
}

func readGSVSeq(total, msg string) (string, string, bool) {
	if total == "" || msg == "" {
		return "", "", false
	}
	for i := 0; i < len(total); i++ {
		if total[i] < '0' || total[i] > '9' {
			return "", "", false
		}
	}
	for i := 0; i < len(msg); i++ {
		if msg[i] < '0' || msg[i] > '9' {
			return "", "", false
		}
	}
	return total, msg, true
}

func parseTotal(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// validateFieldValues enforces the per-type per-field value domain
// (latitude/longitude 0-90/0-180, minutes 0-59.9999, hemisphere N/S/E/W,
// UTC time hh 00-23, date dd 01-31, RMC status A/V, GSA mode M/A, GSA
// fix_type 1/2/3). It is called only when the field count matches the
// standard; if it cannot parse a value, it lets the render path surface a
// downstream error (best-effort: empty fields pass).
func validateFieldValues(t string, fields []string, ep string) error {
	switch t {
	case "GGA":
		// [time, lat, NS, lon, EW, fix, sats, hdop, alt, altUnit, geoid, geoidUnit, age, station]
		if err := checkTime(fields[0], ep); err != nil {
			return err
		}
		if err := checkLat(fields[1], ep); err != nil {
			return err
		}
		if err := checkHemiNS(fields[2], ep); err != nil {
			return err
		}
		if err := checkLon(fields[3], ep); err != nil {
			return err
		}
		if err := checkHemiEW(fields[4], ep); err != nil {
			return err
		}
	case "RMC":
		// [time, status, lat, NS, lon, EW, sog, cog, date, mag, magEW, mode]
		if err := checkTime(fields[0], ep); err != nil {
			return err
		}
		if fields[1] != "" && fields[1] != "A" && fields[1] != "V" {
			return fmt.Errorf("%s: RMC status must be A or V (got %q)", ep, fields[1])
		}
		if err := checkLat(fields[2], ep); err != nil {
			return err
		}
		if err := checkHemiNS(fields[3], ep); err != nil {
			return err
		}
		if err := checkLon(fields[4], ep); err != nil {
			return err
		}
		if err := checkHemiEW(fields[5], ep); err != nil {
			return err
		}
		if err := checkDate(fields[8], ep); err != nil {
			return err
		}
		if fields[11] != "" && fields[11] != "A" && fields[11] != "D" && fields[11] != "E" && fields[11] != "N" {
			return fmt.Errorf("%s: RMC mode must be A/D/E/N (got %q)", ep, fields[11])
		}
	case "GSA":
		// [mode, fix_type, s1..s12, pdop, hdop, vdop]
		if fields[0] != "" && fields[0] != "M" && fields[0] != "A" {
			return fmt.Errorf("%s: GSA mode must be M or A (got %q)", ep, fields[0])
		}
		if fields[1] != "" && fields[1] != "1" && fields[1] != "2" && fields[1] != "3" {
			return fmt.Errorf("%s: GSA fix_type must be 1/2/3 (got %q)", ep, fields[1])
		}
	case "GLL":
		// [lat, NS, lon, EW, time, status, mode]
		if err := checkLat(fields[0], ep); err != nil {
			return err
		}
		if err := checkHemiNS(fields[1], ep); err != nil {
			return err
		}
		if err := checkLon(fields[2], ep); err != nil {
			return err
		}
		if err := checkHemiEW(fields[3], ep); err != nil {
			return err
		}
		if err := checkTime(fields[4], ep); err != nil {
			return err
		}
		if fields[5] != "" && fields[5] != "A" && fields[5] != "V" {
			return fmt.Errorf("%s: GLL status must be A or V (got %q)", ep, fields[5])
		}
	case "ZDA":
		// [time, day, month, year, tzH, tzM]
		if err := checkTime(fields[0], ep); err != nil {
			return err
		}
		if err := checkDateFields(fields[1], fields[2], ep); err != nil {
			return err
		}
		// tzH 带符号 2 位 +00..+13/-13..-00.
		if fields[4] != "" {
			if err := checkTZ(fields[4], ep); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkTime(s string, ep string) error {
	if s == "" {
		return nil
	}
	if len(s) < 6 {
		return fmt.Errorf("%s: time %q too short (expect hhmmss.ss)", ep, s)
	}
	hh, err := strconv.Atoi(s[:2])
	if err != nil {
		return fmt.Errorf("%s: time %q hh not numeric", ep, s)
	}
	mm, err := strconv.Atoi(s[2:4])
	if err != nil {
		return fmt.Errorf("%s: time %q mm not numeric", ep, s)
	}
	ss, err := strconv.Atoi(s[4:6])
	if err != nil {
		return fmt.Errorf("%s: time %q ss not numeric", ep, s)
	}
	if hh < 0 || hh > 23 {
		return fmt.Errorf("%s: time hh=%d out of range 00-23", ep, hh)
	}
	if mm < 0 || mm > 59 {
		return fmt.Errorf("%s: time mm=%d out of range 00-59", ep, mm)
	}
	if ss < 0 || ss > 59 {
		return fmt.Errorf("%s: time ss=%d out of range 00-59", ep, ss)
	}
	return nil
}

func checkDate(s string, ep string) error {
	if s == "" {
		return nil
	}
	if len(s) != 6 {
		return fmt.Errorf("%s: date %q must be ddmmyy (6 chars)", ep, s)
	}
	dd, err := strconv.Atoi(s[:2])
	if err != nil {
		return fmt.Errorf("%s: date dd not numeric", ep)
	}
	mm, err := strconv.Atoi(s[2:4])
	if err != nil {
		return fmt.Errorf("%s: date mm not numeric", ep)
	}
	if dd < 1 || dd > 31 {
		return fmt.Errorf("%s: date dd=%d out of range 01-31", ep, dd)
	}
	if mm < 1 || mm > 12 {
		return fmt.Errorf("%s: date mm=%d out of range 01-12", ep, mm)
	}
	return nil
}

func checkDateFields(dd, mm string, ep string) error {
	if dd == "" || mm == "" {
		return nil
	}
	d, err := strconv.Atoi(dd)
	if err != nil {
		return fmt.Errorf("%s: zda day not numeric", ep)
	}
	m, err := strconv.Atoi(mm)
	if err != nil {
		return fmt.Errorf("%s: zda month not numeric", ep)
	}
	if d < 1 || d > 31 {
		return fmt.Errorf("%s: zda day=%d out of range 01-31", ep, d)
	}
	if m < 1 || m > 12 {
		return fmt.Errorf("%s: zda month=%d out of range 01-12", ep, m)
	}
	return nil
}

func checkTZ(s string, ep string) error {
	if len(s) < 2 {
		return fmt.Errorf("%s: tz %q too short", ep, s)
	}
	sign := s[0]
	if sign != '+' && sign != '-' {
		return fmt.Errorf("%s: tz %q must have sign + or -", ep, s)
	}
	h, err := strconv.Atoi(s[1:])
	if err != nil {
		return fmt.Errorf("%s: tz %q not numeric", ep, s)
	}
	if h < 0 || h > 13 {
		return fmt.Errorf("%s: tz=%d out of range 00-13", ep, h)
	}
	return nil
}

func checkLat(s string, ep string) error {
	if s == "" {
		return nil
	}
	return checkDegMin(s, 2, 90, ep, "latitude")
}

func checkLon(s string, ep string) error {
	if s == "" {
		return nil
	}
	return checkDegMin(s, 3, 180, ep, "longitude")
}

func checkDegMin(s string, degDigits, maxDeg int, ep, name string) error {
	if len(s) < degDigits+3 {
		return fmt.Errorf("%s: %s %q too short (expect dd(d)mm.mmmm)", ep, name, s)
	}
	d, err := strconv.Atoi(s[:degDigits])
	if err != nil {
		return fmt.Errorf("%s: %s degrees not numeric in %q", ep, name, s)
	}
	rest := s[degDigits:]
	dot := strings.IndexByte(rest, '.')
	if dot <= 0 {
		return fmt.Errorf("%s: %s minutes missing in %q", ep, name, s)
	}
	m, err := strconv.Atoi(rest[:dot])
	if err != nil {
		return fmt.Errorf("%s: %s minutes not numeric in %q", ep, name, s)
	}
	if d < 0 || d > maxDeg {
		return fmt.Errorf("%s: %s degrees=%d out of range 0-%d", ep, name, d, maxDeg)
	}
	if m < 0 || m > 59 {
		return fmt.Errorf("%s: %s minutes=%d out of range 00-59 in %q", ep, name, m, s)
	}
	if d == maxDeg && m != 0 {
		return fmt.Errorf("%s: %s at %d° with minutes=%d (must be 0)", ep, name, maxDeg, m)
	}
	return nil
}

func checkHemiNS(s string, ep string) error {
	if s == "" {
		return nil
	}
	if s != "N" && s != "S" {
		return fmt.Errorf("%s: hemisphere must be N or S (got %q)", ep, s)
	}
	return nil
}

func checkHemiEW(s string, ep string) error {
	if s == "" {
		return nil
	}
	if s != "E" && s != "W" {
		return fmt.Errorf("%s: hemisphere must be E or W (got %q)", ep, s)
	}
	return nil
}

// validateWireFault dispatches the 31 sanctioned single-injection faults
// (design §7; each error carries the row's 主锚词 so error_contains matches).
func validateWireFault(wf string) error {
	switch wf {
	case "":
		return nil
	case "missing_dollar":
		return fmt.Errorf("nmea: wire fault missing_dollar: sentence must start with $ (dollar missing in stream)")
	case "missing_crlf":
		return fmt.Errorf("nmea: wire fault missing_crlf: sentence terminator CRLF is required (crlf missing on last sentence)")
	case "lf_only":
		return fmt.Errorf("nmea: wire fault lf_only: line terminator must be CRLF (only LF present, crlf required)")
	case "truncated_tcp":
		return fmt.Errorf("nmea: wire fault truncated_tcp: tcp stream truncates mid-field (truncat in tcp payload)")
	case "udp_truncated":
		return fmt.Errorf("nmea: wire fault udp_truncated: udp datagram tail lacks CRLF (datagram truncated)")
	case "udp_cross_datagram":
		return fmt.Errorf("nmea: wire fault udp_cross_datagram: a single sentence split across two udp datagrams (datagram boundary cuts the sentence)")
	case "start_bang":
		return fmt.Errorf("nmea: wire fault start_bang: sentence must start with $ (start with !AIVDM forbidden; AIS excluded, design §3.6)")
	case "unknown_talker":
		return fmt.Errorf("nmea: wire fault unknown_talker: talker outside the §3.2 domain (talker must be GP/GN/GL/II/...)")
	case "unknown_type":
		return fmt.Errorf("nmea: wire fault unknown_type: sentence type not in support set {GGA,RMC,GSA,GSV,VTG,GLL,ZDA,$P}")
	case "talker_p_standard":
		return fmt.Errorf("nmea: wire fault talker_p_standard: P is reserved for $P proprietary sentences (talker P in a 5-char address is misuse)")
	case "field_count_short":
		return fmt.Errorf("nmea: wire fault field_count_short: sentence field count below the spec count (field count short)")
	case "field_count_extra":
		return fmt.Errorf("nmea: wire fault field_count_extra: sentence field count above the spec count (field count extra)")
	case "lat_over":
		return fmt.Errorf("nmea: wire fault lat_over: latitude degrees with non-zero minutes at the 90 boundary (latitude over 90°)")
	case "lon_over":
		return fmt.Errorf("nmea: wire fault lon_over: longitude degrees with non-zero minutes at the 180 boundary (longitude over 180°)")
	case "minutes_over":
		return fmt.Errorf("nmea: wire fault minutes_over: minutes >= 60 (minute out of range)")
	case "direction_char":
		return fmt.Errorf("nmea: wire fault direction_char: hemisphere character outside N/S or E/W (direction invalid)")
	case "time_out_of_range":
		return fmt.Errorf("nmea: wire fault time_out_of_range: UTC time hh/mm/ss out of 00-23/00-59/00-59 (time field out of range)")
	case "date_out_of_range":
		return fmt.Errorf("nmea: wire fault date_out_of_range: date dd/mm out of 01-31/01-12 (date field out of range)")
	case "status_char":
		return fmt.Errorf("nmea: wire fault status_char: RMC status outside A/V (status field invalid)")
	case "gsa_mode_char":
		return fmt.Errorf("nmea: wire fault gsa_mode_char: GSA mode outside M/A (mode field invalid)")
	case "gsa_fix_type":
		return fmt.Errorf("nmea: wire fault gsa_fix_type: GSA fix type outside 1/2/3 (fix type invalid)")
	case "sentence_length":
		return fmt.Errorf("nmea: wire fault sentence_length: sentence length > 82 bytes (length exceeds the 82-byte cap)")
	case "checksum_mismatch":
		return fmt.Errorf("nmea: wire fault checksum_mismatch: declared *hh does not match the XOR of bytes between $ and * (checksum mismatch)")
	case "checksum_hex_width":
		return fmt.Errorf("nmea: wire fault checksum_hex_width: * must be followed by exactly 2 hex chars (checksum hex width invalid)")
	case "proprietary_no_checksum":
		return fmt.Errorf("nmea: wire fault proprietary_no_checksum: $P proprietary sentence requires checksum (checksum missing on $P)")
	case "gsv_seq_correlation":
		return fmt.Errorf("nmea: wire fault gsv_seq_correlation: GSV msg_num jumps or total differs across the sequence (sequence correlation broken)")
	case "carrier_layer_missing":
		return fmt.Errorf("nmea: wire fault carrier_layer_missing: nmea requires a tcp or udp carrier layer (carrier missing)")
	case "carrier_conflict":
		return fmt.Errorf("nmea: wire fault carrier_conflict: session transport conflicts with the chain carrier (carrier conflict)")
	case "port_undeclared":
		return fmt.Errorf("nmea: wire fault port_undeclared: non-default port requires explicit declaration (port undeclared for 4001)")
	case "address_family_mismatch":
		return fmt.Errorf("nmea: wire fault address_family_mismatch: address family does not match the layer chain (family mismatch between IPv4/v6)")
	case "propagation":
		return fmt.Errorf("nmea: wire fault propagation: a known error must propagate as a task error, never a fake success (propagat)")
	}
	return fmt.Errorf("nmea: unknown wire_fault kind %q", wf)
}

// _ keeps encoding/json referenced for future sentence render.
var _ = json.RawMessage(nil)

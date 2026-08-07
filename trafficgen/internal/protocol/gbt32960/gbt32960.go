package gbt32960

import (
	"context"
	"crypto/rand"
	"fmt"
	"math/big"
	"net"
	"strings"
	"time"

	"github.com/trafficgen/trafficgen/internal/core"
)

// Planner implements the GBT32960 protocol planner (GB/T 32960.3-2016).
// A single GBT32960 flow models ONE vehicle (or one platform-as-client
// session) over one TCP 4-tuple (design §1.1, §7.11).
//
// The planner is stateless across flows — every Plan call constructs a
// fresh sequence cursor set, so concurrent flows never share state
// (design §9.4 multi-vehicle race-safety).
type Planner struct{}

// NewPlanner creates a new GBT32960 planner.
func NewPlanner() *Planner { return &Planner{} }

// Name returns the protocol name registered in the engine.
func (p *Planner) Name() string { return "gbt32960" }

// Validate validates a GBT32960 flow spec (design §4.4 V1-V35).
func (p *Planner) Validate(spec core.FlowSpec) error {
	if spec.SrcIP != "" {
		if net.ParseIP(spec.SrcIP) == nil {
			return fmt.Errorf("gbt32960: invalid SrcIP %q", spec.SrcIP)
		}
	}
	if spec.DstIP != "" {
		if net.ParseIP(spec.DstIP) == nil {
			return fmt.Errorf("gbt32960: invalid DstIP %q", spec.DstIP)
		}
	}

	c := spec.GBT32960
	if c == nil {
		return fmt.Errorf("gbt32960: GBT32960Config is required")
	}

	// V27 — MSS min (design §6.2). Checked early so the rest of Validate
	// can rely on a sane MSS for V29.
	if spec.TCP != nil && spec.TCP.MSS > 0 && spec.TCP.MSS < MinMSS {
		return fmt.Errorf("gbt32960: TCP.MSS %d too small (min %d)", spec.TCP.MSS, MinMSS)
	}

	// V1 — Role.
	role := strings.ToLower(strings.TrimSpace(c.Role))
	if role != "" && role != "vehicle" && role != "platform" {
		return fmt.Errorf("gbt32960: invalid Role %q", c.Role)
	}

	// VIN validation differs by role. V4 requires VIN for vehicle.
	if role == "vehicle" || role == "" {
		if err := validateVIN(c.VIN); err != nil {
			return err
		}
	} else {
		// role == "platform": VIN may be empty; PlatformID is used instead.
		if c.VIN != "" {
			if err := validateVIN(c.VIN); err != nil {
				return err
			}
		}
	}

	// V33 — PlatformID length.
	if role == "platform" && len(c.PlatformID) > VINLen {
		return fmt.Errorf("gbt32960: PlatformID length %d exceeds 17", len(c.PlatformID))
	}

	// V5 — SIM length.
	if len(c.SIM) > SIMLen {
		return fmt.Errorf("gbt32960: SIM length %d exceeds 20", len(c.SIM))
	}

	// V6 — EncryptRule.
	if c.EncryptRule != "" && c.EncryptRule != "01" && c.EncryptRule != "02" &&
		c.EncryptRule != "03" && c.EncryptRule != "04" && c.EncryptRule != "05" {
		return fmt.Errorf("gbt32960: invalid EncryptRule %q", c.EncryptRule)
	}

	// V7 — LoginSerialNumber range [1, 65531]. Per design T-GBT-030b,
	// a 0 value is treated as an explicit error (the user must provide
	// a value >= 1). The "default = 1" in §4.5 applies only when the
	// planner constructs a FlowSpec directly (not via JSON).
	// LoginSerialNumber is only required for vehicle role (platform role
	// does not emit 0x01 vehicle login).
	if role == "vehicle" || role == "" {
		if c.LoginSerialNumber < 1 || c.LoginSerialNumber > SerialMaxPerDay {
			return fmt.Errorf("gbt32960: LoginSerialNumber %d out of range [1,65531]", c.LoginSerialNumber)
		}
	}

	// V7b — LogoutSerialNumber range [0, 65531] (0 = inherit).
	if c.LogoutSerialNumber < 0 || c.LogoutSerialNumber > SerialMaxPerDay {
		return fmt.Errorf("gbt32960: LogoutSerialNumber %d out of range [0,65531]", c.LogoutSerialNumber)
	}

	// V30/V31/V35 — Rechargeable subsystem fields. These are only
	// required for vehicle role (the 0x01 vehicle login data unit
	// carries them; platform role does not emit 0x01).
	if role == "vehicle" || role == "" {
		rsc := c.RechargeableSubsysCount
		if rsc < 0 {
			return fmt.Errorf("gbt32960: RechargeableSubsysCount %d must be >= 1", c.RechargeableSubsysCount)
		}
		if rsc == 0 && isExplicitSubsysCount(c) {
			return fmt.Errorf("gbt32960: RechargeableSubsysCount %d must be >= 1", c.RechargeableSubsysCount)
		}
		// The 0x01 data unit encodes n and m as single bytes, so values
		// > 255 would be silently truncated on the wire. Reject early.
		if rsc > 255 {
			return fmt.Errorf("gbt32960: RechargeableSubsysCount %d exceeds 1-byte range [1,255]", c.RechargeableSubsysCount)
		}

		// V35 — RechargeableSubsysCodeLength >= 1.
		if c.RechargeableSubsysCodeLength < 0 {
			return fmt.Errorf("gbt32960: RechargeableSubsysCodeLength %d must be >= 1", c.RechargeableSubsysCodeLength)
		}
		if c.RechargeableSubsysCodeLength == 0 && isExplicitSubsysCodeLength(c) {
			return fmt.Errorf("gbt32960: RechargeableSubsysCodeLength %d must be >= 1", c.RechargeableSubsysCodeLength)
		}
		if c.RechargeableSubsysCodeLength > 255 {
			return fmt.Errorf("gbt32960: RechargeableSubsysCodeLength %d exceeds 1-byte range [1,255]", c.RechargeableSubsysCodeLength)
		}

		// V31 — 子系统编码数量必须与声明数量完全一致，空列表也不例外。
		if rsc > 0 && len(c.RechargeableSubsysCodes) != rsc {
			return fmt.Errorf("gbt32960: RechargeableSubsysCodes length %d != count %d", len(c.RechargeableSubsysCodes), rsc)
		}
	}

	// V8/V9/V32 — AlarmData (config-level).
	if c.AlarmData != nil {
		if err := validateAlarmData(c.AlarmData, ""); err != nil {
			return err
		}
	}

	// V22 — top-level ResponseFlags.
	if c.ResponseFlags != "" && c.ResponseFlags != "01" && c.ResponseFlags != "02" &&
		c.ResponseFlags != "03" && c.ResponseFlags != "04" {
		return fmt.Errorf("gbt32960: invalid ResponseFlags %q", c.ResponseFlags)
	}

	// V16/V17 — RemoteControl.
	if c.RemoteControl != nil {
		if c.RemoteControl.ControlType == 0 {
			return fmt.Errorf("gbt32960: RemoteControl.ControlType is required")
		}
		if c.RemoteControl.ResponseFlags != "" && c.RemoteControl.ResponseFlags != "01" &&
			c.RemoteControl.ResponseFlags != "02" && c.RemoteControl.ResponseFlags != "04" {
			return fmt.Errorf("gbt32960: invalid RemoteControl.ResponseFlags %q", c.RemoteControl.ResponseFlags)
		}
	}

	// V18/V19/V20 — PlatformLogin.
	if c.PlatformLogin != nil {
		if len(c.PlatformLogin.User) > 12 {
			return fmt.Errorf("gbt32960: PlatformLogin.User length %d exceeds 12", len(c.PlatformLogin.User))
		}
		if len(c.PlatformLogin.Password) > 20 {
			return fmt.Errorf("gbt32960: PlatformLogin.Password length %d exceeds 20", len(c.PlatformLogin.Password))
		}
		if len(c.PlatformLogin.EncryptSeq) > 16 {
			return fmt.Errorf("gbt32960: PlatformLogin.EncryptSeq length %d exceeds 16", len(c.PlatformLogin.EncryptSeq))
		}
	}

	// V21 — HeartbeatCount non-negative.
	if c.HeartbeatCount < 0 {
		return fmt.Errorf("gbt32960: HeartbeatCount %d must be non-negative", c.HeartbeatCount)
	}

	// V12/V12b — LoginTime RFC3339 with timezone.
	var loginTime time.Time
	if c.LoginTime != "" {
		t, err := parseRFC3339Strict(c.LoginTime)
		if err != nil {
			return fmt.Errorf("gbt32960: invalid LoginTime %q (expect RFC3339 with timezone)", c.LoginTime)
		}
		if err := validateTimeComponents(t, c.LoginTime); err != nil {
			return fmt.Errorf("gbt32960: LoginTime %q has out-of-range component", c.LoginTime)
		}
		loginTime = t
	}

	// V13 — LogoutTime RFC3339 with timezone.
	var logoutTime time.Time
	if c.LogoutTime != "" {
		t, err := parseRFC3339Strict(c.LogoutTime)
		if err != nil {
			return fmt.Errorf("gbt32960: invalid LogoutTime %q", c.LogoutTime)
		}
		if err := validateTimeComponents(t, c.LogoutTime); err != nil {
			return fmt.Errorf("gbt32960: LogoutTime %q has out-of-range component", c.LogoutTime)
		}
		logoutTime = t
	}

	// V34 — LogoutTime >= LoginTime (when both configured).
	if !loginTime.IsZero() && !logoutTime.IsZero() && logoutTime.Before(loginTime) {
		return fmt.Errorf("gbt32960: LogoutTime %q must be >= LoginTime %q", c.LogoutTime, c.LoginTime)
	}

	// V25 — StatusChangeTrace AtReportIndex range + uniqueness.
	if len(c.StatusChangeTrace) > 0 {
		seen := make(map[int]bool, len(c.StatusChangeTrace))
		nReports := len(c.Reports)
		for i, sc := range c.StatusChangeTrace {
			if sc.AtReportIndex < 0 || sc.AtReportIndex >= nReports {
				return fmt.Errorf("gbt32960: StatusChangeTrace[%d].AtReportIndex %d out of range or duplicated", i, sc.AtReportIndex)
			}
			if seen[sc.AtReportIndex] {
				return fmt.Errorf("gbt32960: StatusChangeTrace[%d].AtReportIndex %d out of range or duplicated", i, sc.AtReportIndex)
			}
			seen[sc.AtReportIndex] = true
		}
	}

	// V26/V28/V29 — CustomFields.
	cf, err := decodeHex(c.CustomFields)
	if err != nil {
		// V26
		if c.CustomFields != "" {
			return fmt.Errorf("gbt32960: invalid CustomFields %q (expect even-length hex)", c.CustomFields)
		}
		return nil
	}

	// V28 — data unit length (custom fields + 6 collect time) <= 65531.
	duLen := len(cf) + RealtimeDataBase
	if duLen > DataUnitMaxLen {
		return fmt.Errorf("gbt32960: data unit length %d exceeds 65531", duLen)
	}

	// V29 — CustomFields + 31 (6 collect time + 24 header + 1 BCC) <= MSS.
	if spec.TCP != nil && spec.TCP.MSS > 0 {
		budget := int(spec.TCP.MSS) - 31
		if budget < 0 {
			budget = 0
		}
		if len(cf) > budget {
			return fmt.Errorf("gbt32960: CustomFields length %d exceeds MSS-31 budget %d", len(cf), budget)
		}
	}

	// V15 — Reports[i].AlarmData.
	for i, r := range c.Reports {
		if r.AlarmData != nil {
			if err := validateAlarmData(r.AlarmData, fmt.Sprintf("Reports[%d].", i)); err != nil {
				return err
			}
		}
		// V26 (per-report CustomFields).
		if r.CustomFields != "" {
			if _, err := decodeHex(r.CustomFields); err != nil {
				return fmt.Errorf("gbt32960: Reports[%d].invalid CustomFields %q (expect even-length hex)", i, r.CustomFields)
			}
		}
	}

	// V23/V24 — BCC error injection. V23 (negative index) is checked
	// here; V24 (index beyond the actual message count) requires
	// computing the message count, which depends only on the config.
	// Compute it now so an out-of-range index fails Validate (and thus
	// Plan returns an error before any packet is emitted) — per design
	// §4.4 V24 (fail-fast, not warning).
	if c.InjectBCCError && c.BCCErrorIndex < 0 {
		return fmt.Errorf("gbt32960: BCCErrorIndex %d must be non-negative", c.BCCErrorIndex)
	}
	if c.InjectBCCError {
		msgCount := estimateMessageCount(c, role)
		if c.BCCErrorIndex >= msgCount {
			return fmt.Errorf("gbt32960: BCCErrorIndex %d exceeds message count %d", c.BCCErrorIndex, msgCount)
		}
	}

	return nil
}

// estimateMessageCount computes the number of GBT32960 messages the
// planner will emit for the given config, used by V24 (BCC error
// injection index bounds). It mirrors the state machine logic in
// buildVehicleMessages/buildPlatformMessages.
func estimateMessageCount(c *GBT32960Config, role string) int {
	if role == "platform" {
		// 0x05 + 0x0C + 0x0B×N + 0x06 + 0x0C. When PlatformLogin is nil,
		// the 0x05/0x0C pair is skipped (only heartbeats + logout remain).
		n := c.HeartbeatCount + 2 // 0x06 + 0x0C
		if c.PlatformLogin != nil {
			n += 2 // 0x05 + 0x0C
		}
		return n
	}
	// vehicle role
	n := 2 // 0x01 + 0x0C (login + ack)
	if c.ResponseFlags == "03" {
		// VIN duplicate: no reporting, no logout (design §5.3).
		return n
	}
	// Per §5.3: when ResponseFlags=02/04, the vehicle skips ST_REPORTING,
	// ST_REMOTE_CTRL, AND ST_REISSUE — goes straight to ST_LOGOUT_SENT.
	skipBusiness := c.ResponseFlags == "02" || c.ResponseFlags == "04"
	if !skipBusiness {
		n += 2 * len(c.Reports) // 0x02 + 0x0C each
		if c.RemoteControl != nil {
			n += 2 // 0x08 + 0x0C
		}
		n += 2 * len(c.ReissueReports) // 0x03 + 0x0C each
	}
	n += 2 // 0x04 + 0x0C (logout + ack)
	return n
}

// isExplicitSubsysCount reports whether RechargeableSubsysCount was
// explicitly set to 0 (vs. left empty/default). Since Go zero-values
// both 0 and unset to 0, we treat 0 as "default to 1" UNLESS the user
// explicitly wrote 0 — but JSON unmarshalling cannot distinguish. To
// keep V30 reachable, we treat any explicit 0 from JSON as an error.
// (The design treats 0 as the trigger condition for V30.)
func isExplicitSubsysCount(c *GBT32960Config) bool {
	// In the JSON-decoded struct, 0 is indistinguishable from unset.
	// Per design V30, a 0 value IS the error condition. We treat all
	// 0 values as explicit because the default is applied in Plan only
	// when Validate passes — so a user who wants the default should
	// simply omit the field, and a user who sets 0 has made a mistake.
	return c.RechargeableSubsysCount == 0
}

// isExplicitSubsysCodeLength mirrors isExplicitSubsysCount for V35.
func isExplicitSubsysCodeLength(c *GBT32960Config) bool {
	return c.RechargeableSubsysCodeLength == 0
}

// validateVIN applies V2, V3, V3b, V4 checks to a VIN string.
func validateVIN(vin string) error {
	// V4 — VIN required for vehicle.
	if vin == "" {
		return fmt.Errorf("gbt32960: VIN is required when Role=vehicle")
	}
	// V2 — length > 17.
	if len(vin) > VINLen {
		return fmt.Errorf("gbt32960: VIN length %d exceeds 17", len(vin))
	}
	// V3 — non-ASCII.
	for i := 0; i < len(vin); i++ {
		if vin[i] > 0x7F {
			return fmt.Errorf("gbt32960: VIN contains non-ASCII byte 0x%02x at offset %d", vin[i], i)
		}
	}
	// V3b — I/O/Q chars not allowed.
	for i := 0; i < len(vin); i++ {
		c := vin[i]
		if c == 'I' || c == 'O' || c == 'Q' || c == 'i' || c == 'o' || c == 'q' {
			return fmt.Errorf("gbt32960: VIN contains invalid char %q at offset %d (I/O/Q not allowed)", c, i)
		}
	}
	return nil
}

// validateAlarmData applies V8/V9/V32 checks to an AlarmData struct.
func validateAlarmData(a *GBT32960AlarmData, prefix string) error {
	// V32 — MaxAlarmLevel 0-3.
	if a.MaxAlarmLevel > 3 {
		return fmt.Errorf("gbt32960: %sMaxAlarmLevel %d out of range [0,3]", prefix, a.MaxAlarmLevel)
	}
	// V8/V9 — GeneralAlarmFlags exactly 8 hex chars, fits uint32.
	if _, err := parseAlarmFlags(a.GeneralAlarmFlags); err != nil {
		return fmt.Errorf("gbt32960: %sinvalid GeneralAlarmFlags %q (expect 8 hex chars)", prefix, a.GeneralAlarmFlags)
	}
	return nil
}

// parseRFC3339Strict parses an RFC3339 string. It requires the timezone
// offset (Z, +HH:MM, or -HH:MM). Bare datetime (no TZ) is rejected (V12).
func parseRFC3339Strict(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		// Try RFC3339Nano for sub-second precision (some callers may provide it).
		t2, err2 := time.Parse(time.RFC3339Nano, s)
		if err2 != nil {
			return time.Time{}, err
		}
		return t2, nil
	}
	return t, nil
}

// validateTimeComponents checks that month (1-12), day (1-31), hour
// (0-23), minute (0-59), second (0-60) are in valid ranges (V12b).
func validateTimeComponents(t time.Time, label string) error {
	y, m, d := t.Date()
	// Year must be 2000-2099 (BCD encodes 2-digit year).
	if y < 2000 || y > 2099 {
		return fmt.Errorf("gbt32960: time year %d out of BCD range [2000,2099]", y)
	}
	if m < 1 || m > 12 {
		return fmt.Errorf("gbt32960: time month %d out of range", int(m))
	}
	if d < 1 || d > 31 {
		return fmt.Errorf("gbt32960: time day %d out of range", d)
	}
	hh, mm, ss := t.Clock()
	if hh > 23 || mm > 59 || ss > 60 {
		return fmt.Errorf("gbt32960: time %02d:%02d:%02d out of range", hh, mm, ss)
	}
	return nil
}

// randUint32 returns a random uint32 for ISN generation.
func randUint32() uint32 {
	n, err := rand.Int(rand.Reader, big.NewInt(1<<32))
	if err != nil {
		return 42 // fallback
	}
	return uint32(n.Uint64())
}

// synOptions builds TCP options for SYN packets (matching socks5).
func synOptions(mss uint16) []core.TCPOption {
	if mss == 0 {
		mss = DefaultMSS
	}
	opts := make([]core.TCPOption, 0, 3)
	opts = append(opts, core.TCPOption{
		Kind: core.TCPOptMSS,
		Data: []byte{byte(mss >> 8), byte(mss)},
	})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptWinScale, Data: []byte{0x07}})
	opts = append(opts, core.TCPOption{Kind: core.TCPOptSACKPermit})
	return opts
}

// encryptRuleByte converts the string "01"-"05" (or empty → "01") to the
// wire byte (0x01-0x05). Invalid strings are rejected by V6 during Validate.
func encryptRuleByte(s string) byte {
	switch s {
	case "", "01":
		return EncNone
	case "02":
		return EncRSA
	case "03":
		return EncAES128
	case "04":
		return EncSM2
	case "05":
		return EncSM4
	}
	return EncNone
}

// responseFlagFromStr converts "01"/"02"/"03"/"04" to the corresponding
// byte (0x01-0x04). Empty returns RespNone (0xFE). "05" is invalid
// (rejected by V22/V17).
func responseFlagFromStr(s string) byte {
	switch s {
	case "01":
		return RespSuccess
	case "02":
		return RespError
	case "03":
		return RespVINDup
	case "04":
		return RespNotSupp
	}
	return RespNone // 0xFE
}

// infoBodiesForReport computes the info-body bytes (info type + info body
// loop) for a single report entry, applying the 3-tier override:
//  1. Report field (user)
//  2. StatusChangeTrace entry
//  3. Config-level field (auto)
//  4. Default minimal info body (none)
func infoBodiesForReport(
	cfgCustomFields string,
	cfgAlarmData *GBT32960AlarmData,
	traceCustomFields string,
	traceAlarmData *GBT32960AlarmData,
	reportCustomFields string,
	reportAlarmData *GBT32960AlarmData,
	isTransBattery bool,
) ([]byte, error) {
	// Resolve CustomFields with 3-tier override (user > trace > auto > none).
	resolvedCF := cfgCustomFields
	if traceCustomFields != "" {
		resolvedCF = traceCustomFields
	}
	if reportCustomFields != "" {
		resolvedCF = reportCustomFields
	}

	// Resolve AlarmData with 3-tier override.
	resolvedAlarm := cfgAlarmData
	if traceAlarmData != nil {
		resolvedAlarm = traceAlarmData
	}
	if reportAlarmData != nil {
		resolvedAlarm = reportAlarmData
	}

	if resolvedCF != "" {
		// CustomFields explicitly provided — emit raw hex bytes as the
		// full info-body loop. AlarmData is ignored in this path.
		raw, err := decodeHex(resolvedCF)
		if err != nil {
			return nil, err
		}
		return raw, nil
	}

	// Neither CustomFields nor AlarmData provided: emit default minimal
	// info body (design §3.2.3).
	return buildDefaultInfoBodies(isTransBattery, resolvedAlarm), nil
}

// Plan generates packet configs for a GBT32960 flow (design §5, §6).
// It emits a TCP 3-way handshake, the GBT32960 message sequence (each
// message as one PSH-ACK payload, cumulative-ACK model — no pure ACK
// between business packets), and a TCP 3-way teardown.
func (p *Planner) Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	if err := p.Validate(spec); err != nil {
		return nil, err
	}

	configChan := make(chan core.PacketConfig, 256)

	go func() {
		defer close(configChan)

		c := spec.GBT32960
		flowID := fmt.Sprintf("%s-%s-%d-%d", spec.SrcIP, spec.DstIP, spec.SrcPort, spec.DstPort)

		// --- Apply defaults (design §4.5) ---
		role := strings.ToLower(strings.TrimSpace(c.Role))
		if role == "" {
			role = "vehicle"
		}
		vinPad := byte(0x00)
		if c.VINPadByte != nil {
			vinPad = *c.VINPadByte
		}
		loginSerial := c.LoginSerialNumber
		if loginSerial == 0 {
			loginSerial = 1
		}
		logoutSerial := c.LogoutSerialNumber
		if logoutSerial == 0 {
			logoutSerial = loginSerial
		}
		subsysCount := c.RechargeableSubsysCount
		if subsysCount == 0 {
			subsysCount = 1
		}
		subsysCodeLen := c.RechargeableSubsysCodeLength
		if subsysCodeLen == 0 {
			subsysCodeLen = 1
		}
		isTransBattery := true
		if c.IsTransBatteryData != nil {
			isTransBattery = *c.IsTransBatteryData
		}
		encByte := encryptRuleByte(c.EncryptRule)

		// Resolve login/logout/report times.
		loginTime, logoutTime, reportTimes := resolveTimes(c)

		// Build the VIN/PlatformID field (17 bytes) for wire messages.
		var vinField []byte
		if role == "platform" {
			if c.PlatformID != "" {
				vinField = encodeVIN(c.PlatformID, 0x00)
			} else {
				vinField = make([]byte, VINLen)
			}
		} else {
			vinField = encodeVIN(c.VIN, vinPad)
		}

		// --- TCP setup ---
		effectiveTTL := spec.TTL
		if effectiveTTL == 0 {
			effectiveTTL = DefaultTTL
		}
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

		clientSeq := uint32(0)
		if spec.TCP != nil {
			clientSeq = spec.TCP.InitialSeq
		}
		if clientSeq == 0 {
			clientSeq = randUint32()
		}
		serverSeq := randUint32()
		winSize := uint16(65535)

		// gbtMessages collects built GBT32960 wire messages in emit order,
		// so BCC error injection can be applied by index before they go
		// on the wire (design §7.15).
		type pendingMsg struct {
			cmd       byte
			resp      byte
			data      []byte
			direction string // "up" or "down"
			built     []byte // built wire bytes (after optional BCC flip)
		}
		var msgs []pendingMsg

		// emitMsg records a GBT32960 message to be sent later.
		emitMsg := func(direction string, cmd, resp byte, data []byte) {
			msgs = append(msgs, pendingMsg{
				cmd:       cmd,
				resp:      resp,
				data:      data,
				direction: direction,
			})
		}

		// Build the message sequence according to the role's state machine.
		if role == "vehicle" {
			buildVehicleMessages(c, emitMsg, loginTime, logoutTime, reportTimes,
				loginSerial, logoutSerial, subsysCount, subsysCodeLen,
				isTransBattery)
		} else {
			buildPlatformMessages(c, emitMsg)
		}

		// Build wire bytes for each message (and apply BCC injection).
		// V24 — BCC error injection index bounds (Plan-time check).
		if c.InjectBCCError && (c.BCCErrorIndex < 0 || c.BCCErrorIndex >= len(msgs)) {
			// Out of range: the design requires Plan to surface this as
			// an error. Since Plan has already returned the channel, we
			// close it with no packets — the engine treats 0 packets as
			// a failed task. Validate should have caught this earlier;
			// this is a defensive check.
			return
		}
		for i := range msgs {
			wire := buildMessage(msgs[i].cmd, msgs[i].resp, vinField, encByte, msgs[i].data)
			if c.InjectBCCError && i == c.BCCErrorIndex {
				if flipped, err := flipBCCBit(wire); err == nil {
					wire = flipped
				}
			}
			msgs[i].built = wire
		}

		// emitTCP sends a TCP packet config to the channel.
		emitTCP := func(direction, srcMAC, dstMAC, srcIP, dstIP string, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) {
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

		// emitData sends payload as one PSH-ACK in the given direction,
		// advancing the sender's seq. (GBT32960 messages are typically
		// < 200 bytes, so no MSS segmentation is needed — V29 enforces
		// the MSS budget at Validate time.)
		emitData := func(direction string, senderSeq, peerSeq uint32, payload []byte) uint32 {
			var srcMAC, dstMAC, srcIP, dstIP string
			var srcPort, dstPort uint16
			if direction == "down" {
				srcMAC, dstMAC = spec.DstMAC, spec.SrcMAC
				srcIP, dstIP = spec.DstIP, spec.SrcIP
				srcPort, dstPort = spec.DstPort, spec.SrcPort
			} else {
				srcMAC, dstMAC = spec.SrcMAC, spec.DstMAC
				srcIP, dstIP = spec.SrcIP, spec.DstIP
				srcPort, dstPort = spec.SrcPort, spec.DstPort
			}
			emitTCP(direction, srcMAC, dstMAC, srcIP, dstIP, srcPort, dstPort,
				senderSeq, peerSeq, 0x18, payload)
			return senderSeq + uint32(len(payload))
		}

		// --- TCP handshake ---
		emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, clientSeq, 0, 0x02, nil)
		clientSeq++
		emitTCP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
			spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x12, nil)
		serverSeq++
		emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)

		// --- Emit GBT32960 messages in order ---
		// Each up message advances clientSeq; each down message advances
		// serverSeq. ACK is cumulative (peer's last seq + payload len).
		for _, m := range msgs {
			if m.direction == "up" {
				clientSeq = emitData("up", clientSeq, serverSeq, m.built)
			} else {
				serverSeq = emitData("down", serverSeq, clientSeq, m.built)
			}
		}

		// --- TCP teardown (FIN, FIN-ACK, ACK) ---
		emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x11, nil)
		clientSeq++
		emitTCP("down", spec.DstMAC, spec.SrcMAC, spec.DstIP, spec.SrcIP,
			spec.DstPort, spec.SrcPort, serverSeq, clientSeq, 0x11, nil)
		serverSeq++
		emitTCP("up", spec.SrcMAC, spec.DstMAC, spec.SrcIP, spec.DstIP,
			spec.SrcPort, spec.DstPort, clientSeq, serverSeq, 0x10, nil)
	}()

	return configChan, nil
}

// groupIDMeta 返回分组元数据。显式 group_id 优先；未配置时按 VIN
// （平台角色按 PlatformID）分组，使同一车辆会话始终路由到同一工作分片。
func groupIDMeta(spec core.FlowSpec) map[string]interface{} {
	if spec.GroupID != nil && spec.GroupID.Strategy != "" {
		if g := core.FlowGroupIDValue(spec.GroupID, 0); g != "" {
			return map[string]interface{}{"group_id": g}
		}
	}
	if spec.GBT32960 != nil {
		if spec.GBT32960.VIN != "" {
			return map[string]interface{}{"group_id": spec.GBT32960.VIN}
		}
		if spec.GBT32960.PlatformID != "" {
			return map[string]interface{}{"group_id": spec.GBT32960.PlatformID}
		}
	}
	return nil
}

// resolveTimes computes the login time, logout time, and per-report
// collect times (design §4.5). Empty times default to time.Now() and
// sequential 30s stamps.
func resolveTimes(c *GBT32960Config) (time.Time, time.Time, []time.Time) {
	var loginTime time.Time
	if c.LoginTime != "" {
		loginTime, _ = parseRFC3339Strict(c.LoginTime)
	}
	if loginTime.IsZero() {
		loginTime = time.Now()
	}

	nReports := len(c.Reports)
	reportTimes := make([]time.Time, nReports)
	for i, r := range c.Reports {
		if r.Time != "" {
			t, err := parseRFC3339Strict(r.Time)
			if err == nil {
				reportTimes[i] = t
				continue
			}
		}
		// Default: LoginTime + 30s × (i+1).
		reportTimes[i] = loginTime.Add(30 * time.Second * time.Duration(i+1))
	}

	// Logout time: explicit > LoginTime + Σ(reports interval) + 60s.
	var logoutTime time.Time
	if c.LogoutTime != "" {
		logoutTime, _ = parseRFC3339Strict(c.LogoutTime)
	}
	if logoutTime.IsZero() {
		// Σ(reports interval) ≈ 30s × N (sequential default), plus 60s.
		interval := 30 * time.Second * time.Duration(nReports)
		logoutTime = loginTime.Add(interval + 60*time.Second)
	}

	return loginTime, logoutTime, reportTimes
}

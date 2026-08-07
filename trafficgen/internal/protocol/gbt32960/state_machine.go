package gbt32960

import (
	"time"
)

// buildVehicleMessages builds the GBT32960 message sequence for the
// vehicle-side state machine (design §5.1):
//
//	ST_LOGIN_SENT → ST_LOGIN_ACKED → ST_REPORTING → ST_REMOTE_CTRL →
//	ST_REISSUE → ST_LOGOUT_SENT
//
// Order is fixed: ST_REPORTING → ST_REMOTE_CTRL → ST_REISSUE →
// ST_LOGOUT_SENT (design §5.1 状态顺序约束). 0x0C acknowledgement is
// generated after each uplink message that requires one (0x01/0x02/0x03/
// 0x04). The 0x0C header resp field is always 0xFE (design §3.12);
// success/failure is carried by the NEXT uplink message's resp field
// (controlled by Config.ResponseFlags).
//
// The vinField and encByte are pre-computed by Plan and applied at wire
// build time (after this function returns the message list).
func buildVehicleMessages(
	c *GBT32960Config,
	emitMsg func(direction string, cmd, resp byte, data []byte),
	loginTime, logoutTime time.Time,
	reportTimes []time.Time,
	loginSerial, logoutSerial, subsysCount, subsysCodeLen int,
	isTransBattery bool,
) {
	// Determine the resp byte for the "next uplink" message after the
	// login ACK. Per §3.12, ResponseFlags writes into the NEXT uplink
	// message's resp field, NOT the 0x0C header (which is always 0xFE).
	nextUplinkResp := responseFlagFromStr(c.ResponseFlags)

	// --- ST_LOGIN_SENT: emit 0x01 vehicle login (up) ---
	loginData := buildLoginData(
		loginTime,
		uint16(loginSerial),
		c.SIM,
		subsysCount,
		subsysCodeLen,
		c.RechargeableSubsysCodes,
	)
	emitMsg("up", CmdVehicleLogin, RespNone, loginData)

	// --- ST_LOGIN_ACKED: emit 0x0C platform ack (down, resp=0xFE) ---
	emitMsg("down", CmdAck, RespNone, buildAckData(CmdVehicleLogin))

	// Per §5.3异常分支: when ResponseFlags=03 (VIN duplicate), the
	// vehicle does NOT enter ST_REPORTING and does NOT proactively
	// logout — it goes directly to TCP teardown. So we skip Reports,
	// RemoteControl, Reissue, AND the 0x04 logout message.
	if c.ResponseFlags == "03" {
		return
	}

	// Per §5.3: when ResponseFlags=02 (error) or 04 (unsupported), the
	// vehicle skips ST_REPORTING AND ST_REMOTE_CTRL/ST_REISSUE, going
	// straight to ST_LOGOUT_SENT. (§5.3 lists only ST_REPORTING as
	// skipped, but §5.1's fixed order ST_REPORTING → ST_REMOTE_CTRL →
	// ST_REISSUE → ST_LOGOUT_SENT means ST_REMOTE_CTRL/ST_REISSUE are
	// also unreachable when ST_LOGIN_ACKED fails — the vehicle's session
	// is rejected, so no further business can occur.)
	skipReporting := c.ResponseFlags == "02" || c.ResponseFlags == "04"

	// consumed tracks whether nextUplinkResp has been written into a
	// emitted uplink message's resp field. Per §3.12, ResponseFlags
	// writes into the NEXT uplink message's resp field (singular) — it
	// must not leak into subsequent uplinks.
	consumed := true
	if nextUplinkResp != RespNone {
		consumed = false
	}

	// --- ST_REPORTING: emit 0x02 for each Report (up) + 0x0C (down) ---
	if !skipReporting {
		traceByIndex := buildTraceIndex(c)
		for i, r := range c.Reports {
			// 3-tier override: config > trace > report > default.
			traceCF, traceAlarm := "", (*GBT32960AlarmData)(nil)
			if sc, ok := traceByIndex[i]; ok {
				traceCF = sc.CustomFields
				traceAlarm = sc.AlarmData
			}
			infoBodies, err := infoBodiesForReport(
				c.CustomFields, c.AlarmData,
				traceCF, traceAlarm,
				r.CustomFields, r.AlarmData,
				isTransBattery,
			)
			if err != nil {
				// Should have been caught by Validate; emit minimal body.
				infoBodies = buildDefaultInfoBodies(isTransBattery, nil)
			}
			collectTime := reportTimes[i]
			reportData := buildRealtimeData(collectTime, infoBodies)
			// The first uplink after login carries the ResponseFlags
			// value (if any) as its resp field; subsequent uplinks use
			// 0xFE (normal uplink).
			resp := byte(RespNone)
			if !consumed {
				resp = nextUplinkResp
				consumed = true
			}
			emitMsg("up", CmdRealtimeReport, resp, reportData)
			emitMsg("down", CmdAck, RespNone, buildAckData(CmdRealtimeReport))
		}
	}

	// --- ST_REMOTE_CTRL: emit 0x08 (down) + 0x0C (up) ---
	// Per §5.1 order constraint: ST_REMOTE_CTRL runs AFTER ST_REPORTING
	// and BEFORE ST_REISSUE.
	if !skipReporting && c.RemoteControl != nil {
		ctrlData, err := buildControlData(c.RemoteControl)
		if err != nil {
			ctrlData = []byte{c.RemoteControl.ControlType}
		}
		emitMsg("down", CmdControl, RespNone, ctrlData)
		// Vehicle's 0x0C acknowledgement (header resp=0xFE always).
		// The RemoteControl.ResponseFlags writes into the NEXT uplink
		// message's resp field (the next 0x03 or 0x04 below).
		emitMsg("up", CmdAck, RespNone, buildAckData(CmdControl))
		// Override nextUplinkResp if RemoteControl.ResponseFlags is set;
		// mark as not-yet-consumed so the next uplink carries it.
		if c.RemoteControl.ResponseFlags != "" {
			nextUplinkResp = responseFlagFromStr(c.RemoteControl.ResponseFlags)
			consumed = false
		}
	}

	// --- ST_REISSUE: emit 0x03 for each ReissueReport (up) + 0x0C (down) ---
	// Per §5.1: ST_REISSUE runs AFTER ST_REMOTE_CTRL.
	if !skipReporting {
		for i, r := range c.ReissueReports {
			// Reissue reports do not use StatusChangeTrace (trace applies
			// to Reports only). Use the same 3-tier override but without
			// trace.
			infoBodies, err := infoBodiesForReport(
				c.CustomFields, c.AlarmData,
				"", nil,
				r.CustomFields, r.AlarmData,
				isTransBattery,
			)
			if err != nil {
				infoBodies = buildDefaultInfoBodies(isTransBattery, nil)
			}
			collectTime := reissueCollectTime(c, r, i)
			reportData := buildRealtimeData(collectTime, infoBodies)
			// The first reissue uplink may carry a deferred ResponseFlags
			// (from login ACK or RemoteControl) if not yet consumed.
			resp := byte(RespNone)
			if !consumed {
				resp = nextUplinkResp
				consumed = true
			}
			emitMsg("up", CmdReissueReport, resp, reportData)
			emitMsg("down", CmdAck, RespNone, buildAckData(CmdReissueReport))
		}
	}

	// --- ST_LOGOUT_SENT: emit 0x04 vehicle logout (up) + 0x0C (down) ---
	logoutData := buildLogoutData(logoutTime, uint16(logoutSerial))
	// If nextUplinkResp is still unconsumed (no Reports, no Reissue,
	// no RemoteControl, or skipReporting), the 0x04 carries it.
	resp := byte(RespNone)
	if !consumed {
		resp = nextUplinkResp
		consumed = true
	}
	emitMsg("up", CmdVehicleLogout, resp, logoutData)
	emitMsg("down", CmdAck, RespNone, buildAckData(CmdVehicleLogout))
}

// buildPlatformMessages builds the GBT32960 message sequence for the
// platform-side state machine (design §5.2):
//
//	ST_PLAT_LOGIN_SENT → ST_PLAT_LOGIN_ACKED → ST_HEARTBEAT → ST_LOGOUT
//
// 0x05 platform login (up, 48B data) → 0x0C ack (down) → 0x0B heartbeat
// × N (up, no ack) → 0x06 platform logout (up) → 0x0C ack (down).
func buildPlatformMessages(
	c *GBT32960Config,
	emitMsg func(direction string, cmd, resp byte, data []byte),
) {
	// --- ST_PLAT_LOGIN_SENT: emit 0x05 platform login (up) ---
	if c.PlatformLogin != nil {
		loginData := buildPlatformLoginData(c.PlatformLogin)
		emitMsg("up", CmdPlatformLogin, RespNone, loginData)
		// --- ST_PLAT_LOGIN_ACKED: emit 0x0C ack (down) ---
		emitMsg("down", CmdAck, RespNone, buildAckData(CmdPlatformLogin))
	}

	// --- ST_HEARTBEAT: emit 0x0B × N (up, no ack per §3.11) ---
	for i := 0; i < c.HeartbeatCount; i++ {
		emitMsg("up", CmdHeartbeat, RespNone, nil)
	}

	// --- ST_LOGOUT: emit 0x06 platform logout (up) + 0x0C (down) ---
	emitMsg("up", CmdPlatformLogout, RespNone, nil)
	emitMsg("down", CmdAck, RespNone, buildAckData(CmdPlatformLogout))
}

// buildTraceIndex indexes StatusChangeTrace by AtReportIndex for O(1)
// lookup during the Reports loop.
func buildTraceIndex(c *GBT32960Config) map[int]GBT32960StatusChange {
	if len(c.StatusChangeTrace) == 0 {
		return nil
	}
	m := make(map[int]GBT32960StatusChange, len(c.StatusChangeTrace))
	for _, sc := range c.StatusChangeTrace {
		m[sc.AtReportIndex] = sc
	}
	return m
}

// reissueCollectTime resolves the collect time for a reissue report.
// Reissue reports typically carry historical times (earlier than
// LoginTime); if Time is empty, default to LoginTime - 30s × (N-i).
func reissueCollectTime(c *GBT32960Config, r GBT32960Report, i int) time.Time {
	if r.Time != "" {
		t, err := parseRFC3339Strict(r.Time)
		if err == nil {
			return t
		}
	}
	// Default: historical times stepping backwards from LoginTime.
	var loginTime time.Time
	if c.LoginTime != "" {
		loginTime, _ = parseRFC3339Strict(c.LoginTime)
	}
	if loginTime.IsZero() {
		loginTime = time.Now()
	}
	n := len(c.ReissueReports)
	// i=0 → LoginTime - 30s×N; i=N-1 → LoginTime - 30s.
	offset := 30 * time.Second * time.Duration(n-i)
	return loginTime.Add(-offset)
}

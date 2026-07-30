package dhcpv6

// Scenario-mode dialog generation (RFC 8415 state-machine auto-assembly).
//
// When DHCPv6Config.Scenario is set, the planner synthesizes the full DHCPv6
// message sequence for that dialog from the RFC 8415 client/server state
// machine, with correct option chains and a shared transaction-id. The user
// supplies only the lease parameters (DefaultLeasedAddr, DefaultPreferred/
// ValidLifetime, DefaultT1/T2, ServerDUID, etc.); per-message option rules
// from RFC 8415 §21 (ClientID/ServerID/IA_NA/IAADDR/Preference/StatusCode) are
// applied automatically by buildClientServerMessage at serialization time
// (ClientID auto-prepended for client messages, ServerID auto-prepended for
// server messages and REQUEST/RENEW/RELEASE/DECLINE).
//
// Supported scenarios (design_dhcpv6.md §4):
//   sarr                — SOLICIT→ADVERTISE→REQUEST→REPLY (§4.1, 4-way)
//   sarr_rapid          — SOLICIT(+RapidCommit)→REPLY(+RapidCommit) (§4.2, 2-way)
//   renew               — RENEW→REPLY (§4.4, T1 timeout)
//   rebind              — REBIND→REPLY (§4.5, T2 timeout)
//   release             — RELEASE→REPLY (§4.6)
//   decline             — DECLINE→REPLY (§4.7, DAD conflict)
//   confirm             — CONFIRM→REPLY (§4.8, link change)
//   information_request — INFORMATION-REQUEST→REPLY (§4.3, stateless)
//   reconfigure         — RECONFIGURE→(RENEW|INFORMATION-REQUEST)→REPLY (§4.9)
//   relay               — client SOLICIT→ADVERTISE→REQUEST→REPLY, but each
//                         client/server message is wrapped in RELAY-FORW/
//                         RELAY-REPL (§4.10). Requires RelayConfig.
//
// XID handling: RFC 8415 §15.1 requires "the same transaction-id is used for
// all messages in the session" — so SOLICIT/ADVERTISE/REQUEST/REPLY share ONE
// XID. buildScenarioMessages generates a random XID per transaction group and
// sets it explicitly on every message in that group (bypassing the planner's
// auto-XID logic, which would treat REQUEST as a new transaction). Server
// replies copy the request's XID. RECONFIGURE starts a new transaction (its
// own XID), and the RENEW it triggers uses yet another XID.

import (
	"fmt"
	"net"

	"github.com/trafficgen/trafficgen/internal/core"
)

// validateScenario validates the prerequisites for a scenario. The
// synthesized messages inherit default fields from DHCPv6Config, so the
// scenario-specific requirements are checked against those defaults.
func validateScenario(cfg *core.DHCPv6Config) error {
	leased := cfg.DefaultLeasedAddr

	// Validate leased IPv6 address for scenarios that carry IA_NA.
	needsLeased := cfg.Scenario == "sarr" || cfg.Scenario == "sarr_rapid" ||
		cfg.Scenario == "renew" || cfg.Scenario == "rebind" ||
		cfg.Scenario == "release" || cfg.Scenario == "decline" ||
		cfg.Scenario == "confirm" || cfg.Scenario == "relay"
	if needsLeased {
		if leased == "" {
			return fmt.Errorf("dhcpv6: scenario %q requires default_leased_addr (leased IPv6)", cfg.Scenario)
		}
		ip := net.ParseIP(leased)
		if ip == nil || ip.To4() != nil {
			return fmt.Errorf("dhcpv6: scenario %q: default_leased_addr must be IPv6: %s", cfg.Scenario, leased)
		}
	}

	// Relay scenario requires RelayConfig.
	if cfg.Scenario == "relay" {
		if cfg.RelayConfig == nil {
			return fmt.Errorf("dhcpv6: scenario %q requires relay_config", cfg.Scenario)
		}
		if cfg.RelayConfig.RelayIP == "" {
			return fmt.Errorf("dhcpv6: scenario %q: relay_config.relay_ip is required", cfg.Scenario)
		}
		if net.ParseIP(cfg.RelayConfig.RelayIP) == nil || net.ParseIP(cfg.RelayConfig.RelayIP).To4() != nil {
			return fmt.Errorf("dhcpv6: scenario %q: relay_config.relay_ip must be IPv6: %s", cfg.Scenario, cfg.RelayConfig.RelayIP)
		}
	}

	// Scenario+Messages both set → reject (would conflict). The manual
	// Messages list is ignored in scenario mode, so a non-empty Messages
	// is a likely user mistake.
	if len(cfg.Messages) > 0 {
		return fmt.Errorf("dhcpv6: scenario %q and messages (%d) cannot both be set", cfg.Scenario, len(cfg.Messages))
	}

	switch cfg.Scenario {
	case "sarr", "sarr_rapid", "renew", "rebind", "release", "decline",
		"confirm", "information_request", "reconfigure", "relay":
		// Known scenario.
	default:
		return fmt.Errorf("dhcpv6: unknown scenario %q (want sarr/sarr_rapid/renew/rebind/release/decline/confirm/information_request/reconfigure/relay)", cfg.Scenario)
	}
	return nil
}

// buildScenarioMessages synthesizes the message sequence for the configured
// scenario. Each message carries only the per-message options that differ
// from the DHCPv6Config defaults; the planner's emit loop auto-prepends
// ClientID/ServerID at serialization time (see buildClientServerMessage), so
// the synthesized messages only need the protocol-specific options (IA_NA,
// IAADDR, Preference, StatusCode, ORO, RapidCommit, RDNSS, etc.).
//
// XID handling: RFC 8415 §15.1 requires "the same transaction-id is used for
// all messages in the session" — so SOLICIT/ADVERTISE/REQUEST/REPLY share ONE
// XID. The planner's auto-XID logic would otherwise treat REQUEST as a new
// transaction (generating a different XID), which is wrong for a single SARR
// session. To enforce the shared-XID contract, buildScenarioMessages
// generates a random XID per transaction group and sets it explicitly on
// every message in that group. Server replies copy the request's XID (also
// set explicitly to the same value). RECONFIGURE starts a new transaction
// (its own XID), and the RENEW it triggers uses yet another XID.
func buildScenarioMessages(cfg *core.DHCPv6Config) []core.DHCPv6Message {
	leased := cfg.DefaultLeasedAddr
	iaid := cfg.DefaultIAID
	if iaid == 0 {
		iaid = 1
	}
	preferred := cfg.DefaultPreferredLifetime
	if preferred == 0 {
		preferred = 3600
	}
	valid := cfg.DefaultValidLifetime
	if valid == 0 {
		valid = 7200
	}
	t1 := cfg.DefaultT1
	if t1 == 0 {
		t1 = 1800
	}
	t2 := cfg.DefaultT2
	if t2 == 0 {
		t2 = 2880
	}
	pref := cfg.DefaultPreference // default 0
	statusCode := cfg.DefaultStatusCode
	statusMsg := cfg.DefaultStatusMessage

	// IA Address sub-option bytes for the leased address (used in
	// ADVERTISE/REPLY IA_NA). preferred=3600, valid=7200 by default.
	iaAddrData := BuildIAAddress(IAAddress{
		IPv6Addr:  leased,
		Preferred: preferred,
		Valid:     valid,
	}, nil)

	// IA_NA for SOLICIT/REQUEST (T1=0, T2=0 = let server decide; no IAADDR).
	iaNASolicit := BuildIA_NA(iaid, 0, 0, nil)
	// IA_NA for ADVERTISE/REPLY (T1/T2 set + IA Address carrying leased IP).
	iaNAAssigned := BuildIA_NA(iaid, t1, t2, appendOption(nil, OptIAAddr, iaAddrData))
	// IA_NA for RENEW/REBIND/RELEASE/DECLINE/CONFIRM (carries the leased
	// address so the server knows which address to renew/release/decline).
	iaNALease := BuildIA_NA(iaid, 0, 0, appendOption(nil, OptIAAddr, iaAddrData))

	// ORO: default [RDNSS, DNSSL, SNTP]; user may override.
	oro := cfg.DefaultORO
	if oro == nil {
		oro = []uint16{OptRDNSS, OptDNSSL, OptSNTP}
	}
	oroData := BuildORO(oro)

	// Helper builders for common message shapes. Each takes an explicit XID
	// so the shared-XID contract is enforced (the planner's auto-XID logic
	// is bypassed when TransactionID is non-zero).
	solicit := func(xid [3]byte, extra ...core.DHCPv6Option) core.DHCPv6Message {
		opts := append([]core.DHCPv6Option{{Code: OptORO, Data: oroData}}, extra...)
		opts = append(opts, core.DHCPv6Option{Code: OptIANA, Data: iaNASolicit})
		return core.DHCPv6Message{MsgType: MsgTypeSolicit, TransactionID: xid, Options: opts}
	}
	advertise := func(xid [3]byte) core.DHCPv6Message {
		return core.DHCPv6Message{
			MsgType:       MsgTypeAdvertise,
			TransactionID: xid,
			Options: []core.DHCPv6Option{
				{Code: OptPreference, Data: BuildPreference(pref)},
				{Code: OptIANA, Data: iaNAAssigned},
			},
		}
	}
	request := func(xid [3]byte) core.DHCPv6Message {
		return core.DHCPv6Message{
			MsgType:       MsgTypeRequest,
			TransactionID: xid,
			Options: []core.DHCPv6Option{
				{Code: OptORO, Data: oroData},
				{Code: OptIANA, Data: iaNASolicit},
			},
		}
	}
	reply := func(xid [3]byte) core.DHCPv6Message {
		opts := []core.DHCPv6Option{{Code: OptIANA, Data: iaNAAssigned}}
		// Top-level StatusCode only when non-Success (RFC 8415 §21.13:
		// Success has no top-level status option in REPLY by default).
		if statusCode != 0 {
			opts = append(opts, core.DHCPv6Option{
				Code: OptStatusCode,
				Data: BuildStatusCode(statusCode, statusMsg),
			})
		}
		return core.DHCPv6Message{MsgType: MsgTypeReply, TransactionID: xid, Options: opts}
	}
	replyWithLease := func(xid [3]byte) core.DHCPv6Message {
		// RENEW/REBIND/RELEASE/DECLINE REPLY: server echoes the leased
		// address with updated T1/T2 (or Status=Success for release/decline).
		return core.DHCPv6Message{
			MsgType:       MsgTypeReply,
			TransactionID: xid,
			Options:       []core.DHCPv6Option{{Code: OptIANA, Data: iaNAAssigned}},
		}
	}

	switch cfg.Scenario {
	case "sarr":
		// SOLICIT → ADVERTISE → REQUEST → REPLY (§4.1, 4-way).
		// All 4 messages share ONE transaction-id (RFC 8415 §15.1).
		xid := randomXID()
		return []core.DHCPv6Message{
			solicit(xid),
			advertise(xid),
			request(xid),
			reply(xid),
		}

	case "sarr_rapid":
		// SOLICIT(+RapidCommit) → REPLY(+RapidCommit+IA_NA) (§4.2, 2-way).
		xid := randomXID()
		return []core.DHCPv6Message{
			solicit(xid, core.DHCPv6Option{Code: OptRapidCommit, Data: BuildRapidCommit()}),
			{
				MsgType:       MsgTypeReply,
				TransactionID: xid,
				Options: []core.DHCPv6Option{
					{Code: OptRapidCommit, Data: BuildRapidCommit()},
					{Code: OptIANA, Data: iaNAAssigned},
				},
			},
		}

	case "renew":
		// RENEW → REPLY (§4.4). Client sends the leased address in IA_NA;
		// server replies with updated T1/T2. New transaction-id.
		xid := randomXID()
		return []core.DHCPv6Message{
			{
				MsgType:       MsgTypeRenew,
				TransactionID: xid,
				Options: []core.DHCPv6Option{
					{Code: OptORO, Data: oroData},
					{Code: OptIANA, Data: iaNALease},
				},
			},
			replyWithLease(xid),
		}

	case "rebind":
		// REBIND → REPLY (§4.5). REBIND is multicast, NO ServerID
		// (goes to all servers). The planner does NOT auto-add ServerID
		// for REBIND (it's not in needsServerID), matching RFC 8415 §16.
		xid := randomXID()
		return []core.DHCPv6Message{
			{
				MsgType:       MsgTypeRebind,
				TransactionID: xid,
				Options: []core.DHCPv6Option{
					{Code: OptORO, Data: oroData},
					{Code: OptIANA, Data: iaNALease},
				},
			},
			replyWithLease(xid),
		}

	case "release":
		// RELEASE → REPLY (§4.6). REPLY carries Status=Success.
		xid := randomXID()
		return []core.DHCPv6Message{
			{
				MsgType:       MsgTypeRelease,
				TransactionID: xid,
				Options: []core.DHCPv6Option{
					{Code: OptIANA, Data: iaNALease},
				},
			},
			{
				MsgType:       MsgTypeReply,
				TransactionID: xid,
				Options: []core.DHCPv6Option{
					{Code: OptStatusCode, Data: BuildStatusCode(0, "Success")},
				},
			},
		}

	case "decline":
		// DECLINE → REPLY (§4.7). IA_NA carries the conflicting address;
		// REPLY carries Status=Success (server marks address unavailable).
		xid := randomXID()
		return []core.DHCPv6Message{
			{
				MsgType:       MsgTypeDecline,
				TransactionID: xid,
				Options: []core.DHCPv6Option{
					{Code: OptIANA, Data: iaNALease},
				},
			},
			{
				MsgType:       MsgTypeReply,
				TransactionID: xid,
				Options: []core.DHCPv6Option{
					{Code: OptStatusCode, Data: BuildStatusCode(0, "Success")},
				},
			},
		}

	case "confirm":
		// CONFIRM → REPLY (§4.8). CONFIRM carries all assigned addresses;
		// REPLY carries Status=Success (still on link) or NotOnLink.
		xid := randomXID()
		sc := statusCode
		if sc == 0 {
			sc = 0 // Success by default; user sets 4 for NotOnLink
		}
		return []core.DHCPv6Message{
			{
				MsgType:       MsgTypeConfirm,
				TransactionID: xid,
				Options: []core.DHCPv6Option{
					{Code: OptIANA, Data: iaNALease},
				},
			},
			{
				MsgType:       MsgTypeReply,
				TransactionID: xid,
				Options: []core.DHCPv6Option{
					{Code: OptStatusCode, Data: BuildStatusCode(sc, statusMsg)},
				},
			},
		}

	case "information_request":
		// INFORMATION-REQUEST → REPLY (§4.3, stateless). No IA_NA.
		// REPLY carries RDNSS/DNSSL/SNTP/INFO_REFRESH_TIME from defaults.
		xid := randomXID()
		replyOpts := []core.DHCPv6Option{}
		if len(cfg.DefaultDNSServers) > 0 {
			replyOpts = append(replyOpts, core.DHCPv6Option{
				Code: OptRDNSS,
				Data: BuildRDNSS(3600, cfg.DefaultDNSServers),
			})
		}
		if len(cfg.DefaultDNSSearch) > 0 {
			replyOpts = append(replyOpts, core.DHCPv6Option{
				Code: OptDNSSL,
				Data: BuildDNSSL(3600, cfg.DefaultDNSSearch),
			})
		}
		if len(cfg.DefaultSNTPServers) > 0 {
			replyOpts = append(replyOpts, core.DHCPv6Option{
				Code: OptSNTP,
				Data: BuildSNTPServers(cfg.DefaultSNTPServers),
			})
		}
		if cfg.DefaultInfoRefreshTime != 0 {
			replyOpts = append(replyOpts, core.DHCPv6Option{
				Code: OptInfoRefreshTime,
				Data: BuildInfoRefreshTime(cfg.DefaultInfoRefreshTime),
			})
		} else {
			replyOpts = append(replyOpts, core.DHCPv6Option{
				Code: OptInfoRefreshTime,
				Data: BuildInfoRefreshTime(86400),
			})
		}
		return []core.DHCPv6Message{
			{
				MsgType:       MsgTypeInformationRequest,
				TransactionID: xid,
				Options: []core.DHCPv6Option{
					{Code: OptORO, Data: BuildORO(append(oro, OptInfoRefreshTime))},
				},
			},
			{MsgType: MsgTypeReply, TransactionID: xid, Options: replyOpts},
		}

	case "reconfigure":
		// RECONFIGURE → RENEW → REPLY (§4.9). RECONFIGURE carries
		// option 19 (Reconf Msg-Type = 5 RENEW). RECONFIGURE is server-
		// initiated: it uses its own transaction-id. The RENEW it triggers
		// is a new client transaction (different XID), and REPLY copies
		// the RENEW XID.
		reconfXID := randomXID()
		renewXID := randomXID()
		return []core.DHCPv6Message{
			{
				MsgType:       MsgTypeReconfigure,
				TransactionID: reconfXID,
				Options: []core.DHCPv6Option{
					{Code: OptReconfMsg, Data: BuildReconfMsg(MsgTypeRenew)},
				},
			},
			{
				MsgType:       MsgTypeRenew,
				TransactionID: renewXID,
				Options: []core.DHCPv6Option{
					{Code: OptORO, Data: oroData},
					{Code: OptIANA, Data: iaNALease},
				},
			},
			replyWithLease(renewXID),
		}

	case "relay":
		// Relay scenario: the SARR dialog is emitted, but each client/
		// server message is wrapped in a RELAY-FORW/RELAY-REPL carrying
		// the inner message bytes in option 9. The inner messages are
		// built first (reusing the sarr logic), then wrapped.
		innerXID := randomXID()
		inner := []core.DHCPv6Message{
			solicit(innerXID),
			advertise(innerXID),
			request(innerXID),
			reply(innerXID),
		}
		// Serialize each inner message to bytes, then wrap in a relay
		// message. The wrapping requires the inner bytes as option 9 data,
		// so we build them via buildClientServerMessage. The relay messages
		// themselves don't carry transaction-ids (they use hop-count), so
		// we leave TransactionID zero on the outer relay messages.
		clientDUID := cfg.ClientDUID
		if clientDUID == nil {
			clientDUID = autoClientDUID("") // best-effort; user should set ClientDUID
		}
		serverDUID := cfg.ServerDUID
		if serverDUID == nil {
			serverDUID = autoServerDUID()
		}
		rc := cfg.RelayConfig
		hop := rc.HopCount
		if hop == 0 {
			hop = 1
		}
		var out []core.DHCPv6Message
		for _, m := range inner {
			innerBytes, err := buildClientServerMessage(m, cfg, clientDUID, serverDUID, innerXID)
			if err != nil {
				// Fall back to emitting the raw inner message (no relay wrap).
				out = append(out, m)
				continue
			}
			relayType := uint8(MsgTypeRelayForw)
			if inferDirection(m.MsgType) == "down" {
				relayType = MsgTypeRelayRepl
			}
			opts := []core.DHCPv6Option{
				{Code: OptRelayMsg, Data: BuildRelayMessage(innerBytes)},
			}
			if rc.InterfaceID != nil && relayType == MsgTypeRelayForw {
				opts = append(opts, core.DHCPv6Option{
					Code: OptInterfaceID,
					Data: BuildInterfaceID(rc.InterfaceID),
				})
			}
			out = append(out, core.DHCPv6Message{
				MsgType: relayType,
				RelayFields: &core.RelayFields{
					HopCount:    hop,
					LinkAddress: rc.RelayIP,
					PeerAddress: leased, // client link-local; user sets DefaultLeasedAddr
				},
				Options: opts,
			})
		}
		return out

	default:
		// Unreachable: validateScenario rejects unknown scenarios.
		return []core.DHCPv6Message{{MsgType: MsgTypeSolicit}}
	}
}

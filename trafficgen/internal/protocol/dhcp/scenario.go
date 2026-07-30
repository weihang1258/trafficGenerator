package dhcp

// Scenario-mode dialog generation (RFC 2131 state-machine auto-assembly).
//
// When DHCPConfig.Scenario is set, the planner synthesizes the full DHCP
// message sequence for that dialog from the RFC 2131 client/server state
// machine, with correct option chains and shared xid. The user supplies
// only the lease parameters (DefaultYourIP, DefaultServerIdentifier,
// DefaultLeaseTime, etc.); per-message option rules from RFC 2131 §4.3
// (Tables 3/4/5) are applied automatically by making each synthesized
// message self-contained (no Default* inheritance), so options that
// RFC forbids on a given message type are genuinely absent.
//
// Supported scenarios:
//   dora    — Discover→Offer→Request→ACK (§3.1)
//   nak     — Discover→Offer→Request→NAK (§4.3.2)
//   release — DORA + Release (§4.3.4)
//   inform  — Inform→ACK (§4.3.5)
//   renew   — DORA + RENEWING Request→ACK (§4.3.2)
//   rebind  — DORA + REBINDING Request→ACK (§4.3.2)

import (
	"fmt"

	"github.com/trafficgen/trafficgen/internal/core"
)

// validateScenario validates the prerequisites for a scenario. The
// synthesized messages inherit default fields from DHCPConfig, so the
// scenario-specific requirements are checked against those defaults.
func validateScenario(dhcp *core.DHCPConfig) error {
	// Validate Role (验证角色) - reuses the same rule as manual mode so
	// an invalid role is caught early.
	role := dhcp.Role
	if role == "" {
		role = "client"
	}
	if role != "client" && role != "server" && role != "relay" {
		return fmt.Errorf("invalid DHCP role: %s (must be client, server, or relay)", role)
	}

	leasedIP := dhcp.DefaultYourIP
	serverID := dhcp.DefaultServerIdentifier
	clientIP := dhcp.DefaultClientIP

	switch dhcp.Scenario {
	case "dora", "nak", "release", "renew", "rebind":
		if leasedIP == "" {
			return fmt.Errorf("scenario %q requires default_your_ip (leased IP)", dhcp.Scenario)
		}
		if serverID == "" {
			return fmt.Errorf("scenario %q requires default_server_identifier", dhcp.Scenario)
		}
	case "inform":
		if clientIP == "" {
			return fmt.Errorf("scenario %q requires default_client_ip (client IP)", dhcp.Scenario)
		}
		if serverID == "" {
			return fmt.Errorf("scenario %q requires default_server_identifier", dhcp.Scenario)
		}
	default:
		return fmt.Errorf("unknown DHCP scenario: %q (want dora/nak/release/inform/renew/rebind)", dhcp.Scenario)
	}
	return nil
}

// scenarioConfig returns a copy of dhcp with all the Default* option fields
// cleared, so synthesized messages are fully self-contained (no default
// inheritance). Non-option fields (Xid, Role, HType, HLen, BroadcastFlag,
// Secs, Sname, File, ClientMAC) are preserved because they are not
// per-message options.
func scenarioConfig(dhcp *core.DHCPConfig) *core.DHCPConfig {
	cp := *dhcp
	// Clear option-bearing defaults so synthesized messages control
	// exactly which options appear on each message type.
	cp.DefaultClientIP = ""
	cp.DefaultYourIP = ""
	cp.DefaultServerIP = ""
	cp.DefaultRelayAgentIP = ""
	cp.DefaultServerIdentifier = ""
	cp.DefaultLeaseTime = 0
	cp.DefaultT1 = 0
	cp.DefaultT2 = 0
	cp.DefaultSubnetMask = ""
	cp.DefaultRouters = nil
	cp.DefaultDNS = nil
	cp.DefaultDomainName = ""
	cp.DefaultHostname = ""
	cp.DefaultDomainSearch = nil
	cp.DefaultClientID = nil
	cp.DefaultRequestedIP = ""
	cp.DefaultParamRequestList = nil
	cp.DefaultVendorClass = ""
	cp.DefaultRelayAgentInfo = nil
	return &cp
}

// buildScenarioMessages synthesizes the message sequence for the configured
// scenario. Each message is self-contained: it carries the exact fields it
// needs, copying from DHCPConfig defaults where appropriate. Because the
// scenario planner uses scenarioConfig (cleared defaults), the emit loop
// will NOT add any options the message did not explicitly set — so RFC
// option-presence rules (e.g. NAK must not carry option 51) are enforced
// structurally.
func buildScenarioMessages(dhcp *core.DHCPConfig) []core.DHCPMessage {
	leasedIP := dhcp.DefaultYourIP
	serverID := dhcp.DefaultServerIdentifier
	clientIP := dhcp.DefaultClientIP

	// clientOpts returns the client-side options (hostname, param request
	// list, client ID, vendor class) copied from DHCPConfig defaults.
	// These appear on DISCOVER/REQUEST/INFORM when the user configured
	// them, and are absent otherwise.
	clientOpts := func(m *core.DHCPMessage) {
		if dhcp.DefaultHostname != "" {
			m.Hostname = dhcp.DefaultHostname
		}
		if len(dhcp.DefaultParamRequestList) > 0 {
			m.ParamRequestList = dhcp.DefaultParamRequestList
		}
		if len(dhcp.DefaultClientID) > 0 {
			m.ClientID = dhcp.DefaultClientID
		}
		if dhcp.DefaultVendorClass != "" {
			m.VendorClass = dhcp.DefaultVendorClass
		}
	}

	// serverOpts returns the server-side options (subnet mask, routers,
	// DNS, domain name, domain search, T1, T2) copied from DHCPConfig
	// defaults. These appear on OFFER/ACK when configured.
	serverOpts := func(m *core.DHCPMessage) {
		if dhcp.DefaultSubnetMask != "" {
			m.SubnetMask = dhcp.DefaultSubnetMask
		}
		if len(dhcp.DefaultRouters) > 0 {
			m.Routers = dhcp.DefaultRouters
		}
		if len(dhcp.DefaultDNS) > 0 {
			m.DNS = dhcp.DefaultDNS
		}
		if dhcp.DefaultDomainName != "" {
			m.DomainName = dhcp.DefaultDomainName
		}
		if len(dhcp.DefaultDomainSearch) > 0 {
			m.DomainSearch = dhcp.DefaultDomainSearch
		}
		if dhcp.DefaultT1 > 0 {
			m.T1 = dhcp.DefaultT1
		}
		if dhcp.DefaultT2 > 0 {
			m.T2 = dhcp.DefaultT2
		}
	}

	// offerAck returns a message for OFFER/ACK carrying the leased IP
	// (yiaddr), server identifier (option 54), lease time (option 51),
	// and server-side options.
	offerAck := func(msgType uint8) core.DHCPMessage {
		m := core.DHCPMessage{
			Type:             msgType,
			YourIP:           leasedIP,
			ServerIdentifier: serverID,
			LeaseTime:        dhcp.DefaultLeaseTime,
		}
		serverOpts(&m)
		return m
	}

	// informAck returns the ACK responding to INFORM: server identifier
	// + server-side options, but NO lease time, NO T1/T2, and NO yiaddr
	// (RFC §4.3.5: server MUST NOT send lease expiration time and SHOULD
	// NOT fill yiaddr).
	informAck := func() core.DHCPMessage {
		m := core.DHCPMessage{
			Type:             MsgTypeAck,
			ServerIdentifier: serverID,
		}
		// Only copy non-lease server options (subnet mask, routers,
		// DNS, domain name, domain search). T1/T2 and lease time are
		// lease-specific and must be absent.
		if dhcp.DefaultSubnetMask != "" {
			m.SubnetMask = dhcp.DefaultSubnetMask
		}
		if len(dhcp.DefaultRouters) > 0 {
			m.Routers = dhcp.DefaultRouters
		}
		if len(dhcp.DefaultDNS) > 0 {
			m.DNS = dhcp.DefaultDNS
		}
		if dhcp.DefaultDomainName != "" {
			m.DomainName = dhcp.DefaultDomainName
		}
		if len(dhcp.DefaultDomainSearch) > 0 {
			m.DomainSearch = dhcp.DefaultDomainSearch
		}
		return m
	}

	switch dhcp.Scenario {
	case "dora":
		disc := core.DHCPMessage{Type: MsgTypeDiscover}
		clientOpts(&disc)
		req := core.DHCPMessage{
			Type:             MsgTypeRequest,
			RequestedIP:      leasedIP,
			ServerIdentifier: serverID,
		}
		clientOpts(&req)
		return []core.DHCPMessage{disc, offerAck(MsgTypeOffer), req, offerAck(MsgTypeAck)}

	case "nak":
		disc := core.DHCPMessage{Type: MsgTypeDiscover}
		clientOpts(&disc)
		req := core.DHCPMessage{
			Type:             MsgTypeRequest,
			RequestedIP:      leasedIP,
			ServerIdentifier: serverID,
		}
		clientOpts(&req)
		return []core.DHCPMessage{
			disc,
			offerAck(MsgTypeOffer),
			req,
			{Type: MsgTypeNak, ServerIdentifier: serverID},
		}

	case "release":
		disc := core.DHCPMessage{Type: MsgTypeDiscover}
		clientOpts(&disc)
		req := core.DHCPMessage{
			Type:             MsgTypeRequest,
			RequestedIP:      leasedIP,
			ServerIdentifier: serverID,
		}
		clientOpts(&req)
		rel := core.DHCPMessage{
			Type:             MsgTypeRelease,
			ClientIP:         leasedIP,
			ServerIdentifier: serverID,
		}
		clientOpts(&rel)
		return []core.DHCPMessage{
			disc,
			offerAck(MsgTypeOffer),
			req,
			offerAck(MsgTypeAck),
			rel,
		}

	case "inform":
		inf := core.DHCPMessage{Type: MsgTypeInform, ClientIP: clientIP}
		clientOpts(&inf)
		return []core.DHCPMessage{inf, informAck()}

	case "renew":
		// RENEWING REQUEST: ciaddr=leased IP, NO option 50, NO option 54.
		disc := core.DHCPMessage{Type: MsgTypeDiscover}
		clientOpts(&disc)
		reqSel := core.DHCPMessage{
			Type:             MsgTypeRequest,
			RequestedIP:      leasedIP,
			ServerIdentifier: serverID,
		}
		clientOpts(&reqSel)
		reqRen := core.DHCPMessage{Type: MsgTypeRequest, ClientIP: leasedIP}
		clientOpts(&reqRen)
		return []core.DHCPMessage{
			disc,
			offerAck(MsgTypeOffer),
			reqSel,
			offerAck(MsgTypeAck),
			reqRen,
			offerAck(MsgTypeAck),
		}

	case "rebind":
		// REBINDING REQUEST: ciaddr=leased IP, NO option 50, NO option 54.
		disc := core.DHCPMessage{Type: MsgTypeDiscover}
		clientOpts(&disc)
		reqSel := core.DHCPMessage{
			Type:             MsgTypeRequest,
			RequestedIP:      leasedIP,
			ServerIdentifier: serverID,
		}
		clientOpts(&reqSel)
		reqReb := core.DHCPMessage{Type: MsgTypeRequest, ClientIP: leasedIP}
		clientOpts(&reqReb)
		return []core.DHCPMessage{
			disc,
			offerAck(MsgTypeOffer),
			reqSel,
			offerAck(MsgTypeAck),
			reqReb,
			offerAck(MsgTypeAck),
		}

	default:
		// Unreachable: validateScenario rejects unknown scenarios.
		return []core.DHCPMessage{{Type: MsgTypeDiscover}}
	}
}

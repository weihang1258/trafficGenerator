package pcapparser

import "fmt"

// wellKnownServerPorts are UDP service ports whose presence identifies the
// server side of a flow (§16.7 UDP direction hint). When a flow's first packet
// has one of these ports, that side is the server (overriding the first-packet
// guess that the src is the client).
var wellKnownServerPorts = map[uint16]bool{
	53: true,   // DNS
	67: true,   // DHCP server
	68: true,   // DHCP client (treat as server side for pairing)
	123: true,  // NTP
	161: true,  // SNMP
	162: true,  // SNMP trap
	389: true,  // LDAP
	636: true,  // LDAPS
	520: true,  // RIP
}

// updateDirection calibrates the flow's direction classification using TCP
// handshake flags or the UDP well-known-port hint (§16.7). It is called per
// packet; once calibration locks (DirStatus="classified"), subsequent calls are
// no-ops. The first-packet guess (src=client) is set in newFlowState; this
// refines it.
//
// After calibration, fs.firstSrcIP/firstSrcPort identify the CLIENT endpoint,
// so classifyDirection (which compares the current packet's src to the client)
// returns "c2s" for client->server packets and "s2c" for server->client.
func (fs *FlowState) updateDirection(f packetFields) {
	if fs.dirLocked {
		return
	}
	switch f.l4Proto {
	case "tcp":
		// SYN without ACK: src is the client (connection initiator).
		if f.tcpSYN && !f.tcpACK {
			fs.setClient(f.srcIP.String(), f.srcPort, f.dstIP.String(), f.dstPort, "syn")
			return
		}
		// SYN+ACK: src is the server, dst is the client. Corrects a first-packet
		// guess that was wrong (e.g. capture started at the SYN-ACK).
		if f.tcpSYN && f.tcpACK {
			fs.setClient(f.dstIP.String(), f.dstPort, f.srcIP.String(), f.srcPort, "syn")
			return
		}
	case "udp":
		// Well-known server port hint: if one side's port is a known service
		// port, that side is the server; the other is the client.
		if wellKnownServerPorts[f.srcPort] && !wellKnownServerPorts[f.dstPort] {
			fs.setClient(f.dstIP.String(), f.dstPort, f.srcIP.String(), f.srcPort, "port")
			return
		}
		if wellKnownServerPorts[f.dstPort] && !wellKnownServerPorts[f.srcPort] {
			fs.setClient(f.srcIP.String(), f.srcPort, f.dstIP.String(), f.dstPort, "port")
			return
		}
	}
	// No calibration signal yet: keep the first-packet guess (uncertain).
}

// setClient locks the direction classification: clientIP:clientPort is the
// client endpoint, serverIP:serverPort is the server. method is "syn" or "port".
func (fs *FlowState) setClient(clientIP string, clientPort uint16, serverIP string, serverPort uint16, method string) {
	fs.firstSrcIP = clientIP
	fs.firstSrcPort = clientPort
	fs.serverPort = serverPort // correct the L7 parser hint to the real server port
	fs.Client = fmt.Sprintf("%s:%d", clientIP, clientPort)
	fs.Server = fmt.Sprintf("%s:%d", serverIP, serverPort)
	fs.DirMethod = method
	fs.DirStatus = "classified"
	fs.dirLocked = true
}

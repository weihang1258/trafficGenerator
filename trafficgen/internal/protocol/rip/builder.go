// Package rip implements the RIP (RFC 1058 / RFC 2453 / RFC 2080 / RFC 4822) protocol planner.
package rip

import (
	"encoding/binary"
	"net"
)

// BuildRIPHeader builds the 4-byte RIP header.
// Header layout: Command(1) + Version(1) + Domain(2).
func BuildRIPHeader(command, version uint8, domain uint16) []byte {
	header := make([]byte, 4)
	header[0] = command
	header[1] = version
	binary.BigEndian.PutUint16(header[2:4], domain)
	return header
}

// BuildRIPv1Entry builds a 20-byte RIPv1 route entry.
// Layout: AFI(2) + MustBeZero(2) + IP(4) + MustBeZero(8) + Metric(4).
func BuildRIPv1Entry(route RIPRoute) []byte {
	entry := make([]byte, 20)
	binary.BigEndian.PutUint16(entry[0:2], AFIIPv4)
	// Offset 2-3: MustBeZero (already 0)
	// Offset 4-7: IP Address
	ip := net.ParseIP(route.IPAddr).To4()
	if ip != nil {
		copy(entry[4:8], ip)
	}
	// Offset 8-15: MustBeZero (v1 has no mask/next-hop)
	// Offset 16-19: Metric (4 bytes, big-endian)
	binary.BigEndian.PutUint32(entry[16:20], uint32(route.Metric))
	return entry
}

// BuildRIPv2Entry builds a 20-byte RIPv2 route entry.
// Layout: AFI(2) + RouteTag(2) + IP(4) + Mask(4) + NextHop(4) + Metric(4).
func BuildRIPv2Entry(route RIPRoute) []byte {
	entry := make([]byte, 20)
	binary.BigEndian.PutUint16(entry[0:2], AFIIPv4)
	binary.BigEndian.PutUint16(entry[2:4], route.RouteTag)

	// IP Address
	ip := net.ParseIP(route.IPAddr).To4()
	if ip != nil {
		copy(entry[4:8], ip)
	}

	// Subnet Mask
	if route.SubnetMask != "" {
		mask := net.ParseIP(route.SubnetMask).To4()
		if mask != nil {
			copy(entry[8:12], mask)
		}
	}

	// Next Hop
	if route.NextHop != "" {
		nh := net.ParseIP(route.NextHop).To4()
		if nh != nil {
			copy(entry[12:16], nh)
		}
	}

	// Metric
	binary.BigEndian.PutUint32(entry[16:20], uint32(route.Metric))
	return entry
}

// BuildRIPngEntry builds a 20-byte RIPng route entry.
// Layout: IPv6Prefix(16) + RouteTag(2) + PrefixLen(1) + Metric(1).
func BuildRIPngEntry(route RIPRoute) []byte {
	entry := make([]byte, 20)

	// IPv6 Prefix (16 bytes)
	if route.IPAddr != "" {
		ip := net.ParseIP(route.IPAddr).To16()
		if ip != nil {
			copy(entry[0:16], ip)
		}
	}

	// Route Tag (2 bytes)
	binary.BigEndian.PutUint16(entry[16:18], route.RouteTag)

	// Prefix Length (1 byte)
	entry[18] = route.PrefixLen

	// Metric (1 byte)
	entry[19] = route.Metric

	return entry
}

// BuildSimpleAuthEntry builds a 20-byte simple authentication entry.
// Layout: AFI(2)=0xFFFF + AuthType(2)=0x0002 + Password(16).
func BuildSimpleAuthEntry(password string) []byte {
	entry := make([]byte, 20)
	binary.BigEndian.PutUint16(entry[0:2], AFIAuth)
	binary.BigEndian.PutUint16(entry[2:4], AuthTypeSimple)

	// Password (up to 16 bytes, pad with zeros)
	pwdBytes := []byte(password)
	if len(pwdBytes) > 16 {
		pwdBytes = pwdBytes[:16]
	}
	copy(entry[4:20], pwdBytes)
	return entry
}

// BuildMD5AuthEntry builds a 20-byte MD5 authentication entry.
// Layout: AFI(2)=0xFFFF + AuthType(2)=0x0003 + PacketLength(2) +
// KeyID(1) + AuthDataLen(1) + SeqNum(4) + MustBeZero(8).
// entryCount includes the auth entry itself + route entries.
func BuildMD5AuthEntry(auth *RIPAuth, entryCount int) []byte {
	entry := make([]byte, 20)
	binary.BigEndian.PutUint16(entry[0:2], AFIAuth)
	binary.BigEndian.PutUint16(entry[2:4], AuthTypeMD5)

	// RIPv2 Packet Length = 4 + 20 * entryCount (regular RIPv2 packet total length)
	packetLen := uint16(4 + 20*entryCount)
	binary.BigEndian.PutUint16(entry[4:6], packetLen)

	// Key ID
	entry[6] = auth.KeyID

	// Auth Data Len (default 16 for MD5)
	authDataLen := uint8(16)
	if auth.AuthDataLen != nil {
		authDataLen = *auth.AuthDataLen
	}
	entry[7] = authDataLen

	// Sequence Number (4 bytes)
	binary.BigEndian.PutUint32(entry[8:12], auth.SequenceNumber)

	// MustBeZero (8 bytes) - already zero from make

	return entry
}

// BuildMD5Trailer builds the MD5 trailer: 4-byte header + digest placeholder.
// Trailer header: 0xFFFF (Auth Marker) + 0x0001 (Type=MD5).
// Digest: 0xAA placeholder bytes (length = AuthDataLen, default 16).
func BuildMD5Trailer(auth *RIPAuth) []byte {
	authDataLen := uint8(16)
	if auth.AuthDataLen != nil {
		authDataLen = *auth.AuthDataLen
	}

	trailer := make([]byte, 4+int(authDataLen))
	binary.BigEndian.PutUint16(trailer[0:2], AFIAuth)
	binary.BigEndian.PutUint16(trailer[2:4], MD5TrailerType)

	// Digest placeholder (0xAA) - trafficgen does not compute real HMAC
	for i := 4; i < len(trailer); i++ {
		trailer[i] = 0xAA
	}

	return trailer
}

// BuildRequestFullEntry builds the special request entry for full-route request.
// AFI=0x0000, all other fields zero, metric=16 (infinity) per RFC 2453 §3.9.1.
func BuildRequestFullEntry() []byte {
	entry := make([]byte, 20)
	binary.BigEndian.PutUint16(entry[0:2], AFIRequestFull)
	// Offset 2-15: all zeros
	binary.BigEndian.PutUint32(entry[16:20], 16) // metric = 16 (infinity)
	return entry
}

// BuildRIPPacket builds a complete RIP packet payload.
// For simple auth: header + auth_entry + route_entries.
// For MD5 auth: header + auth_entry + route_entries + trailer.
// For no auth: header + route_entries.
func BuildRIPPacket(version string, command uint8, domain uint16,
	routes []RIPRoute, auth *RIPAuth, isRequestFull bool, isFirstPacket bool) []byte {

	versionByte := getVersionByte(version)
	payload := BuildRIPHeader(command, versionByte, domain)

	// Auth entry (only on first packet)
	hasAuth := false
	requestEntry := isRequestFull && command == CommandRequest
	if isFirstPacket && auth != nil && (len(routes) > 0 || requestEntry) {
		hasAuth = true
		if auth.Type == "md5" {
			// RIPv2 Packet Length counts every 20-byte entry in the regular
			// packet, including the auth entry itself (design §2.5 / §6.8).
			entryCount := 1 + len(routes)
			if requestEntry {
				entryCount++ // the 20-byte request entry (AFI=0, metric=16)
			}
			payload = append(payload, BuildMD5AuthEntry(auth, entryCount)...)
		} else {
			payload = append(payload, BuildSimpleAuthEntry(auth.Password)...)
		}
	}

	// Route entries
	if requestEntry {
		payload = append(payload, BuildRequestFullEntry()...)
	} else {
		for _, route := range routes {
			var entry []byte
			switch version {
			case "v1":
				entry = BuildRIPv1Entry(route)
			case "v2":
				entry = BuildRIPv2Entry(route)
			case "ng":
				entry = BuildRIPngEntry(route)
			}
			payload = append(payload, entry...)
		}
	}

	// MD5 trailer (only on first packet with MD5 auth)
	if hasAuth && auth.Type == "md5" {
		trailer := BuildMD5Trailer(auth)
		payload = append(payload, trailer...)
	}

	return payload
}

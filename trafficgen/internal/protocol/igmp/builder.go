package igmp

import (
	"encoding/binary"
	"fmt"
	"net"

	"github.com/trafficgen/trafficgen/internal/core"
)

// IGMP message types (RFC 1112 v1 / RFC 2236 v2 / RFC 3376 v3).
const (
	TypeMembershipQuery    = 0x11 // v1/v2/v3 query
	TypeMembershipReportV1 = 0x12 // v1 report
	TypeMembershipReportV2 = 0x16 // v2 report
	TypeLeaveGroupV2       = 0x17 // v2 leave
	TypeMembershipReportV3 = 0x22 // v3 report
)

// v3 group record types (RFC 3376 §4.2).
const (
	RecordTypeModeIsInclude       = 1
	RecordTypeModeIsExclude       = 2
	RecordTypeChangeToIncludeMode = 3
	RecordTypeChangeToExcludeMode = 4
	RecordTypeAllowNewSources     = 5
	RecordTypeBlockOldSources     = 6
)

func recordTypeFromString(s string) (byte, error) {
	switch s {
	case "mode_is_include":
		return RecordTypeModeIsInclude, nil
	case "mode_is_exclude":
		return RecordTypeModeIsExclude, nil
	case "change_to_include_mode":
		return RecordTypeChangeToIncludeMode, nil
	case "change_to_exclude_mode":
		return RecordTypeChangeToExcludeMode, nil
	case "allow_new_sources":
		return RecordTypeAllowNewSources, nil
	case "block_old_sources":
		return RecordTypeBlockOldSources, nil
	}
	return 0, fmt.Errorf("invalid record_type %q", s)
}

// checksum computes the RFC 1071 one's complement sum over the IGMP message.
func checksum(b []byte) uint16 {
	if len(b)%2 != 0 {
		b = append(b, 0)
	}
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(b[i : i+2]))
	}
	for sum>>16 != 0 {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return uint16(^sum)
}

// igmpTypeFor maps profile+kind to the wire message type.
func igmpTypeFor(profile, kind string) (byte, error) {
	switch kind {
	case "query":
		return TypeMembershipQuery, nil
	case "report":
		switch profile {
		case "v1":
			return TypeMembershipReportV1, nil
		case "v2":
			return TypeMembershipReportV2, nil
		case "v3":
			return TypeMembershipReportV3, nil
		}
	case "leave":
		if profile == "v2" {
			return TypeLeaveGroupV2, nil
		}
	}
	return 0, fmt.Errorf("igmp: invalid profile %q / kind %q", profile, kind)
}

// buildIGMPMessage builds one IGMP message from the message-level fields.
// records is a []core.IGMPRecord (nil for non-v3-report kinds).
// checksumMode: ""|auto → correct checksum; zero → checksum field zeroed;
// invalid/bad → wrong checksum (for negative-path checksum tests).
func buildIGMPMessage(profile, kind, group string, maxRespTime, maxRespCode, sFlag, qrv, qqic int, records []core.IGMPRecord, sources []string, checksumMode string) ([]byte, error) {
	typ, err := igmpTypeFor(profile, kind)
	if err != nil {
		return nil, err
	}
	gip := net.IPv4zero.To4()
	if group != "" {
		gip = net.ParseIP(group).To4()
		if gip == nil {
			return nil, fmt.Errorf("invalid group address %q", group)
		}
	}

	var msg []byte
	switch typ {
	case TypeMembershipQuery:
		if profile == "v3" {
			hdr := make([]byte, 8)
			hdr[0] = typ
			hdr[1] = byte(maxRespCode)
			copy(hdr[4:8], gip)
			body := make([]byte, 4)
			body[0] = byte((sFlag&0x1)<<3 | (qrv & 0x7))
			body[1] = byte(qqic)
			binary.BigEndian.PutUint16(body[2:4], uint16(len(sources)))
			for _, s := range sources {
				sip := net.ParseIP(s).To4()
				if sip == nil {
					return nil, fmt.Errorf("invalid source address %q", s)
				}
				body = append(body, sip...)
			}
			msg = append(hdr, body...)
		} else {
			// v1: MaxRespTime must be 0. v2: deciseconds.
			mr := maxRespTime
			if profile == "v1" {
				mr = 0
			} else if profile == "v3" {
				mr = maxRespCode
			}
			msg = make([]byte, 8)
			msg[0] = typ
			msg[1] = byte(mr)
			copy(msg[4:8], gip)
		}
	case TypeMembershipReportV3:
		msg = make([]byte, 8)
		msg[0] = typ
		binary.BigEndian.PutUint16(msg[6:8], uint16(len(records)))
		for _, rec := range records {
			rt, err := recordTypeFromString(rec.RecordType)
			if err != nil {
				return nil, err
			}
			rg := net.ParseIP(rec.Group).To4()
			if rg == nil {
				return nil, fmt.Errorf("invalid record group %q", rec.Group)
			}
			r := make([]byte, 8)
			r[0] = rt
			r[1] = 0 // AuxDataLen
			binary.BigEndian.PutUint16(r[2:4], uint16(len(rec.Sources)))
			copy(r[4:8], rg)
			for _, s := range rec.Sources {
				sip := net.ParseIP(s).To4()
				if sip == nil {
					return nil, fmt.Errorf("invalid record source %q", s)
				}
				r = append(r, sip...)
			}
			msg = append(msg, r...)
		}
	case TypeMembershipReportV1, TypeMembershipReportV2, TypeLeaveGroupV2:
		msg = make([]byte, 8)
		msg[0] = typ
		copy(msg[4:8], gip)
	default:
		return nil, fmt.Errorf("igmp: unsupported message type 0x%x", typ)
	}

	if checksumMode != "invalid" && checksumMode != "bad" {
		// zero or auto → write correct checksum over the zeroed field.
		msg[2] = 0
		msg[3] = 0
		if checksumMode != "zero" {
			binary.BigEndian.PutUint16(msg[2:4], checksum(msg))
		}
	}
	return msg, nil
}

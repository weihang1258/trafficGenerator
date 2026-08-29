package pim

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
)

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// checksumField returns the 2-byte checksum from a built PIM message.
func checksumField(msg []byte) uint16 {
	return binary.BigEndian.Uint16(msg[2:4])
}

func TestHelloHoldtime(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{Kind: "hello", Holdtime: 105}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != (2<<4)|0 {
		t.Fatalf("byte0=%02x want 0x20 (version 2, type hello)", msg[0])
	}
	if msg[1] != 0 {
		t.Fatalf("byte1=%02x want 0 (reserved)", msg[1])
	}
	// Option 1: holdtime. Type(2) len(2) value(2) at offset 4..9.
	if msg[4] != 0 || msg[5] != 1 {
		t.Fatalf("opt type=%02x%02x want 0001 (holdtime)", msg[4], msg[5])
	}
	if msg[6] != 0 || msg[7] != 2 {
		t.Fatalf("opt len=%02x%02x want 0002", msg[6], msg[7])
	}
	if got := binary.BigEndian.Uint16(msg[8:10]); got != 105 {
		t.Fatalf("holdtime=%d want 105", got)
	}
	if checksumField(msg) == 0 {
		t.Fatal("checksum is 0, want nonzero (auto mode)")
	}
}

func TestHelloZeroHoldtime(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{Kind: "hello", Holdtime: 0}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != 0x20 {
		t.Fatalf("byte0=%02x want 0x20", msg[0])
	}
	if got := binary.BigEndian.Uint16(msg[8:10]); got != 0 {
		t.Fatalf("holdtime=%d want 0", got)
	}
}

func TestHelloOptions(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{
		Kind:         "hello",
		Holdtime:     90,
		DRPriority:   200,
		GenerationID: "0x11223344",
		LANPruneDelay: &core.PIMLANPruneDelay{
			TBit:        true,
			Propagation: 100,
			Override:    500,
		},
	}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	// LAN prune delay opt 2: type 0002, len 0004, value (0x8000|100) 500.
	off := 10 // after holdtime opt (6 bytes: 2+2+2)
	if msg[off] != 0 || msg[off+1] != 2 {
		t.Fatalf("opt type at %d = %02x%02x want 0002", off, msg[off], msg[off+1])
	}
	if msg[off+2] != 0 || msg[off+3] != 4 {
		t.Fatalf("opt len = %02x%02x want 0004", msg[off+2], msg[off+3])
	}
	prop := binary.BigEndian.Uint16(msg[off+4 : off+6])
	if prop&0x8000 == 0 {
		t.Fatal("T bit not set")
	}
	if prop&0x7fff != 100 {
		t.Fatalf("propagation=%d want 100", prop&0x7fff)
	}
	if got := binary.BigEndian.Uint16(msg[off+6 : off+8]); got != 500 {
		t.Fatalf("override=%d want 500", got)
	}
	// DR priority opt 19.
	drOff := off + 8
	if msg[drOff] != 0 || msg[drOff+1] != 19 {
		t.Fatalf("dr opt type = %02x%02x want 0013", msg[drOff], msg[drOff+1])
	}
	if got := binary.BigEndian.Uint32(msg[drOff+4 : drOff+8]); got != 200 {
		t.Fatalf("dr priority=%d want 200", got)
	}
	// Generation ID opt 20.
	genOff := drOff + 8
	if msg[genOff] != 0 || msg[genOff+1] != 20 {
		t.Fatalf("gen opt type = %02x%02x want 0014", msg[genOff], msg[genOff+1])
	}
	if got := binary.BigEndian.Uint32(msg[genOff+4 : genOff+8]); got != 0x11223344 {
		t.Fatalf("generation_id=%08x want 11223344", got)
	}
}

func TestJoinPruneSource(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{
		Kind:             "join_prune",
		UpstreamNeighbor: "192.0.2.254",
		Holdtime:         180,
		Groups: []core.PIMGroup{{
			Group:         "232.1.1.1",
			JoinedSources: []core.PIMSource{{Source: "198.51.100.10"}},
			PrunedSources: []core.PIMSource{{Source: "198.51.100.11"}},
		}},
	}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != (2<<4)|3 {
		t.Fatalf("byte0=%02x want 0x23", msg[0])
	}
	// upstream neighbor at offset 4: [01 00] + 4 IP.
	if msg[4] != 1 || msg[5] != 0 {
		t.Fatalf("upstream family=%02x%02x want 0100", msg[4], msg[5])
	}
	if string(msg[6:10]) != string([]byte{192, 0, 2, 254}) {
		t.Fatalf("upstream=% x want 192.0.2.254", msg[6:10])
	}
	// reserved, ngroups=1, holdtime=180.
	if msg[10] != 0 {
		t.Fatalf("reserved=%02x want 0", msg[10])
	}
	if msg[11] != 1 {
		t.Fatalf("ngroups=%d want 1", msg[11])
	}
	if got := binary.BigEndian.Uint16(msg[12:14]); got != 180 {
		t.Fatalf("holdtime=%d want 180", got)
	}
	// group at offset 14: [01 00 00 20] + 232.1.1.1.
	if msg[14] != 1 || msg[15] != 0 || msg[16] != 0 || msg[17] != 32 {
		t.Fatalf("group enc=% x want 01000020", msg[14:18])
	}
	if string(msg[18:22]) != string([]byte{232, 1, 1, 1}) {
		t.Fatalf("group=% x want 232.1.1.1", msg[18:22])
	}
	// njoins=1, nprunes=1 (2 bytes each).
	if got := binary.BigEndian.Uint16(msg[22:24]); got != 1 {
		t.Fatalf("njoins=%d want 1", got)
	}
	if got := binary.BigEndian.Uint16(msg[24:26]); got != 1 {
		t.Fatalf("nprunes=%d want 1", got)
	}
	// join source at offset 26: [01 00 flags=00 mask=32] + 198.51.100.10.
	if msg[26] != 1 || msg[27] != 0 || msg[28] != 0 || msg[29] != 32 {
		t.Fatalf("join src enc=% x want 01000020(flags 0)", msg[26:30])
	}
	if string(msg[30:34]) != string([]byte{198, 51, 100, 10}) {
		t.Fatalf("join src=% x", msg[30:34])
	}
}

func TestJoinPruneWildcard(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{
		Kind:             "join_prune",
		UpstreamNeighbor: "192.0.2.254",
		Holdtime:         180,
		Groups: []core.PIMGroup{{
			Group:         "239.1.1.1",
			JoinedSources: []core.PIMSource{{Wildcard: true}},
		}},
	}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	// group at 14: [01 00 00 20] + 239.1.1.1.
	// njoins=1 nprunes=0 at 22,24.
	if string(msg[18:22]) != string([]byte{239, 1, 1, 1}) {
		t.Fatalf("group=% x", msg[18:22])
	}
	if got := binary.BigEndian.Uint16(msg[22:24]); got != 1 {
		t.Fatalf("njoins=%d want 1", got)
	}
	if got := binary.BigEndian.Uint16(msg[24:26]); got != 0 {
		t.Fatalf("nprunes=%d want 0", got)
	}
	// wildcard source: flags byte 0x02 (W bit), source 0.0.0.0.
	if msg[28] != 0x02 {
		t.Fatalf("wildcard flags=%02x want 02", msg[28])
	}
	if string(msg[30:34]) != "\x00\x00\x00\x00" {
		t.Fatalf("wildcard source=% x want 00000000", msg[30:34])
	}
}

func TestBootstrap(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{
		Kind:           "bootstrap",
		BSR:            "192.0.2.10",
		BSRPriority:    128,
		HashMaskLength: 30,
		RPSets: []core.PIMRPSet{{
			GroupPrefix: "239.0.0.0/8",
			RPs: []core.PIMRP{
				{RP: "192.0.2.20", Priority: 10, Holdtime: 150},
				{RP: "192.0.2.21", Priority: 20, Holdtime: 150},
			},
		}},
	}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != (2<<4)|4 {
		t.Fatalf("byte0=%02x want 0x24", msg[0])
	}
	// fragment tag(2) hash(1) bsr_prio(1) bsr.
	if got := binary.BigEndian.Uint16(msg[4:6]); got != 1 {
		t.Fatalf("fragment_tag=%d want 1", got)
	}
	if msg[6] != 30 {
		t.Fatalf("hash_mask_len=%d want 30", msg[6])
	}
	if msg[7] != 128 {
		t.Fatalf("bsr_priority=%d want 128", msg[7])
	}
	// bsr family [01 00] at 8:9, bsr IP at 10:13.
	if msg[8] != 1 || msg[9] != 0 {
		t.Fatalf("bsr family=%02x%02x want 0100", msg[8], msg[9])
	}
	if string(msg[10:14]) != string([]byte{192, 0, 2, 10}) {
		t.Fatalf("bsr=% x want 192.0.2.10", msg[10:14])
	}
	// group set: prefix(8) + rp_count frp_count + 2 reserved.
	// prefix 239.0.0.0/8 at offset 14.
	if string(msg[18:22]) != string([]byte{239, 0, 0, 0}) {
		t.Fatalf("group prefix=% x want 239.0.0.0", msg[18:22])
	}
	if msg[22] != 2 || msg[23] != 2 {
		t.Fatalf("rp_count/frp_count=%d/%d want 2/2", msg[22], msg[23])
	}
	if msg[24] != 0 || msg[25] != 0 {
		t.Fatalf("reserved=%02x%02x want 0000", msg[24], msg[25])
	}
	// RP1 at 26: [01 00]+192.0.2.20, holdtime(2)=150, priority(1)=10, reserved(1).
	if string(msg[28:32]) != string([]byte{192, 0, 2, 20}) {
		t.Fatalf("rp1=% x want 192.0.2.20", msg[28:32])
	}
	if got := binary.BigEndian.Uint16(msg[32:34]); got != 150 {
		t.Fatalf("rp1 holdtime=%d want 150", got)
	}
	if msg[34] != 10 {
		t.Fatalf("rp1 priority=%d want 10", msg[34])
	}
	// RP2. RP1 occupies offset 26-35 (10 bytes); RP2 starts at 36.
	if string(msg[38:42]) != string([]byte{192, 0, 2, 21}) {
		t.Fatalf("rp2=% x want 192.0.2.21", msg[38:42])
	}
	if msg[44] != 20 {
		t.Fatalf("rp2 priority=%d want 20", msg[44])
	}
}

func TestCandidateRPAdv(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{
		Kind:          "candidate_rp_adv",
		RP:            "192.0.2.30",
		RPPriority:    64,
		Holdtime:      150,
		GroupPrefixes: []string{"239.0.0.0/8", "232.0.0.0/8"},
	}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != (2<<4)|8 {
		t.Fatalf("byte0=%02x want 0x28", msg[0])
	}
	if msg[4] != 2 {
		t.Fatalf("prefix_count=%d want 2", msg[4])
	}
	if msg[5] != 64 {
		t.Fatalf("priority=%d want 64", msg[5])
	}
	if got := binary.BigEndian.Uint16(msg[6:8]); got != 150 {
		t.Fatalf("holdtime=%d want 150", got)
	}
	// RP at 8: [01 00]+192.0.2.30.
	if string(msg[10:14]) != string([]byte{192, 0, 2, 30}) {
		t.Fatalf("rp=% x want 192.0.2.30", msg[10:14])
	}
	// prefix1 at 14: [01 00 00 08]+239.0.0.0, prefix2 at 22.
	if string(msg[18:22]) != string([]byte{239, 0, 0, 0}) {
		t.Fatalf("prefix1=% x", msg[18:22])
	}
	if string(msg[26:30]) != string([]byte{232, 0, 0, 0}) {
		t.Fatalf("prefix2=% x", msg[26:30])
	}
}

func TestRegister(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{
		Kind: "register",
		RegisterFlags: &core.PIMRegisterFlags{
			BorderBit:    false,
			NullRegister: false,
		},
		InnerIPv4: &core.PIMInnerIPv4{
			Src:        "198.51.100.10",
			Dst:        "239.1.1.1",
			PayloadHex: "de ad be ef",
		},
	}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != (2<<4)|1 {
		t.Fatalf("byte0=%02x want 0x21", msg[0])
	}
	if got := binary.BigEndian.Uint16(msg[2:4]); got == 0 {
		t.Fatal("register checksum is 0, want nonzero (auto mode, over 8-byte prefix)")
	}
	// flags(4) = 0.
	if got := binary.BigEndian.Uint32(msg[4:8]); got != 0 {
		t.Fatalf("register flags=%08x want 0", got)
	}
	// inner IPv4: version/IHL, total len = 20+4=24.
	if msg[8] != 0x45 {
		t.Fatalf("inner version/ihl=%02x want 45", msg[8])
	}
	if got := binary.BigEndian.Uint16(msg[10:12]); got != 24 {
		t.Fatalf("inner total len=%d want 24", got)
	}
	// inner payload: hex "deadbeef" at 28..32.
	if got := hex.EncodeToString(msg[28:32]); got != "deadbeef" {
		t.Fatalf("inner payload=%s want deadbeef", got)
	}
}

func TestRegisterFlagsBorderNull(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{
		Kind: "register",
		RegisterFlags: &core.PIMRegisterFlags{
			BorderBit:    true,
			NullRegister: true,
		},
		InnerIPv4: &core.PIMInnerIPv4{Src: "198.51.100.10", Dst: "239.1.1.1"},
	}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	got := binary.BigEndian.Uint32(msg[4:8])
	if got&regFlagBorder == 0 || got&regFlagNull == 0 {
		t.Fatalf("register flags=%08x want border+null bits set", got)
	}
}

func TestRegisterStop(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{
		Kind:   "register_stop",
		Group:  "239.1.1.1",
		Source: "198.51.100.10",
	}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != (2<<4)|2 {
		t.Fatalf("byte0=%02x want 0x22", msg[0])
	}
	// group at 4: [01 00 00 20]+239.1.1.1; source at 12: [01 00]+198.51.100.10.
	if string(msg[8:12]) != string([]byte{239, 1, 1, 1}) {
		t.Fatalf("group=% x", msg[8:12])
	}
	if string(msg[14:18]) != string([]byte{198, 51, 100, 10}) {
		t.Fatalf("source=% x", msg[14:18])
	}
}

func TestAssert(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{
		Kind:             "assert",
		Group:            "239.1.1.1",
		Source:           "198.51.100.10",
		RptBit:           true,
		MetricPreference: 10,
		RouteMetric:      100,
	}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if msg[0] != (2<<4)|5 {
		t.Fatalf("byte0=%02x want 0x25", msg[0])
	}
	// group(8) + source(6) at 4..18, then rpt/metric_pref(4) + metric(4).
	pref := binary.BigEndian.Uint32(msg[18:22])
	if pref&0x80000000 == 0 {
		t.Fatal("rpt bit not set")
	}
	if pref&0x7fffffff != 10 {
		t.Fatalf("metric_pref=%d want 10", pref&0x7fffffff)
	}
	if got := binary.BigEndian.Uint32(msg[22:26]); got != 100 {
		t.Fatalf("metric=%d want 100", got)
	}
}

func TestChecksumModeZero(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{Kind: "hello", Holdtime: 105}, "zero")
	if err != nil {
		t.Fatal(err)
	}
	if msg[2] != 0 || msg[3] != 0 {
		t.Fatalf("checksum=%02x%02x want 0000 (zero mode)", msg[2], msg[3])
	}
}

func TestChecksumModeInvalid(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{Kind: "hello", Holdtime: 105}, "invalid")
	if err != nil {
		t.Fatal(err)
	}
	// invalid/bad mode leaves the checksum field zeroed (the builder does not
	// compute a correct checksum, emitting a malformed PIM message).
	if msg[2] != 0 || msg[3] != 0 {
		t.Fatalf("checksum=%02x%02x want 0000 (invalid mode leaves zeroed)", msg[2], msg[3])
	}
}

// ---- Validate negative paths ----

func TestValidateRejectsIPv6Profile(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{PIM: &core.PIMConfig{Profile: "pim_rfc7761_ipv6_pending"}})
	if err == nil || !contains(err.Error(), "profile") {
		t.Fatalf("err=%v want profile", err)
	}
}

func TestValidateRejectsChecksumWireFault(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{PIM: &core.PIMConfig{
		Events: []core.PIMEvent{{Kind: "hello", WireFault: &core.PIMWireFault{Kind: "checksum"}}},
	}})
	if err == nil || !contains(err.Error(), "checksum") {
		t.Fatalf("err=%v want checksum", err)
	}
}

func TestValidateRejectsLengthWireFault(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{PIM: &core.PIMConfig{
		Events: []core.PIMEvent{{Kind: "hello", WireFault: &core.PIMWireFault{Kind: "length", DeclaredTotalLength: 1}}},
	}})
	if err == nil || !contains(err.Error(), "length") {
		t.Fatalf("err=%v want length", err)
	}
}

func TestValidateRejectsTypeWireFault(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{PIM: &core.PIMConfig{
		Events: []core.PIMEvent{{Kind: "hello", WireFault: &core.PIMWireFault{Kind: "type", Value: 9}}},
	}})
	if err == nil || !contains(err.Error(), "type") {
		t.Fatalf("err=%v want type", err)
	}
}

func TestValidateRejectsIPv6Address(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{PIM: &core.PIMConfig{
		Events: []core.PIMEvent{{
			Kind:             "join_prune",
			UpstreamNeighbor: "192.0.2.254",
			Groups: []core.PIMGroup{{
				Group:         "ff0e::1",
				JoinedSources: []core.PIMSource{{Source: "2001:db8::10"}},
			}},
		}},
	}})
	if err == nil || !contains(err.Error(), "address") {
		t.Fatalf("err=%v want address", err)
	}
}

func TestValidateRejectsSSMRegister(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{PIM: &core.PIMConfig{
		Profile: "pim_ssm_rfc4607_ipv4",
		Events:  []core.PIMEvent{{Kind: "register", RP: "192.0.2.100", Group: "239.1.1.1"}},
	}})
	if err == nil || !contains(err.Error(), "ssm") {
		t.Fatalf("err=%v want ssm", err)
	}
}

func TestValidateRejectsDfElection(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{PIM: &core.PIMConfig{
		Events: []core.PIMEvent{{Kind: "df_election", Neighbor: "192.0.2.2"}},
	}})
	if err == nil || !contains(err.Error(), "df") {
		t.Fatalf("err=%v want df", err)
	}
}

func TestValidateNilConfig(t *testing.T) {
	if err := (Planner{}).Validate(core.FlowSpec{}); err != nil {
		t.Fatalf("nil config: err=%v", err)
	}
}

func TestParseGenIDVariants(t *testing.T) {
	msg, err := buildMessageByKind(core.PIMEvent{Kind: "hello", Holdtime: 105, GenerationID: "0x11223344"}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	// generation_id is option 20, last option: header(4) + holdtime(6) = 10, then opt20: type(2)+len(2)+val(4).
	off := 10
	if msg[off] != 0 || msg[off+1] != 20 {
		t.Fatalf("gen opt type=%02x%02x want 0014", msg[off], msg[off+1])
	}
	if got := binary.BigEndian.Uint32(msg[off+4 : off+8]); got != 0x11223344 {
		t.Fatalf("gen=%08x", got)
	}
	// no 0x prefix
	msg2, err := buildMessageByKind(core.PIMEvent{Kind: "hello", Holdtime: 105, GenerationID: "11223344"}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(msg2[off+4 : off+8]); got != 0x11223344 {
		t.Fatalf("gen(no prefix)=%08x", got)
	}
	// invalid -> error
	if _, err := buildMessageByKind(core.PIMEvent{Kind: "hello", GenerationID: "zzz"}, "auto"); err == nil {
		t.Fatal("invalid generation_id should error")
	}
}

func TestJoinPruneEmptyGroups(t *testing.T) {
	// zero groups is a valid boundary: upstream + reserved + ngroups=0 + holdtime.
	msg, err := buildMessageByKind(core.PIMEvent{Kind: "join_prune", UpstreamNeighbor: "192.0.2.254", Holdtime: 180}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if msg[11] != 0 {
		t.Fatalf("ngroups=%d want 0", msg[11])
	}
	// total length = 4 header + 6 upstream + 1 res + 1 ngroups + 2 holdtime = 14.
	if len(msg) != 14 {
		t.Fatalf("len=%d want 14", len(msg))
	}
}

func TestJoinPruneEmptyJoinedSources(t *testing.T) {
	// a group with 0 joins / 0 prunes.
	msg, err := buildMessageByKind(core.PIMEvent{
		Kind: "join_prune", UpstreamNeighbor: "192.0.2.254", Holdtime: 180,
		Groups: []core.PIMGroup{{Group: "232.1.1.1"}},
	}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint16(msg[22:24]); got != 0 {
		t.Fatalf("njoins=%d want 0", got)
	}
	if got := binary.BigEndian.Uint16(msg[24:26]); got != 0 {
		t.Fatalf("nprunes=%d want 0", got)
	}
}

func TestValidateSSMWildcardPrune(t *testing.T) {
	err := (Planner{}).Validate(core.FlowSpec{PIM: &core.PIMConfig{
		Profile: "pim_ssm_rfc4607_ipv4",
		Events: []core.PIMEvent{{
			Kind:             "join_prune",
			UpstreamNeighbor: "192.0.2.254",
			Groups:           []core.PIMGroup{{Group: "232.1.1.1", PrunedSources: []core.PIMSource{{Wildcard: true}}}},
		}},
	}})
	if err == nil || !contains(err.Error(), "ssm") {
		t.Fatalf("err=%v want ssm", err)
	}
}

func TestRegisterInnerNil(t *testing.T) {
	// null-register with no inner packet: flags only.
	msg, err := buildMessageByKind(core.PIMEvent{Kind: "register", RegisterFlags: &core.PIMRegisterFlags{NullRegister: true}}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if got := binary.BigEndian.Uint32(msg[4:8]); got&regFlagNull == 0 {
		t.Fatalf("flags=%08x want null bit", got)
	}
	if len(msg) != 8 {
		t.Fatalf("len=%d want 8 (header+flags only)", len(msg))
	}
}

// mustSpec builds a FlowSpec the way the engine does: spec.PIM comes from the
// case's flat `pim` sub-map (strategy_convert.go case "pim").
func mustSpec(t *testing.T, cfgJSON []byte, src, dst string) core.FlowSpec {
	var w struct {
		PIM *core.PIMConfig `json:"pim"`
	}
	if err := json.Unmarshal(cfgJSON, &w); err != nil {
		t.Fatal(err)
	}
	return core.FlowSpec{SrcIP: src, DstIP: dst, PIM: w.PIM}
}

func TestNegativeCases(t *testing.T) {
	// Each case mirrors the pcap case JSON exactly (chain, src/dst, pim config).
	cases := []struct {
		id, chain, contains, src, dst string
		pim                           string // JSON of the flat `pim` object
	}{
		{"pim_neg_ipv6_profile", `[{"ip":{}},{"pim":{}}]`, "profile", "2001:db8::1", "ff02::d",
			`{"profile":"pim_rfc7761_ipv6_pending","checksum_mode":"auto","events":[{"kind":"hello","direction":"c2s","holdtime":105}]}`},
		{"pim_neg_checksum", `[{"ip":{}},{"pim":{}}]`, "checksum", "192.0.2.1", "224.0.0.13",
			`{"profile":"pim_sm_rfc7761_ipv4","checksum_mode":"auto","events":[{"kind":"hello","direction":"c2s","holdtime":105,"wire_fault":{"kind":"checksum"}}]}`},
		{"pim_neg_length", `[{"ip":{}},{"pim":{}}]`, "length", "192.0.2.1", "224.0.0.13",
			`{"profile":"pim_sm_rfc7761_ipv4","checksum_mode":"auto","events":[{"kind":"hello","direction":"c2s","holdtime":105,"wire_fault":{"kind":"length","declared_total_length":1}}]}`},
		{"pim_neg_type", `[{"ip":{}},{"pim":{}}]`, "type", "192.0.2.1", "224.0.0.13",
			`{"profile":"pim_sm_rfc7761_ipv4","checksum_mode":"auto","events":[{"kind":"hello","direction":"c2s","holdtime":105,"wire_fault":{"kind":"type","value":9}}]}`},
		{"pim_neg_address_family", `[{"ip":{}},{"pim":{}}]`, "address", "192.0.2.1", "224.0.0.13",
			`{"profile":"pim_sm_rfc7761_ipv4","checksum_mode":"auto","events":[{"kind":"join_prune","direction":"c2s","upstream_neighbor":"192.0.2.254","groups":[{"group":"ff0e::1","joined_sources":[{"source":"2001:db8::10"}],"pruned_sources":[]}]}]}`},
		{"pim_neg_ssm_rp", `[{"ip":{}},{"pim":{}}]`, "ssm", "192.0.2.1", "224.0.0.13",
			`{"profile":"pim_ssm_rfc4607_ipv4","checksum_mode":"auto","events":[{"kind":"register","direction":"c2s","rp":"192.0.2.100","group":"239.1.1.1"}]}`},
		{"pim_neg_df_profile", `[{"ip":{}},{"pim":{}}]`, "df", "192.0.2.1", "224.0.0.13",
			`{"profile":"pim_sm_rfc7761_ipv4","checksum_mode":"auto","events":[{"kind":"df_election","direction":"c2s","neighbor":"192.0.2.2"}]}`},
	}
	for _, c := range cases {
		chain, err := layers.BuildLayersPlanner("pim", json.RawMessage(c.chain))
		if err != nil {
			t.Errorf("%s: BuildLayersPlanner: %v", c.id, err)
			continue
		}
		spec := mustSpec(t, []byte(`{"pim":`+c.pim+`}`), c.src, c.dst)
		verr := chain.Validate(spec)
		if verr == nil {
			t.Errorf("%s: Validate returned nil, want error containing %q", c.id, c.contains)
			continue
		}
		if !strings.Contains(verr.Error(), c.contains) {
			t.Errorf("%s: err=%q want contains %q", c.id, verr.Error(), c.contains)
		}
	}
}

func TestGeneratorRegistered(t *testing.T) {
	g, err := layers.NewLayerGenerator("pim")
	if err != nil {
		t.Fatal(err)
	}
	if g.Name() != "pim" {
		t.Fatalf("name=%q want pim", g.Name())
	}
}

func TestValidatorRegistered(t *testing.T) {
	// protocolValidator("pim") is invoked by ChainPlanner.ValidateSpec; here we
	// exercise the registered validator through a chain planner.
	cp := layers.NewChainPlanner("pim")
	spec := core.FlowSpec{
		SrcIP: "192.0.2.1", DstIP: "224.0.0.13", TTL: 1,
		PIM: &core.PIMConfig{Profile: "pim_sm_rfc7761_ipv4", ChecksumMode: "auto",
			Events: []core.PIMEvent{{Kind: "hello", Direction: "c2s", Holdtime: 105}}},
	}
	if err := cp.Validate(spec); err != nil {
		t.Fatalf("registered validator rejected a valid spec: %v", err)
	}
}

func TestGenerateEmitsFullPacket(t *testing.T) {
	var pkt core.PacketConfig
	err := (&PIMGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "192.0.2.1", DstIP: "224.0.0.13",
			PIM: &core.PIMConfig{Profile: "pim_sm_rfc7761_ipv4", ChecksumMode: "auto",
				Events: []core.PIMEvent{{Kind: "hello", Direction: "c2s", Holdtime: 105}}},
		},
		Emit: func(p core.PacketConfig) error { pkt = p; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if pkt.L3.Protocol != core.ProtocolPIM {
		t.Fatalf("L3.Protocol=%d want 103", pkt.L3.Protocol)
	}
	if pkt.L3.SrcIP != "192.0.2.1" {
		t.Fatalf("src=%q", pkt.L3.SrcIP)
	}
	if pkt.L3.DstIP != "224.0.0.13" {
		t.Fatalf("dst=%q", pkt.L3.DstIP)
	}
	if pkt.Direction != "up" {
		t.Fatalf("dir=%q want up (c2s)", pkt.Direction)
	}
	if len(pkt.Payload) != 10 {
		t.Fatalf("payload len=%d want 10 (4 hdr + 6 holdtime opt)", len(pkt.Payload))
	}
}

func TestGenerateDownDirectionSwaps(t *testing.T) {
	// s2c → "down"; the ChainPlanner raw-IP branch swaps L3 src/dst afterwards.
	var pkt core.PacketConfig
	err := (&PIMGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{
			SrcIP: "192.0.2.1", DstIP: "224.0.0.13",
			PIM: &core.PIMConfig{Profile: "pim_sm_rfc7761_ipv4", ChecksumMode: "auto",
				Events: []core.PIMEvent{{Kind: "hello", Direction: "s2c", Holdtime: 0}}},
		},
		Emit: func(p core.PacketConfig) error { pkt = p; return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if pkt.Direction != "down" {
		t.Fatalf("dir=%q want down (s2c)", pkt.Direction)
	}
}

// TestE2EChainHello_DrivesRealChain: drive the [ip,pim] chain through the real
// ChainPlanner (as the engine does) and confirm the built frame's PIM offset-34
// bytes are 20 00 (version 2, type hello) as the case asserts.
func TestE2EChainHello(t *testing.T) {
	p, err := layers.BuildLayersPlanner("pim", json.RawMessage(`[{"ip":{}},{"pim":{}}]`))
	if err != nil {
		t.Fatal(err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: "192.0.2.1", DstIP: "224.0.0.13", TTL: 1,
		PIM: &core.PIMConfig{Profile: "pim_sm_rfc7761_ipv4", ChecksumMode: "auto",
			Events: []core.PIMEvent{{Kind: "hello", Direction: "c2s", Holdtime: 105}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := core.NewBuilder()
	var frame []byte
	for cfg := range ch {
		fb, err := b.Build(cfg)
		if err != nil {
			t.Fatal(err)
		}
		frame = fb
	}
	if len(frame) < 36 {
		t.Fatalf("frame too short: %d bytes", len(frame))
	}
	if frame[34] != 0x20 || frame[35] != 0x00 {
		t.Fatalf("offset34=%02x %02x want 20 00", frame[34], frame[35])
	}
	if frame[23] != core.ProtocolPIM {
		t.Fatalf("ip.proto=%d want 103 (at offset 23)", frame[23])
	}
	if frame[22] != 1 {
		t.Fatalf("ip.ttl=%d want 1", frame[22])
	}
}

// TestE2EChainRegisterStop: drive the chain for a register-stop and confirm the
// offset-34 bytes are 22 00 (type register-stop) and ip.proto=103.
func TestE2EChainRegisterStop(t *testing.T) {
	p, err := layers.BuildLayersPlanner("pim", json.RawMessage(`[{"ip":{}},{"pim":{}}]`))
	if err != nil {
		t.Fatal(err)
	}
	ch, err := p.Plan(context.Background(), core.FlowSpec{
		SrcIP: "192.0.2.1", DstIP: "224.0.0.13", TTL: 1,
		PIM: &core.PIMConfig{Profile: "pim_sm_rfc7761_ipv4", ChecksumMode: "auto",
			Events: []core.PIMEvent{{Kind: "register_stop", Direction: "s2c", Group: "239.1.1.1", Source: "198.51.100.10"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	b := core.NewBuilder()
	var frame []byte
	for cfg := range ch {
		fb, err := b.Build(cfg)
		if err != nil {
			t.Fatal(err)
		}
		frame = fb
		if cfg.Direction != "down" {
			t.Fatalf("register_stop s2c: direction=%q want down", cfg.Direction)
		}
	}
	if frame[23] != core.ProtocolPIM {
		t.Fatalf("ip.proto=%d want 103", frame[23])
	}
	if frame[34] != 0x22 || frame[35] != 0x00 {
		t.Fatalf("offset34=%02x %02x want 22 00", frame[34], frame[35])
	}
}

func TestGenerateEventSequence(t *testing.T) {
	evs := []core.PIMEvent{
		{Kind: "hello", Direction: "c2s", Holdtime: 105, DRPriority: 10},
		{Kind: "hello", Direction: "s2c", Holdtime: 105, DRPriority: 20},
		{Kind: "hello", Direction: "c2s", Holdtime: 105, DRPriority: 20},
	}
	var count int
	var dirs []string
	err := (&PIMGenerator{}).Generate(context.Background(), &layers.GenRequest{
		Meta: layers.FlowMeta{SrcIP: "192.0.2.1", DstIP: "224.0.0.13",
			PIM: &core.PIMConfig{Profile: "pim_sm_rfc7761_ipv4", ChecksumMode: "auto", Events: evs}},
		Emit: func(p core.PacketConfig) error { count++; dirs = append(dirs, p.Direction); return nil },
	})
	if err != nil {
		t.Fatal(err)
	}
	if count != 3 {
		t.Fatalf("emitted=%d want 3", count)
	}
	// directions c2s→up, s2c→down, c2s→up.
	if dirs[0] != "up" || dirs[1] != "down" || dirs[2] != "up" {
		t.Fatalf("dirs=%v want [up down up]", dirs)
	}
}

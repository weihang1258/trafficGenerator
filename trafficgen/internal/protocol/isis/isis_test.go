package isis

import (
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// testCfg returns a minimal valid LSP config.
func testCfg() *core.ISISConfig {
	return &core.ISISConfig{
		WireProfile:       "iso10589_ethertype",
		Level:             "l1",
		PDUType:           "lsp",
		SystemID:          "0102.0304.0506",
		LSPID:             "0102030405060000",
		RemainingLifetime: 120,
		Sequence:          1,
		ChecksumMode:      "auto",
		TLVs: []core.ISISTLV{
			{Type: 1, ValueHex: "03 49 00 01"},
			{Type: 132, ValueHex: "c0 00 02 01"},
		},
	}
}

func TestBuildLANIIHL1(t *testing.T) {
	pdu, err := buildIIH("l1", "0102.0304.0506", 30, 100, "01020304050601", []core.ISISTLV{{Type: 1, ValueHex: "03 49 00 01"}})
	if err != nil {
		t.Fatal(err)
	}
	// Common header: disc, hdr_len(=27 IIH fixed), version, id_len, pdu_type,
	// version2, resv, max_area. LI=27 so tshark's IIH subdissector fully decodes.
	want := []byte{0x83, 27, 0x01, 0x06, 0x0f, 0x01, 0x00, 0x00}
	for i, w := range want {
		if pdu[i] != w {
			t.Fatalf("common header byte %d = %02x want %02x", i, pdu[i], w)
		}
	}
	if pdu[8] != 0x01 { // circuit_type L1
		t.Fatalf("circuit_type=%02x", pdu[8])
	}
	// source_id(6) at 9-14
	if got := pdu[9:15]; string(got) != "\x01\x02\x03\x04\x05\x06" {
		t.Fatalf("source_id=%x", got)
	}
	if got := binary.BigEndian.Uint16(pdu[15:17]); got != 30 {
		t.Fatalf("holding_timer=%d", got)
	}
	if got := binary.BigEndian.Uint16(pdu[17:19]); got != 33 {
		t.Fatalf("pdu_length=%d", got)
	}
	if pdu[19] != 100 {
		t.Fatalf("priority=%d", pdu[19])
	}
	if got := pdu[20:27]; string(got) != "\x01\x02\x03\x04\x05\x06\x01" {
		t.Fatalf("lan_id=%x", got)
	}
	// TLV 1 area addresses: type=1 len=4 value=03490001
	if pdu[27] != 1 || pdu[28] != 4 {
		t.Fatalf("TLV header=%02x %02x", pdu[27], pdu[28])
	}
	if string(pdu[29:33]) != "\x03\x49\x00\x01" {
		t.Fatalf("TLV value=%x", pdu[29:33])
	}
	if len(pdu) != 33 {
		t.Fatalf("len=%d want 33", len(pdu))
	}
}

func TestBuildLANIIHL2(t *testing.T) {
	pdu, err := buildIIH("l2", "0a0b.0c0d.0e0f", 45, 64, "0a0b0c0d0e0f02", []core.ISISTLV{{Type: 1, ValueHex: "03 49 00 02"}})
	if err != nil {
		t.Fatal(err)
	}
	if pdu[4] != 0x10 { // pdu_type L2 IIH (16)
		t.Fatalf("pdu_type=%02x", pdu[4])
	}
	if pdu[8] != 0x02 { // circuit_type L2
		t.Fatalf("circuit_type=%02x", pdu[8])
	}
	if got := binary.BigEndian.Uint16(pdu[15:17]); got != 45 {
		t.Fatalf("holding_timer=%d", got)
	}
	if pdu[19] != 64 {
		t.Fatalf("priority=%d", pdu[19])
	}
	if got := binary.BigEndian.Uint16(pdu[17:19]); got != 33 {
		t.Fatalf("pdu_length=%d", got)
	}
}

func TestBuildLSPL1IPv4(t *testing.T) {
	pdu, err := buildLSP("l1", "0102030405060000", 120, 1, 0, 1,
		[]core.ISISTLV{{Type: 1, ValueHex: "03 49 00 01"}, {Type: 132, ValueHex: "c0 00 02 01"}}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if pdu[4] != 0x12 { // pdu_type L1 LSP (18)
		t.Fatalf("pdu_type=%02x", pdu[4])
	}
	if got := binary.BigEndian.Uint16(pdu[8:10]); got != 39 {
		t.Fatalf("pdu_length=%d", got)
	}
	if got := binary.BigEndian.Uint16(pdu[10:12]); got != 120 {
		t.Fatalf("remaining_lifetime=%d", got)
	}
	if got := pdu[12:20]; string(got) != "\x01\x02\x03\x04\x05\x06\x00\x00" {
		t.Fatalf("lsp_id=%x", got)
	}
	if got := binary.BigEndian.Uint32(pdu[20:24]); got != 1 {
		t.Fatalf("sequence=%d", got)
	}
	if got := binary.BigEndian.Uint16(pdu[24:26]); got == 0 {
		t.Fatalf("checksum=%d (must be nonzero)", got)
	} else if got != 0xb792 {
		t.Fatalf("checksum=%04x want b792", got)
	}
	// Type block (1 byte at 26): bit7=P partition, bits1-0=IS type (1=L1).
	if pdu[26] != 0x01 {
		t.Fatalf("type_block=%02x want 0x01 (L1)", pdu[26])
	}
	// TLV order: type 1 then 132 (type 1 at byte 27, TLV 132 at byte 33).
	if pdu[27] != 1 || pdu[33] != 132 {
		t.Fatalf("TLV order: %02x %02x", pdu[27], pdu[33])
	}
	if len(pdu) != 39 {
		t.Fatalf("len=%d want 39", len(pdu))
	}
}

func TestBuildLSPL2IPv6(t *testing.T) {
	pdu, err := buildLSP("l2", "0a0b0c0d0e0f0001", 120, 7, 0, 2,
		[]core.ISISTLV{{Type: 232, ValueHex: "20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01"}}, "auto")
	if err != nil {
		t.Fatal(err)
	}
	if pdu[4] != 0x14 { // pdu_type L2 LSP (20)
		t.Fatalf("pdu_type=%02x", pdu[4])
	}
	if got := binary.BigEndian.Uint16(pdu[8:10]); got != 45 {
		t.Fatalf("pdu_length=%d", got)
	}
	if got := pdu[12:20]; string(got) != "\x0a\x0b\x0c\x0d\x0e\x0f\x00\x01" {
		t.Fatalf("lsp_id=%x", got)
	}
	if got := binary.BigEndian.Uint32(pdu[20:24]); got != 7 {
		t.Fatalf("sequence=%d", got)
	}
	if got := binary.BigEndian.Uint16(pdu[24:26]); got == 0 {
		t.Fatalf("checksum=%d (must be nonzero)", got)
	} else if got != 0xdeea {
		t.Fatalf("checksum=%04x want deea", got)
	}
	if pdu[26] != 0x02 { // type block: IS type 2 (L2)
		t.Fatalf("type_block=%02x want 0x02 (L2)", pdu[26])
	}
	if pdu[27] != 232 {
		t.Fatalf("TLV type=%d", pdu[27])
	}
	if len(pdu) != 45 {
		t.Fatalf("len=%d want 45", len(pdu))
	}
}

func TestBuildPSNP(t *testing.T) {
	pdu, err := buildPSNP("l2", "0a0b.0c0d.0e0f", []core.ISISTLV{{Type: 9, ValueHex: "00 78 0a 0b 0c 0d 0e 0f 00 01 00 00 00 07 00 01"}})
	if err != nil {
		t.Fatal(err)
	}
	if pdu[4] != 0x1b { // pdu_type L2 PSNP (27)
		t.Fatalf("pdu_type=%02x", pdu[4])
	}
	if got := binary.BigEndian.Uint16(pdu[8:10]); got != 35 {
		t.Fatalf("pdu_length=%d", got)
	}
	if got := pdu[10:16]; string(got) != "\x0a\x0b\x0c\x0d\x0e\x0f" {
		t.Fatalf("source_id=%x", got)
	}
	if pdu[16] != 0 { // source circuit (zero)
		t.Fatalf("source_circuit=%d want 0", pdu[16])
	}
	if pdu[17] != 9 {
		t.Fatalf("TLV type=%d", pdu[17])
	}
	if len(pdu) != 35 {
		t.Fatalf("len=%d want 35", len(pdu))
	}
}

func TestBuildCSNP(t *testing.T) {
	pdu, err := buildCSNP("l1", "0102.0304.0506", "0102030405060000", "010203040506ffff",
		[]core.ISISTLV{{Type: 9, ValueHex: "00 78 01 02 03 04 05 06 00 00 00 00 00 01 00 01"}})
	if err != nil {
		t.Fatal(err)
	}
	if pdu[4] != 0x18 { // pdu_type L1 CSNP (24)
		t.Fatalf("pdu_type=%02x", pdu[4])
	}
	if got := binary.BigEndian.Uint16(pdu[8:10]); got != 51 {
		t.Fatalf("pdu_length=%d", got)
	}
	if got := pdu[10:16]; string(got) != "\x01\x02\x03\x04\x05\x06" {
		t.Fatalf("source_id=%x", got)
	}
	if pdu[16] != 0 { // source circuit (zero)
		t.Fatalf("source_circuit=%d want 0", pdu[16])
	}
	if got := pdu[17:25]; string(got) != "\x01\x02\x03\x04\x05\x06\x00\x00" {
		t.Fatalf("start_lsp_id=%x", got)
	}
	if got := pdu[25:33]; string(got) != "\x01\x02\x03\x04\x05\x06\xff\xff" {
		t.Fatalf("end_lsp_id=%x", got)
	}
	if pdu[33] != 9 {
		t.Fatalf("TLV type=%d", pdu[33])
	}
	if len(pdu) != 51 {
		t.Fatalf("len=%d want 51", len(pdu))
	}
}

func TestLLCPayloadPadding(t *testing.T) {
	// IIH PDU 33 bytes -> LLC(3)+PDU=36 -> pad to 46.
	pdu := make([]byte, 33)
	for i := range pdu {
		pdu[i] = 0x83
	}
	if got := llcPayloadLen(pdu); got != 46 {
		t.Fatalf("llcPayloadLen=%d want 46", got)
	}
	// CSNP PDU 51 bytes -> LLC+PDU=54 -> no pad.
	pdu2 := make([]byte, 51)
	if got := llcPayloadLen(pdu2); got != 54 {
		t.Fatalf("llcPayloadLen=%d want 54", got)
	}
	// padPayload produces exactly that size.
	if got := len(padPayload(pdu)); got != 46 {
		t.Fatalf("padPayload len=%d", got)
	}
}

func TestLSPFletcherChecksumVariation(t *testing.T) {
	// Checksum must change with sequence and TLV content. It does NOT change
	// with remaining lifetime, because Wireshark's osi_check_and_get_checksum
	// starts the sum at the LSP ID (offset 12), excluding pdu_length and
	// remaining lifetime (offset 8-11).
	base, _ := buildLSP("l1", "0102030405060000", 120, 1, 0, 1,
		[]core.ISISTLV{{Type: 132, ValueHex: "c0 00 02 01"}}, "auto")
	seq2, _ := buildLSP("l1", "0102030405060000", 120, 2, 0, 1,
		[]core.ISISTLV{{Type: 132, ValueHex: "c0 00 02 01"}}, "auto")
	lspID2, _ := buildLSP("l1", "0102030405060001", 120, 1, 0, 1,
		[]core.ISISTLV{{Type: 132, ValueHex: "c0 00 02 01"}}, "auto")
	if binary.BigEndian.Uint16(base[24:26]) == binary.BigEndian.Uint16(seq2[24:26]) {
		t.Fatal("checksum did not change with sequence")
	}
	if binary.BigEndian.Uint16(base[24:26]) == binary.BigEndian.Uint16(lspID2[24:26]) {
		t.Fatal("checksum did not change with lsp_id")
	}
}

// --- Negative-path Validate tests (all 12) ---

func TestValidateNegProfile(t *testing.T) {
	cfg := testCfg()
	cfg.WireProfile = "unknown_profile"
	err := validate("isis", cfg)
	if err == nil || !strings.Contains(err.Error(), "profile") {
		t.Fatalf("want error containing 'profile', got %v", err)
	}
}

func TestValidateNegIdentifier(t *testing.T) {
	cfg := testCfg()
	cfg.SystemID = "0102" // too short
	err := validate("isis", cfg)
	if err == nil || !strings.Contains(err.Error(), "system") {
		t.Fatalf("want error containing 'system', got %v", err)
	}
}

func TestValidateNegState(t *testing.T) {
	cfg := testCfg()
	cfg.PDUType = "events"
	cfg.Events = []core.ISISEvent{{
		Kind: "lsp", PDUType: "lsp", Level: "l1", SystemID: "0102.0304.0506",
		NeighborState: "Down", LSPID: "0102030405060000",
		RemainingLifetime: 120, Sequence: 1, CircuitType: 1, ChecksumMode: "auto",
	}}
	err := validate("isis", cfg)
	if err == nil || !strings.Contains(err.Error(), "state") {
		t.Fatalf("want error containing 'state', got %v", err)
	}
}

func TestValidateNegAddressFamily(t *testing.T) {
	cfg := testCfg()
	cfg.AddressProfile = "ipv4_basic"
	cfg.TLVs = []core.ISISTLV{{Type: 232, ValueHex: "20 01 0d b8 00 00 00 00 00 00 00 00 00 00 00 01"}}
	err := validate("isis", cfg)
	if err == nil || !strings.Contains(err.Error(), "address") {
		t.Fatalf("want error containing 'address', got %v", err)
	}
}

func TestValidateNegDuplicateArea(t *testing.T) {
	cfg := testCfg()
	cfg.AreaAddresses = []string{"49.0001"}
	cfg.TLVs = []core.ISISTLV{{Type: 1, ValueHex: "03 49 00 01"}}
	err := validate("isis", cfg)
	if err == nil || !strings.Contains(err.Error(), "area") {
		t.Fatalf("want error containing 'area', got %v", err)
	}
}

func TestValidateNegMixedCarrier(t *testing.T) {
	cfg := testCfg()
	cfg.WireFault = &core.ISISWireFault{Kind: "mixed_carrier"}
	err := validate("isis", cfg)
	if err == nil || !strings.Contains(err.Error(), "carrier") {
		t.Fatalf("want error containing 'carrier', got %v", err)
	}
}

func TestValidateNegHeader(t *testing.T) {
	cfg := testCfg()
	cfg.WireFault = &core.ISISWireFault{Kind: "header", HeaderLength: 7}
	err := validate("isis", cfg)
	if err == nil || !strings.Contains(err.Error(), "header") {
		t.Fatalf("want error containing 'header', got %v", err)
	}
}

func TestValidateNegLevelType(t *testing.T) {
	cfg := testCfg()
	cfg.WireFault = &core.ISISWireFault{Kind: "level_type", PDUType: 20, CircuitType: 2}
	err := validate("isis", cfg)
	if err == nil || !strings.Contains(err.Error(), "level") {
		t.Fatalf("want error containing 'level', got %v", err)
	}
}

func TestValidateNegLength(t *testing.T) {
	cfg := testCfg()
	cfg.WireFault = &core.ISISWireFault{Kind: "length", PDULength: 27}
	err := validate("isis", cfg)
	if err == nil || !strings.Contains(err.Error(), "length") {
		t.Fatalf("want error containing 'length', got %v", err)
	}
}

func TestValidateNegVendorTLV(t *testing.T) {
	cfg := testCfg()
	cfg.TLVs = []core.ISISTLV{{Type: 250, ValueHex: "00"}}
	err := validate("isis", cfg)
	if err == nil || !strings.Contains(err.Error(), "tlv") {
		t.Fatalf("want error containing 'tlv', got %v", err)
	}
}

func TestValidateNegChecksum(t *testing.T) {
	cfg := testCfg()
	cfg.WireFault = &core.ISISWireFault{Kind: "checksum"}
	err := validate("isis", cfg)
	if err == nil || !strings.Contains(err.Error(), "checksum") {
		t.Fatalf("want error containing 'checksum', got %v", err)
	}
}

func TestValidateValidLSP(t *testing.T) {
	if err := validate("isis", testCfg()); err != nil {
		t.Fatalf("valid LSP rejected: %v", err)
	}
}

func TestValidateNeighborStateUpAllowed(t *testing.T) {
	cfg := testCfg()
	cfg.PDUType = "events"
	cfg.Events = []core.ISISEvent{{
		Kind: "iih", PDUType: "lan_hello", Level: "l1", SystemID: "0102.0304.0506",
		NeighborState: "Up", HoldingTimer: 30, Priority: 64, LANID: "01020304050601",
		TLVs: []core.ISISTLV{{Type: 1, ValueHex: "03 49 00 01"}},
	}}
	if err := validate("isis", cfg); err != nil {
		t.Fatalf("Up state should be allowed: %v", err)
	}
}

// validate wraps Planner.Validate with the FlowSpec signal.
func validate(proto string, cfg *core.ISISConfig) error {
	return (Planner{}).Validate(core.FlowSpec{ISIS: cfg})
}

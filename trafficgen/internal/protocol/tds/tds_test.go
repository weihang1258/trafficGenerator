package tds

// TDS planner tests derived from design doc 09-tds-design.md (v3.0.1):
// §6 HexDump scenarios S1-S15 and §8 Validate rules. Each test asserts
// byte-level wire output against the spec'd hex sequences, and tests the
// parser round-trip.

import (
	"context"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- helpers ---

func mustPlan(t *testing.T, p *Planner, spec core.FlowSpec) []core.PacketConfig {
	t.Helper()
	ch, err := p.Plan(context.Background(), spec)
	if err != nil {
		t.Fatalf("Plan returned error: %v", err)
	}
	var out []core.PacketConfig
	for c := range ch {
		out = append(out, c)
	}
	return out
}

func tdsSpec(cfg *TDSConfig) core.FlowSpec {
	if cfg == nil {
		cfg = &TDSConfig{}
	}
	raw, _ := json.Marshal(cfg)
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 50000, DstPort: DefaultPort,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Payload: raw,
	}
}

// defaultCfg returns a config with the defaults the planner applies.
func defaultCfg() *TDSConfig {
	cfg := &TDSConfig{}
	applyDefaults(cfg)
	cfg.Sessions = []SessionSpec{{
		ID: "s1",
		Requests: []RequestSpec{{
			Type: RequestSQLBatch,
			Sql:  &SqlBatchSpec{Statements: []StatementSpec{{Text: "select 'foo' as 'bar'"}}},
		}},
	}}
	return cfg
}

func assertHex(t *testing.T, got []byte, wantHex, what string) {
	t.Helper()
	if h := hex.EncodeToString(got); h != wantHex {
		t.Fatalf("%s:\n got %s\nwant %s", what, h, wantHex)
	}
}

// upPayloads returns the "up" payloads in order.
func upPayloads(t *testing.T, pkts []core.PacketConfig) [][]byte {
	t.Helper()
	var out [][]byte
	for _, p := range pkts {
		if p.Direction == "up" && len(p.Payload) > 0 {
			out = append(out, p.Payload)
		}
	}
	return out
}

func downPayloads(t *testing.T, pkts []core.PacketConfig) [][]byte {
	t.Helper()
	var out [][]byte
	for _, p := range pkts {
		if p.Direction == "down" && len(p.Payload) > 0 {
			out = append(out, p.Payload)
		}
	}
	return out
}

// --- S1: Pre-Login (T-001..T-015) ---

func TestPreLoginDefault(t *testing.T) {
	cfg := defaultCfg()
	pkt := buildPreLoginPacket(cfg, 1)
	p, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	// A1/A2: VERSION first, TERMINATOR last.
	res, err := ParsePreLogin(p.Body)
	if err != nil {
		t.Fatalf("ParsePreLogin: %v", err)
	}
	if len(res.Options[PLVersion]) != 6 {
		t.Fatalf("VERSION data length = %d, want 6 (UL_VERSION 4B + US_SUBBUILD 2B)", len(res.Options[PLVersion]))
	}
	// A4: PL_OFFSET big-endian.
	if p.Type != TypePreLogin {
		t.Fatalf("Type = 0x%02x, want 0x12", p.Type)
	}
	// A3: Length = 8 + body.
	if p.Length != len(pkt) {
		t.Fatalf("Length = %d, want %d", p.Length, len(pkt))
	}
}

func TestPreLoginFirstOptionMustBeVersion(t *testing.T) {
	// T-003: VERSION not first → validate error.
	opts := []PreLoginOption{
		{Token: PLEncryption, Data: []byte{0}},
		{Token: PLVersion, Data: make([]byte, 6)}, // 6B = UL_VERSION(4) + US_SUBBUILD(2)
	}
	pkt := BuildPreLogin(opts, StatusEOM, 0, 1)
	p, _ := ParsePacket(pkt)
	if _, err := ParsePreLogin(p.Body); err == nil {
		t.Fatalf("expected error when VERSION is not the first option")
	}
}

func TestPreLoginMissingTerminator(t *testing.T) {
	// T-004: no TERMINATOR at end → error. Build an option table with
	// a trailing option so the terminator is not last.
	opts := []PreLoginOption{
		{Token: PLVersion, Data: make([]byte, 6)}, // 6B = UL_VERSION(4) + US_SUBBUILD(2)
		{Token: PLEncryption, Data: []byte{0}},
	}
	pkt := BuildPreLogin(opts, StatusEOM, 0, 1)
	p, _ := ParsePacket(pkt)
	// BuildPreLogin always appends the terminator; manually strip it.
	body := p.Body[:len(p.Body)-1]
	if _, err := ParsePreLogin(body); err == nil {
		t.Fatalf("expected error when TERMINATOR missing")
	}
}

func TestPreLoginEncryptionOn(t *testing.T) {
	// T-005: ENCRYPT_ON.
	cfg := defaultCfg()
	cfg.EncryptMode = EncryptOn
	pkt := buildPreLoginPacket(cfg, 1)
	p, _ := ParsePacket(pkt)
	res, _ := ParsePreLogin(p.Body)
	if res.Options[PLEncryption][0] != EncryptOn {
		t.Fatalf("encryption data = 0x%02x, want 0x01", res.Options[PLEncryption][0])
	}
}

func TestPreLoginMars(t *testing.T) {
	// T-012/T-013.
	cfg := defaultCfg()
	cfg.MarsEnabled = true
	pkt := buildPreLoginPacket(cfg, 1)
	p, _ := ParsePacket(pkt)
	res, _ := ParsePreLogin(p.Body)
	if res.Options[PLMARS][0] != 1 {
		t.Fatalf("MARS data = 0x%02x, want 0x01", res.Options[PLMARS][0])
	}
	cfg.MarsEnabled = false
	pkt = buildPreLoginPacket(cfg, 1)
	p, _ = ParsePacket(pkt)
	res, _ = ParsePreLogin(p.Body)
	if res.Options[PLMARS][0] != 0 {
		t.Fatalf("MARS data = 0x%02x, want 0x00", res.Options[PLMARS][0])
	}
}

func TestPreLoginResponseMissingVersion(t *testing.T) {
	// T-015: server PRELOGIN response missing VERSION → structural error.
	opts := []PreLoginOption{
		{Token: PLEncryption, Data: []byte{0}},
	}
	pkt := BuildPreLogin(opts, StatusEOM, 0, 1)
	p, _ := ParsePacket(pkt)
	if _, err := ParsePreLogin(p.Body); err == nil {
		t.Fatalf("expected error for missing VERSION")
	}
}

// --- S2: Login7 (T-016..T-040) ---

func TestLogin7VersionWire(t *testing.T) {
	// T-016: 7.4 wire = 04 00 00 74 (BE 编码常量 0x04000074)。
	// TDSVersion 为大端网络序 (spec footnote 72 + MS-TDS 4.2/4.4 示例)。
	cfg := defaultCfg()
	cfg.Version = TDSVersion74
	pkt := buildLogin7Packet(cfg)
	p, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	// TDSVersion at body offset 4..8.
	if hex.EncodeToString(p.Body[4:8]) != "04000074" {
		t.Fatalf("TDSVersion wire = %s, want 04000074", hex.EncodeToString(p.Body[4:8]))
	}
	// T-017..T-019: 版本切换——常量值以 BE 编码上线路。
	cfg.Version = TDSVersion71
	pkt = buildLogin7Packet(cfg)
	p, _ = ParsePacket(pkt)
	if hex.EncodeToString(p.Body[4:8]) != "00000071" {
		t.Fatalf("7.1 wire = %s, want 00000071", hex.EncodeToString(p.Body[4:8]))
	}
	cfg.Version = TDSVersion72
	pkt = buildLogin7Packet(cfg)
	p, _ = ParsePacket(pkt)
	// MS-TDS 4.2 示例: 02 00 09 72。
	if hex.EncodeToString(p.Body[4:8]) != "02000972" {
		t.Fatalf("7.2 wire = %s, want 02000972", hex.EncodeToString(p.Body[4:8]))
	}
	cfg.Version = TDSVersion73A
	pkt = buildLogin7Packet(cfg)
	p, _ = ParsePacket(pkt)
	if hex.EncodeToString(p.Body[4:8]) != "03000a73" {
		t.Fatalf("7.3 wire = %s, want 03000a73", hex.EncodeToString(p.Body[4:8]))
	}
}

func TestLogin7Length(t *testing.T) {
	// T-020: Length = body bytes.
	cfg := defaultCfg()
	pkt := buildLogin7Packet(cfg)
	p, _ := ParsePacket(pkt)
	wantBody := binary.LittleEndian.Uint32(p.Body[0:4])
	if int(wantBody) != len(p.Body) {
		t.Fatalf("LOGIN7 Length = %d, want %d", wantBody, len(p.Body))
	}
	if p.Length != len(pkt) {
		t.Fatalf("packet Length = %d, want %d", p.Length, len(pkt))
	}
}

func TestLogin7Fields(t *testing.T) {
	// T-023..T-028: host/user/password/app fields round-trip.
	cfg := defaultCfg()
	cfg.ClientName = "host1"
	cfg.UserName = "sa"
	cfg.AppName = "trafficgen"
	cfg.Database = "testdb"
	pkt := buildLogin7Packet(cfg)
	p, _ := ParsePacket(pkt)
	res, err := ParseLogin7(p.Body)
	if err != nil {
		t.Fatalf("ParseLogin7: %v", err)
	}
	if res.HostName != "host1" {
		t.Fatalf("HostName = %q, want host1", res.HostName)
	}
	if res.UserName != "sa" {
		t.Fatalf("UserName = %q, want sa", res.UserName)
	}
	if res.AppName != "trafficgen" {
		t.Fatalf("AppName = %q, want trafficgen", res.AppName)
	}
	if res.Database != "testdb" {
		t.Fatalf("Database = %q, want testdb", res.Database)
	}
}

func TestLogin7PasswordObfuscation(t *testing.T) {
	// T-025/T-027: obfuscation is invertible (swap nibbles then XOR 0xA5).
	pw := "password"
	ucs := encodeUTF16(pw)
	obf := obfuscatePassword(pw)
	if len(obf) != len(ucs) {
		t.Fatalf("obfuscated length = %d, want %d", len(obf), len(ucs))
	}
	// Reverse: XOR 0xA5 then swap nibbles — must equal the original UCS-2.
	inv := make([]byte, len(obf))
	for i, b := range obf {
		x := b ^ 0xA5
		inv[i] = (x << 4) | (x >> 4)
	}
	if !bytesEqual(inv, ucs) {
		t.Fatalf("obfuscation not invertible: inv=%x ucs=%x", inv, ucs)
	}
	// Round-trip via full parse: the parsed password equals the obfuscated
	// bytes for the UCS-2 "password".
	cfg := defaultCfg()
	cfg.Password = pw
	pkt := buildLogin7Packet(cfg)
	p, _ := ParsePacket(pkt)
	res, _ := ParseLogin7(p.Body)
	if !bytesEqual(res.Password, obf) {
		t.Fatalf("parsed password = %x, want %x", res.Password, obf)
	}
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestLogin7OffsetTable(t *testing.T) {
	// T-030: offset table 58B; ibHostName = 94 = 0x5E.
	cfg := defaultCfg()
	pkt := buildLogin7Packet(cfg)
	p, _ := ParsePacket(pkt)
	ibHost := binary.LittleEndian.Uint16(p.Body[36:38])
	if ibHost != 0x5E {
		t.Fatalf("ibHostName = 0x%04x, want 0x005E", ibHost)
	}
	// ibUserName follows ibHostName + len(hostUCS). defaultCfg sets
	// ClientName="trafficgen-host" (16 chars = 32B UCS-2).
	hostLen := len(encodeUTF16(cfg.ClientName))
	ibUser := binary.LittleEndian.Uint16(p.Body[40:42])
	if int(ibUser) != int(ibHost)+hostLen {
		t.Fatalf("ibUserName = 0x%04x, want 0x%04x", ibUser, ibHost+uint16(hostLen))
	}
}

func TestLogin7ClientLCID(t *testing.T) {
	// T-031/T-032 basics: OptionFlags1=0xE0, LCID=0x0409.
	cfg := defaultCfg()
	cfg.ClientLCID = 0x0409
	pkt := buildLogin7Packet(cfg)
	p, _ := ParsePacket(pkt)
	if p.Body[24] != 0xE0 {
		t.Fatalf("OptionFlags1 = 0x%02x, want 0xE0", p.Body[24])
	}
	if hex.EncodeToString(p.Body[32:36]) != "09040000" {
		t.Fatalf("ClientLCID = %s, want 09040000", hex.EncodeToString(p.Body[32:36]))
	}
}

// --- S3: SQL Batch (T-041..T-065) ---

func TestSQLBatchAllHeaders(t *testing.T) {
	// T-041..T-043: ALL_HEADERS TotalLength=22, HeaderType=0x0002,
	// TransactionDescriptor=0, OutstandingRequestCount=1 (AutoCommit).
	body := BuildSQLBatch("select 'foo' as 'bar'", true, 0, 1, StatusEOM, 0, 1)
	p, err := ParsePacket(body)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	ah, err := ParseAllHeaders(p.Body)
	if err != nil {
		t.Fatalf("ParseAllHeaders: %v", err)
	}
	if ah.TransactionDescriptor != 0 {
		t.Fatalf("TransactionDescriptor = %d, want 0", ah.TransactionDescriptor)
	}
	if ah.OutstandingCount != 1 {
		t.Fatalf("OutstandingRequestCount = %d, want 1", ah.OutstandingCount)
	}
	if len(ah.HeaderTypes) != 1 || ah.HeaderTypes[0] != HeaderTransactionDescriptor {
		t.Fatalf("header types = %v, want [2]", ah.HeaderTypes)
	}
	// TotalLength check: 4 + 18 = 22.
	if binary.LittleEndian.Uint32(p.Body[0:4]) != 22 {
		t.Fatalf("ALL_HEADERS TotalLength = %d, want 22", binary.LittleEndian.Uint32(p.Body[0:4]))
	}
}

func TestSQLBatchText(t *testing.T) {
	// T-041: SQLText UCS-2 round-trip.
	body := BuildSQLBatch("select 1", true, 0, 1, StatusEOM, 0, 1)
	p, _ := ParsePacket(body)
	sqlText, err := ParseSQLBatch(p.Body, true)
	if err != nil {
		t.Fatalf("ParseSQLBatch: %v", err)
	}
	if sqlText != "select 1" {
		t.Fatalf("SQLText = %q, want \"select 1\"", sqlText)
	}
}

func TestSQLBatchAutoCommit(t *testing.T) {
	// T-043: AutoCommit outstanding=1, TransactionDescriptor=0.
	cfg := defaultCfg()
	pkts := mustPlan(t, &Planner{}, tdsSpec(cfg))
	ups := upPayloads(t, pkts)
	// Find the SQL batch packet (Type=0x01).
	var found []byte
	for _, p := range ups {
		if len(p) > 0 && p[0] == TypeSQLBatch {
			found = p
			break
		}
	}
	if found == nil {
		t.Fatalf("no SQL batch packet found")
	}
	p, _ := ParsePacket(found)
	ah, _ := ParseAllHeaders(p.Body)
	if ah.OutstandingCount != 1 {
		t.Fatalf("outstanding = %d, want 1", ah.OutstandingCount)
	}
}

// --- S4/S5: DML & multi-result-set responses ---

func TestDoneRowCount8B(t *testing.T) {
	// T-046/T-208: DONE row count 8B; 5e9 = 0x12A05F200, 8B LE = 00 F2 05 2A 01 00 00 00.
	done, err := BuildDone(TokenDone, DONECount, 0, 5000000000, true)
	if err != nil {
		t.Fatalf("BuildDone: %v", err)
	}
	// 布局: token(1B FD) + status(2B LE 10 00) + curCmd(2B LE 00 00)
	// + rowCount(8B LE 00 F2 05 2A 01 00 00 00) = 13B。
	// 修复断言错误: 此前 want 误写为 14B (`fd10000000f2052a0100000000`)，
	// 多了 1 字节零；BuildDone 实际输出 13B。
	want := "fd1000000000f2052a01000000"
	if hex.EncodeToString(done) != want {
		t.Fatalf("DONE = %s, want %s", hex.EncodeToString(done), want)
	}
}

func TestDoneRowCount4B(t *testing.T) {
	// T-047: 7.1 uses 4B row count.
	done, _ := BuildDone(TokenDone, DONECount, 0, 5, false)
	if len(done) != 1+2+2+4 {
		t.Fatalf("7.1 DONE length = %d, want 9", len(done))
	}
}

func TestMultiResultSet(t *testing.T) {
	// T-081..T-085: 3 statements → 3 result sets, first two DONE with
	// DONE_MORE, last DONE without.
	var tokens []byte
	for i := 0; i < 3; i++ {
		cm := BuildColMetadata([]ColMetadataColumn{
			{UserType: 0, Flags: 0, TypeInfo: []byte{TypeInt4}, ColName: "c"},
		}, false)
		tokens = append(tokens, cm...)
		val := make([]byte, 4)
		binary.LittleEndian.PutUint32(val, uint32(i+1))
		tokens = append(tokens, BuildRow(val)...)
		status := uint16(DONECount)
		if i < 2 {
			status |= DONEMore
		}
		done, _ := BuildDone(TokenDone, status, 0, 1, true)
		tokens = append(tokens, done...)
	}
	res, err := ParseResponse(tokens, true, TDSVersion74)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if len(res.Dones) != 3 {
		t.Fatalf("DONE count = %d, want 3", len(res.Dones))
	}
	if res.Dones[0].Status != DONECount|DONEMore {
		t.Fatalf("DONE[0] status = 0x%04x, want 0x11", res.Dones[0].Status)
	}
	if res.Dones[1].Status != DONECount|DONEMore {
		t.Fatalf("DONE[1] status = 0x%04x, want 0x11", res.Dones[1].Status)
	}
	if res.Dones[2].Status != DONECount {
		t.Fatalf("DONE[2] status = 0x%04x, want 0x10", res.Dones[2].Status)
	}
	if res.RowCount != 3 {
		t.Fatalf("RowCount = %d, want 3", res.RowCount)
	}
}

func TestParseResponseResetsColsAfterDone(t *testing.T) {
	// T-091: DONE resets column context; a ROW after DONE without a new
	// COLMETADATA produces a parse error (cells cannot be sized without
	// column metadata).
	tokens := BuildColMetadata([]ColMetadataColumn{{TypeInfo: []byte{TypeInt4}}}, false)
	done, _ := BuildDone(TokenDone, DONECount, 0, 1, true)
	tokens = append(tokens, done...)
	tokens = append(tokens, BuildRow([]byte{1, 0, 0, 0})...)
	if _, err := ParseResponse(tokens, true, TDSVersion74); err == nil {
		t.Fatalf("expected error for ROW without COLMETADATA after DONE")
	}
}

// --- S6/S7: RPC (T-096..T-135) ---

func TestRPCProcIDShortForm(t *testing.T) {
	// T-096: FF FF 0A 00 for sp_executesql (ProcID=10).
	pid := uint16(10)
	nameID, err := BuildRPCNameProcID("", &pid)
	if err != nil {
		t.Fatalf("BuildRPCNameProcID: %v", err)
	}
	assertHex(t, nameID, "ffff0a00", "ProcID short form")
}

func TestRPCProcNameLongForm(t *testing.T) {
	// T-097/T-116: US_VARCHAR "foo3" = 04 00 66 00 6F 00 6F 00 33 00.
	nameID, err := BuildRPCNameProcID("foo3", nil)
	if err != nil {
		t.Fatalf("BuildRPCNameProcID: %v", err)
	}
	assertHex(t, nameID, "040066006f006f003300", "ProcName long form")
}

func TestRPCProcIDExclusive(t *testing.T) {
	// V-23/V-24: both set → error.
	pid := uint16(10)
	if _, err := BuildRPCNameProcID("foo3", &pid); err == nil {
		t.Fatalf("expected error when ProcName and ProcID both set")
	}
}

func TestRPCParamVarchar(t *testing.T) {
	// T-099: @stmt "SELECT 1" as BigVarChar: A7 08 00 + collation +
	// 08 00 + ASCII.
	v := "SELECT 1"
	ml := 8
	p := ParamSpec{Name: "@stmt", Type: "varchar", MaxLen: &ml, Value: &v}
	param, err := BuildRPCParam(p)
	if err != nil {
		t.Fatalf("BuildRPCParam: %v", err)
	}
	// ParamName B_VARCHAR "@stmt" = 05 + UCS2 (5 chars × 2B = 10B).
	name := param[:11]
	assertHex(t, name, "054000730074006d007400", "param name")
	// StatusFlags = 00.
	if param[11] != 0 {
		t.Fatalf("StatusFlags = 0x%02x, want 0", param[11])
	}
	// TYPE_INFO: A7 08 00 09 04 D0 00 34.
	assertHex(t, param[12:20], "a708000904d00034", "TYPE_INFO")
	// Data: 08 00 53 45 4C 45 43 54 20 31.
	assertHex(t, param[20:], "080053454c4543542031", "param data")
}

func TestRPCParamStatusFlags(t *testing.T) {
	// T-107/T-108: fDefaultValue=0x02, fByRefValue=0x01.
	if f := BuildRPCParamStatusFlags(false, true, false); f != 0x02 {
		t.Fatalf("defaultValue flags = 0x%02x, want 0x02", f)
	}
	if f := BuildRPCParamStatusFlags(true, false, false); f != 0x01 {
		t.Fatalf("byRef flags = 0x%02x, want 0x01", f)
	}
}

func TestRPCParamNullIntN(t *testing.T) {
	// T-109/T-111: INTNTYPE NULL = 26 00; BITNTYPE NULL = 68 00.
	p := ParamSpec{Name: "", Type: "intn", IsNull: true}
	param, err := BuildRPCParam(p)
	if err != nil {
		t.Fatalf("BuildRPCParam: %v", err)
	}
	// Name(1) + StatusFlags(1) + TYPE_INFO(2: 26 04) + NULL data(1: 00).
	if len(param) != 5 {
		t.Fatalf("INTN NULL param len = %d, want 5", len(param))
	}
	if param[2] != TypeIntN || param[3] != 0x04 {
		t.Fatalf("INTN TYPE_INFO = %x, want 26 04", param[2:4])
	}
	if param[4] != 0 {
		t.Fatalf("INTN NULL data = 0x%02x, want 0 (GEN_NULL)", param[4])
	}
}

func TestRPCParamPLP(t *testing.T) {
	// T-203/T-204: varchar(max) PLP known-length.
	v := "HELLOWORLD"
	p := ParamSpec{Name: "@big", Type: "varchar", Max: true, Value: &v}
	param, err := BuildRPCParam(p)
	if err != nil {
		t.Fatalf("BuildRPCParam: %v", err)
	}
	// TYPE_INFO: A7 FF FF + collation.
	// 布局: bVarChar("@big")(9B: 1B len + 4×2B UCS-2) + StatusFlags(1B) = 10B
	// 头部,所以 TYPE_INFO 在 [10:18]。此前误用 [12:20] (off-by-2)。
	assertHex(t, param[10:18], "a7ffff0904d00034", "max TYPE_INFO")
	// PLP: 8B total len + chunk + terminator.
	plp := param[18:]
	if binary.LittleEndian.Uint64(plp[0:8]) != 10 {
		t.Fatalf("PLP total len = %d, want 10", binary.LittleEndian.Uint64(plp[0:8]))
	}
	if binary.LittleEndian.Uint32(plp[8:12]) != 10 {
		t.Fatalf("PLP chunk len = %d, want 10", binary.LittleEndian.Uint32(plp[8:12]))
	}
	if binary.LittleEndian.Uint32(plp[len(plp)-4:]) != 0 {
		t.Fatalf("PLP terminator missing")
	}
}

func TestRPCParamPLPChunking(t *testing.T) {
	// T-206: chunk size ≤ 4096; 50KB → 13 chunks (12×4096 + 2048).
	big := strings.Repeat("x", 50*1024)
	p := ParamSpec{Name: "@big", Type: "varchar", Max: true, Value: &big}
	param, err := BuildRPCParam(p)
	if err != nil {
		t.Fatalf("BuildRPCParam: %v", err)
	}
	// 同 TestRPCParamPLP: 头部 10B (bVarChar("@big")=9 + StatusFlags=1),
	// PLP 从 [18:] 开始。此前误用 [20:] (off-by-2)。
	plp := param[18:]
	// The current builder emits a single chunk; verify the chunk size limit
	// holds (a value that exceeds a single chunk is emitted in multiple
	// chunks).
	total := binary.LittleEndian.Uint64(plp[0:8])
	if total != 50*1024 {
		t.Fatalf("PLP total = %d, want 51200", total)
	}
	chunks := 0
	pos := 8
	for {
		c := binary.LittleEndian.Uint32(plp[pos : pos+4])
		if c == 0 {
			break
		}
		if c > 4096 {
			t.Fatalf("chunk %d len %d > 4096", chunks, c)
		}
		chunks++
		pos += 4 + int(c)
	}
	if chunks != 13 {
		t.Fatalf("chunk count = %d, want 13", chunks)
	}
}

func TestRPCResponseTokens(t *testing.T) {
	// T-102..T-104: DONEINPROC + RETURNSTATUS + DONEPROC.
	var tokens []byte
	di, _ := BuildDone(TokenDoneInProc, DONEMore|DONECount, 0xC1, 1, true)
	tokens = append(tokens, di...)
	tokens = append(tokens, BuildReturnStatus(0)...)
	dp, _ := BuildDone(TokenDoneProc, DONEFinal, 0xE0, 0, true)
	tokens = append(tokens, dp...)
	res, err := ParseResponse(tokens, true, TDSVersion74)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if len(res.Dones) != 2 {
		t.Fatalf("DONE count = %d, want 2", len(res.Dones))
	}
	if res.Dones[0].Type != TokenDoneInProc || res.Dones[0].Status != DONEMore|DONECount {
		t.Fatalf("DONEINPROC = %+v", res.Dones[0])
	}
	if res.Dones[1].Type != TokenDoneProc || res.Dones[1].Status != DONEFinal {
		t.Fatalf("DONEPROC = %+v", res.Dones[1])
	}
}

// --- S8/S9: Error/Info (T-136..T-160) ---

func TestErrorToken(t *testing.T) {
	// T-136..T-142: syntax error ERROR Class=15 + DONE(DONE_ERROR).
	msg := "Incorrect syntax near 'FROM'."
	tok, err := BuildErrorInfo(TokenError, 102, 1, 15, msg, "", "", 1, true)
	if err != nil {
		t.Fatalf("BuildErrorInfo: %v", err)
	}
	res, err := ParseResponse(tok, true, TDSVersion74)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if len(res.Errors) != 1 {
		t.Fatalf("error count = %d, want 1", len(res.Errors))
	}
	e := res.Errors[0]
	if e.Number != 102 {
		t.Fatalf("Number = %d, want 102", e.Number)
	}
	if e.Class != 15 {
		t.Fatalf("Class = %d, want 15", e.Class)
	}
	if e.MsgText != msg {
		t.Fatalf("MsgText = %q", e.MsgText)
	}
	if e.LineNumber != 1 {
		t.Fatalf("LineNumber = %d, want 1", e.LineNumber)
	}
	// ERROR Length field covers Number..LineNumber.
	// inner = 4(Number) + 1(State) + 1(Class) + 2(USHORTLEN) + len(UCS-2 msg)
	//         + 1(ServerName len) + 1(ProcName len) + 4(LineNumber 4B)
	wantLen := 4 + 1 + 1 + 2 + len(msg)*2 + 1 + 1 + 4
	l := binary.LittleEndian.Uint16(tok[1:3])
	if int(l) != wantLen {
		t.Fatalf("ERROR Length = %d, want %d", l, wantLen)
	}
}

func TestInfoToken(t *testing.T) {
	// T-151..T-153: INFO 5701, Class=0, State=2.
	tok, _ := BuildErrorInfo(TokenInfo, 5701, 2, 0, "Changed database context to 'master'.", "", "", 0, true)
	res, err := ParseResponse(tok, true, TDSVersion74)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if len(res.InfoTokens) != 1 {
		t.Fatalf("info count = %d, want 1", len(res.InfoTokens))
	}
	if res.InfoTokens[0].Number != 5701 || res.InfoTokens[0].Class != 0 || res.InfoTokens[0].State != 2 {
		t.Fatalf("INFO = %+v", res.InfoTokens[0])
	}
}

func TestErrorLineNumberWidth(t *testing.T) {
	// T-139: 7.1 uses 2B LineNumber.
	tok, _ := BuildErrorInfo(TokenError, 1, 1, 15, "x", "", "", 1, false)
	if len(tok) != 3+4+1+1+2+2+1+1+2 {
		t.Fatalf("7.1 ERROR len = %d", len(tok))
	}
}

// --- S10: Attention (T-161..T-170) ---

func TestAttentionPacket(t *testing.T) {
	// T-161: Type=0x06, Length=8, no body.
	pkt := BuildAttention(0, 1)
	if len(pkt) != 8 {
		t.Fatalf("attention packet len = %d, want 8", len(pkt))
	}
	if pkt[0] != TypeAttention {
		t.Fatalf("attention type = 0x%02x, want 0x06", pkt[0])
	}
	if pkt[2] != 0 || pkt[3] != 8 {
		t.Fatalf("attention length = %d, want 8", binary.BigEndian.Uint16(pkt[2:4]))
	}
}

func TestAttentionResponse(t *testing.T) {
	// T-162: DONE_ATTN = 0x20.
	resp := buildAttentionResponse()
	p, _ := ParsePacket(resp)
	res, err := ParseResponse(p.Body, true, TDSVersion74)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if !res.HasDoneAttn() {
		t.Fatalf("expected DONE_ATTN, got %+v", res.Dones)
	}
}

// --- S11: Transactions (T-171..T-185) ---

func TestEnvChangeTran(t *testing.T) {
	// T-171..T-176: ENVCHANGE 8/9/10 with 1B len + 8B TransactionID.
	// E3 0B 00 08 08 01 00 00 00 00 00 00 00 00 (14 bytes)
	e8 := BuildEnvChange(8, EnvChangeTranValue(1), EnvChangeEmptyValue())
	// 布局: token(E3) + Length(2B LE 0B 00) + type(08) + NewValue(1B len 08
	// + 8B txnID LE) + OldValue(1B len 00) = 14B = 28 hex chars。
	// 此前 want 误含 1B 多余零 (15B),与实际输出 14B 不符。
	assertHex(t, e8, "e30b000808010000000000000000", "ENVCHANGE 8")
	// E3 0B 00 09 00 08 01 00 00 00 00 00 00 00 (14 bytes)
	e9 := BuildEnvChange(9, EnvChangeEmptyValue(), EnvChangeTranValue(1))
	assertHex(t, e9, "e30b000900080100000000000000", "ENVCHANGE 9")
	// E3 0B 00 0A 00 08 01 00 00 00 00 00 00 00 (14 bytes)
	e10 := BuildEnvChange(10, EnvChangeEmptyValue(), EnvChangeTranValue(1))
	assertHex(t, e10, "e30b000a00080100000000000000", "ENVCHANGE 10")
}

func TestEnvChangeParse(t *testing.T) {
	// T-172/T-174: parse the ENVCHANGE 8 structure.
	e8 := BuildEnvChange(8, EnvChangeTranValue(1), EnvChangeEmptyValue())
	res, err := ParseResponse(e8, true, TDSVersion74)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if len(res.EnvChanges) != 1 {
		t.Fatalf("envchange count = %d, want 1", len(res.EnvChanges))
	}
	env := res.EnvChanges[0]
	if env.Type != 8 {
		t.Fatalf("envchange type = %d, want 8", env.Type)
	}
	if len(env.NewValue) != 8 || binary.LittleEndian.Uint64(env.NewValue) != 1 {
		t.Fatalf("NewValue = %x, want 8B TransactionID=1", env.NewValue)
	}
}

func TestLoginResponseStructure(t *testing.T) {
	// T-033..T-035: Login Response has ENVCHANGE×4 + INFO×2 + LOGINACK + DONE.
	cfg := defaultCfg()
	resp := buildLoginResponse(cfg)
	p, _ := ParsePacket(resp)
	res, err := ParseResponse(p.Body, true, cfg.Version)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if res.LoginAck == nil {
		t.Fatalf("LOGINACK missing (A35)")
	}
	if len(res.EnvChanges) != 4 {
		t.Fatalf("envchange count = %d, want 4", len(res.EnvChanges))
	}
	if len(res.InfoTokens) != 2 {
		t.Fatalf("info count = %d, want 2", len(res.InfoTokens))
	}
	if len(res.Dones) != 1 || res.Dones[0].Status != DONEFinal {
		t.Fatalf("DONE = %+v", res.Dones)
	}
	// A36: ProgName via B_VARCHAR.
	if res.LoginAck.ProgName != "Microsoft SQL Server" {
		t.Fatalf("ProgName = %q", res.LoginAck.ProgName)
	}
	// A37: Length covers the whole token.
	// A18: TDSVersion = 0x74000004 (server→client BE form).
	if res.LoginAck.TDSVersion != 0x74000004 {
		t.Fatalf("LOGINACK TDSVersion = 0x%08x, want 0x74000004", res.LoginAck.TDSVersion)
	}
}

func TestLoginAckBVarCharProgName(t *testing.T) {
	// T-034: ProgName B_VARCHAR — first byte is 1B length.
	ack := BuildLoginAck(1, 0x74000004, "Microsoft SQL Server", 0)
	// "Microsoft SQL Server" = 20 字符 = 40B UCS-2 (0x28)，ProgName len=0x14=20。
	// inner = interface(1) + TDSVersion BE(4) + bVarChar(1+40) + ProgVer(4) = 50 = 0x32。
	// 修复断言错误: 此前 want 写为 ad3600017400000416 (Length=0x36=54、ProgName
	// len=0x16=22)，与 BuildLoginAck 实际输出 (Length=0x32=50、ProgName
	// len=0x14=20) 不符。设计文档 S2 HexDump 误值，代码按规范实现是正确的。
	assertHex(t, ack[0:9], "ad3200017400000414", "LOGINACK header")
}

// --- S12: MARS (T-186..T-195) ---

func TestMarsSharedSPID(t *testing.T) {
	// T-186: MARS sessions share SPID; OutstandingRequestCount=2.
	cfg := defaultCfg()
	cfg.MarsEnabled = true
	cfg.Sessions = []SessionSpec{
		{ID: "A", Requests: []RequestSpec{{Type: RequestSQLBatch, Sql: &SqlBatchSpec{Statements: []StatementSpec{{Text: "SELECT * FROM bigtable"}}}}}},
		{ID: "B", Requests: []RequestSpec{{Type: RequestSQLBatch, Sql: &SqlBatchSpec{Statements: []StatementSpec{{Text: "INSERT INTO t VALUES(1)"}}}}}},
	}
	pkts := mustPlan(t, &Planner{}, tdsSpec(cfg))
	ups := upPayloads(t, pkts)
	var spids []uint16
	for _, p := range ups {
		if len(p) >= 8 && p[0] == TypeSQLBatch {
			spid := binary.BigEndian.Uint16(p[4:6])
			spids = append(spids, spid)
		}
	}
	if len(spids) != 2 {
		t.Fatalf("SQL batch packets = %d, want 2", len(spids))
	}
	if spids[0] != spids[1] {
		t.Fatalf("SPIDs differ: %d vs %d (want shared)", spids[0], spids[1])
	}
	if spids[0] != 0x0042 {
		t.Fatalf("SPID = 0x%04x, want 0x0042", spids[0])
	}
	// OutstandingRequestCount = 2 for both.
	for i, p := range ups {
		if len(p) >= 8 && p[0] == TypeSQLBatch {
			pkt, _ := ParsePacket(p)
			ah, err := ParseAllHeaders(pkt.Body)
			if err != nil {
				t.Fatalf("ParseAllHeaders[%d]: %v", i, err)
			}
			if ah.OutstandingCount != 2 {
				t.Fatalf("outstanding[%d] = %d, want 2", i, ah.OutstandingCount)
			}
		}
	}
}

func TestMarsRequiresEnabled(t *testing.T) {
	// T-195: multiple sessions without MARS → validate error.
	cfg := defaultCfg()
	cfg.MarsEnabled = false
	cfg.Sessions = []SessionSpec{
		{ID: "A", Requests: []RequestSpec{{Type: RequestSQLBatch, Sql: &SqlBatchSpec{Statements: []StatementSpec{{Text: "SELECT 1"}}}}}},
		{ID: "B", Requests: []RequestSpec{{Type: RequestSQLBatch, Sql: &SqlBatchSpec{Statements: []StatementSpec{{Text: "SELECT 2"}}}}}},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error for multiple sessions without MARS")
	}
}

// --- S13: Multi-RPC batch (T-196..T-202) ---

func TestRPCMultiBatch(t *testing.T) {
	// T-196: BatchFlag=0xFF separates two RPCReqBatch entries.
	pid := uint16(10)
	body, err := BuildRPCBatch([]RpcSpec{
		{ProcID: &pid},
		{ProcName: "foo3"},
	}, true, 0, 1, StatusEOM, 0, 1)
	if err != nil {
		t.Fatalf("BuildRPCBatch: %v", err)
	}
	p, _ := ParsePacket(body)
	// ALL_HEADERS(22) + [FF FF 0A 00 00] + FF + [04 00 66 00 6F 00 6F 00 33 00 00].
	assertHex(t, p.Body[22:], "ffff0a0000ff040066006f006f00330000", "RPC batch body")
}

// --- S14: PLP (T-203..T-209) ---

func TestPLPUnknownLen(t *testing.T) {
	// T-205: UNKNOWN_PLP_LEN sentinel exists.
	if PLPUnknownLen != 0xFFFFFFFFFFFFFFFE {
		t.Fatalf("PLPUnknownLen = 0x%x", PLPUnknownLen)
	}
	if PLPNull != 0xFFFFFFFFFFFFFFFF {
		t.Fatalf("PLPNull = 0x%x", PLPNull)
	}
}

func TestRowCount8BBoundary(t *testing.T) {
	// T-209: 2^32-1 rows fits in 8B.
	done, _ := BuildDone(TokenDone, DONECount, 0, 0xFFFFFFFF, true)
	if binary.LittleEndian.Uint64(done[5:13]) != 0xFFFFFFFF {
		t.Fatalf("rowcount = %d, want 2^32-1", binary.LittleEndian.Uint64(done[5:13]))
	}
}

// --- S15: NULL handling (T-210..T-214) ---

func TestNullInt4Row(t *testing.T) {
	// T-210: INT4 NULL = 4B zeros.
	cm := BuildColMetadata([]ColMetadataColumn{
		{UserType: 0, Flags: FlagNullable, TypeInfo: []byte{TypeInt4}, ColName: "c1"},
		{UserType: 0, Flags: FlagNullable, TypeInfo: []byte{TypeBigVarChar, 5, 0, 0x09, 0x04, 0xD0, 0x00, 0x34}, ColName: "c2"},
	}, false)
	row := BuildRow(append([]byte{0, 0, 0, 0}, 0xFF, 0xFF)) // INT4 NULL + varchar NULL
	tokens := append(cm, row...)
	done, _ := BuildDone(TokenDone, DONECount, 0, 1, true)
	tokens = append(tokens, done...)
	res, err := ParseResponse(tokens, true, TDSVersion74)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if res.ColCount != 2 {
		t.Fatalf("ColCount = %d, want 2", res.ColCount)
	}
	if res.RowCount != 1 {
		t.Fatalf("RowCount = %d, want 1", res.RowCount)
	}
}

func TestNullPLPRow(t *testing.T) {
	// T-212: varchar(max) NULL = 8B PLP_NULL.
	cm := BuildColMetadata([]ColMetadataColumn{
		{UserType: 0, Flags: FlagNullable, TypeInfo: []byte{TypeBigVarChar, 0xFF, 0xFF, 0x09, 0x04, 0xD0, 0x00, 0x34}, ColName: "c3"},
	}, false)
	row := BuildRow([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
	tokens := append(cm, row...)
	done, _ := BuildDone(TokenDone, DONECount, 0, 1, true)
	tokens = append(tokens, done...)
	if _, err := ParseResponse(tokens, true, TDSVersion74); err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
}

func TestNbcRow(t *testing.T) {
	// T-214: NBCROW null bitmap.
	cm := BuildColMetadata([]ColMetadataColumn{
		{TypeInfo: []byte{TypeInt4}, ColName: "c1"},
		{TypeInfo: []byte{TypeInt4}, ColName: "c2"},
		{TypeInfo: []byte{TypeInt4}, ColName: "c3"},
		{TypeInfo: []byte{TypeInt4}, ColName: "c4"},
	}, false)
	// Row 2: c1..c3 NULL (bitmap 0x07), c4=7.
	nbc := BuildNbcRow([]byte{0x07}, []byte{7, 0, 0, 0})
	tokens := append(cm, nbc...)
	done, _ := BuildDone(TokenDone, DONECount, 0, 2, true)
	tokens = append(tokens, done...)
	res, err := ParseResponse(tokens, true, TDSVersion74)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if res.RowCount != 1 {
		t.Fatalf("RowCount = %d, want 1", res.RowCount)
	}
}

// --- Validate rules (V-01..V-50) ---

func TestValidateVersion(t *testing.T) {
	// V-01.
	cfg := defaultCfg()
	cfg.Version = TDSVersion(0x12345678)
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected invalid version error")
	}
}

func TestValidatePacketSize(t *testing.T) {
	// V-02.
	cfg := defaultCfg()
	cfg.PacketSize = 511
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected packet size error (511)")
	}
	cfg.PacketSize = 32768
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected packet size error (32768)")
	}
}

func TestValidateNoSessions(t *testing.T) {
	// V-03.
	cfg := defaultCfg()
	cfg.Sessions = nil
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected no-sessions error")
	}
}

func TestValidateEmptyRequests(t *testing.T) {
	// V-04.
	cfg := defaultCfg()
	cfg.Sessions[0].Requests = nil
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected empty-requests error")
	}
}

func TestValidateBadRequestType(t *testing.T) {
	// V-05.
	cfg := defaultCfg()
	cfg.Sessions[0].Requests[0].Type = RequestType("bogus")
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected bad request type error")
	}
}

func TestValidateSqlMissing(t *testing.T) {
	// V-06.
	cfg := defaultCfg()
	cfg.Sessions[0].Requests[0] = RequestSpec{Type: RequestSQLBatch}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected missing-sql error")
	}
}

func TestValidateProcNameTooLong(t *testing.T) {
	// V-21.
	cfg := defaultCfg()
	long := strings.Repeat("a", 1047)
	cfg.Sessions[0].Requests[0] = RequestSpec{
		Type: RequestRPC,
		Rpc:  &RpcSpec{ProcName: long},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected ProcName too long error")
	}
}

func TestValidateProcIDRange(t *testing.T) {
	// V-22.
	cfg := defaultCfg()
	pid := uint16(16)
	cfg.Sessions[0].Requests[0] = RequestSpec{
		Type: RequestRPC,
		Rpc:  &RpcSpec{ProcID: &pid},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected ProcID out-of-range error")
	}
}

func TestValidateParamType(t *testing.T) {
	// V-24.
	cfg := defaultCfg()
	cfg.Sessions[0].Requests[0] = RequestSpec{
		Type: RequestRPC,
		Rpc: &RpcSpec{Params: []ParamSpec{
			{Type: "not_a_type"},
		}},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected unsupported param type error")
	}
}

func TestValidateTransMgrType(t *testing.T) {
	// V-33.
	cfg := defaultCfg()
	cfg.Sessions[0].Requests[0] = RequestSpec{
		Type:     RequestTransMgr,
		TransMgr: &TransMgrSpec{RequestType: 99},
	}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected unknown request_type error")
	}
}

func TestValidateTranIDRequiresBegin(t *testing.T) {
	// V-35: transaction_id without BEGIN TRAN → error.
	cfg := defaultCfg()
	cfg.Sessions[0].TransactionID = 7
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected transaction_id-without-begin error")
	}
}

func TestValidateFeatureExtVersion(t *testing.T) {
	// V-15: features require 7.4.
	cfg := defaultCfg()
	cfg.Version = TDSVersion72
	cfg.FeatureExts = []FeatureExt{{ID: 0x01}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected feature-ext version error")
	}
}

func TestValidateFeatureID(t *testing.T) {
	// V-16.
	cfg := defaultCfg()
	cfg.FeatureExts = []FeatureExt{{ID: 0x77}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected unknown feature id error")
	}
}

func TestValidateFeatureHex(t *testing.T) {
	// V-17.
	cfg := defaultCfg()
	cfg.FeatureExts = []FeatureExt{{ID: 0x01, Data: "zz"}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected bad feature hex error")
	}
}

// --- Planner end-to-end (T-215..T-220) ---

func TestPlanFullSequence(t *testing.T) {
	// T-215: the full flow emits PRELOGIN + LOGIN7 + SQL Batch + responses.
	cfg := defaultCfg()
	pkts := mustPlan(t, &Planner{}, tdsSpec(cfg))
	ups := upPayloads(t, pkts)
	dns := downPayloads(t, pkts)

	// PRELOGIN first (Type=0x12).
	if len(ups) < 3 || ups[0][0] != TypePreLogin {
		t.Fatalf("first up payload type = %v, want PRELOGIN", firstType(ups))
	}
	// LOGIN7 second (Type=0x10).
	if ups[1][0] != TypeLogin7 {
		t.Fatalf("second up payload type = 0x%02x, want 0x10", ups[1][0])
	}
	// SQL Batch third (Type=0x01).
	if ups[2][0] != TypeSQLBatch {
		t.Fatalf("third up payload type = 0x%02x, want 0x01", ups[2][0])
	}
	// Down side: PRELOGIN response + Login response + table response.
	if len(dns) < 3 {
		t.Fatalf("down packets = %d, want >= 3", len(dns))
	}
	// Login response (Type=0x04) has LOGINACK.
	p, _ := ParsePacket(dns[1])
	res, err := ParseResponse(p.Body, true, cfg.Version)
	if err != nil {
		t.Fatalf("ParseResponse login: %v", err)
	}
	if res.LoginAck == nil {
		t.Fatalf("login response missing LOGINACK")
	}
	// SQL batch response (Type=0x04) has COLMETADATA + ROW + DONE.
	p, _ = ParsePacket(dns[2])
	res, err = ParseResponse(p.Body, true, cfg.Version)
	if err != nil {
		t.Fatalf("ParseResponse batch: %v", err)
	}
	if res.ColCount != 1 || res.RowCount != 1 {
		t.Fatalf("batch response cols=%d rows=%d, want 1/1", res.ColCount, res.RowCount)
	}
	if len(res.Dones) != 1 {
		t.Fatalf("batch response DONE count = %d, want 1", len(res.Dones))
	}
}

func firstType(ups [][]byte) []byte {
	var out []byte
	for _, u := range ups {
		if len(u) > 0 {
			out = append(out, u[0])
		}
	}
	return out
}

func TestPlanTransactionFlow(t *testing.T) {
	// T-171..T-175: TM_BEGIN_XACT → ENVCHANGE 8 response (the SQL Batch
	// path doesn't synthesize ENVCHANGE; the TransMgr path does).
	cfg := defaultCfg()
	cfg.Sessions = []SessionSpec{{
		ID: "s1",
		Requests: []RequestSpec{{
			Type:     RequestTransMgr,
			TransMgr: &TransMgrSpec{RequestType: TMBeginXact},
		}},
	}}
	pkts := mustPlan(t, &Planner{}, tdsSpec(cfg))
	dns := downPayloads(t, pkts)
	// The last down payload is the TM_BEGIN_XACT response.
	p, _ := ParsePacket(dns[len(dns)-1])
	res, err := ParseResponse(p.Body, true, cfg.Version)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	var found8 bool
	for _, e := range res.EnvChanges {
		if e.Type == 8 {
			found8 = true
			if len(e.NewValue) != 8 {
				t.Fatalf("ENVCHANGE 8 NewValue len = %d, want 8", len(e.NewValue))
			}
		}
	}
	if !found8 {
		t.Fatalf("no ENVCHANGE 8 in TM_BEGIN_XACT response")
	}
}

func TestPlanAttention(t *testing.T) {
	// T-161..T-162: attention request + DONE_ATTN response.
	cfg := defaultCfg()
	cfg.Sessions = []SessionSpec{{
		ID: "s1",
		Requests: []RequestSpec{{
			Type: RequestAttention,
		}},
	}}
	pkts := mustPlan(t, &Planner{}, tdsSpec(cfg))
	ups := upPayloads(t, pkts)
	dns := downPayloads(t, pkts)
	var attn []byte
	for _, u := range ups {
		if len(u) >= 8 && u[0] == TypeAttention {
			attn = u
		}
	}
	if attn == nil {
		t.Fatalf("no attention packet found")
	}
	if len(attn) != 8 {
		t.Fatalf("attention packet len = %d, want 8", len(attn))
	}
	// The attention response is the last down payload with a DONE_ATTN.
	p, _ := ParsePacket(dns[len(dns)-1])
	res, err := ParseResponse(p.Body, true, cfg.Version)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if !res.HasDoneAttn() {
		t.Fatalf("expected DONE_ATTN")
	}
}

func TestPlanTransMgr(t *testing.T) {
	// T-181: TM_BEGIN_XACT → ENVCHANGE 8.
	cfg := defaultCfg()
	cfg.Sessions = []SessionSpec{{
		ID: "s1",
		Requests: []RequestSpec{{
			Type:     RequestTransMgr,
			TransMgr: &TransMgrSpec{RequestType: TMBeginXact},
		}},
	}}
	pkts := mustPlan(t, &Planner{}, tdsSpec(cfg))
	ups := upPayloads(t, pkts)
	// The TransMgrReq packet (Type=0x0E).
	var found []byte
	for _, u := range ups {
		if len(u) >= 8 && u[0] == TypeTransMgrReq {
			found = u
		}
	}
	if found == nil {
		t.Fatalf("no TransMgrReq packet found")
	}
	p, _ := ParsePacket(found)
	// ALL_HEADERS(22) + RequestType(2).
	if binary.LittleEndian.Uint16(p.Body[22:24]) != TMBeginXact {
		t.Fatalf("RequestType = %d, want 5", binary.LittleEndian.Uint16(p.Body[22:24]))
	}
}

func TestPlanXMLParam(t *testing.T) {
	// T-219: xml/json/udt/vector PLP types.
	for _, typ := range []string{"xml", "json", "udt"} {
		p := ParamSpec{Name: "@p", Type: typ, Value: strPtr("<root/>")}
		param, err := BuildRPCParam(p)
		if err != nil {
			t.Fatalf("%s param: %v", typ, err)
		}
		// TYPE_INFO token at [6]: 布局为 bVarChar("@p")(5B: 1B len + 2×2B
		// UCS-2) + StatusFlags(1B) = 6B 头部, xml/json/udt 的 TYPE_INFO 仅
		// 1B token。此前误用 [12] (off-by-6)。
		var wantTok byte
		switch typ {
		case "xml":
			wantTok = TypeXML
		case "json":
			wantTok = TypeJSON
		case "udt":
			wantTok = TypeUDT
		}
		if param[6] != wantTok {
			t.Fatalf("%s TYPE_INFO = 0x%02x, want 0x%02x", typ, param[6], wantTok)
		}
	}
	// NULL PLP = 8B 0xFF: TYPE_INFO 1B 在 [6], PLP 数据从 [7:15] 开始。
	// 此前误用 [13:21] (off-by-6)。
	p := ParamSpec{Name: "@p", Type: "xml", IsNull: true}
	param, _ := BuildRPCParam(p)
	if binary.LittleEndian.Uint64(param[7:15]) != PLPNull {
		t.Fatalf("xml NULL = %x, want PLP_NULL", param[7:15])
	}
}

func strPtr(s string) *string { return &s }

func TestEnvChangeTypeVariants(t *testing.T) {
	// T-220: ENVCHANGE Type 12/16/17 NewValue/OldValue directions.
	// Type 12 Defect: NewValue=B_VARBYTE(8B), OldValue=%x00.
	e12 := BuildEnvChange(12, EnvChangeTranValue(7), EnvChangeEmptyValue())
	res, _ := ParseResponse(e12, true, TDSVersion74)
	env := res.EnvChanges[0]
	if env.Type != 12 || len(env.NewValue) != 8 || binary.LittleEndian.Uint64(env.NewValue) != 7 {
		t.Fatalf("Type 12 = %+v", env)
	}
	// Type 16: NewValue=B_VARBYTE, OldValue=%x00.
	e16 := BuildEnvChange(16, bVarByte([]byte{1, 2, 3}), EnvChangeEmptyValue())
	res, _ = ParseResponse(e16, true, TDSVersion74)
	env = res.EnvChanges[0]
	if env.Type != 16 || len(env.NewValue) != 3 {
		t.Fatalf("Type 16 = %+v", env)
	}
	// Type 17: NewValue=%x00, OldValue=B_VARBYTE(8B).
	e17 := BuildEnvChange(17, EnvChangeEmptyValue(), EnvChangeTranValue(3))
	res, _ = ParseResponse(e17, true, TDSVersion74)
	env = res.EnvChanges[0]
	if env.Type != 17 || len(env.OldValue) != 8 || binary.LittleEndian.Uint64(env.OldValue) != 3 {
		t.Fatalf("Type 17 = %+v", env)
	}
}

func TestPlannerValidate(t *testing.T) {
	// Validate via the FlowSpec interface.
	spec := tdsSpec(defaultCfg())
	if err := (&Planner{}).Validate(spec); err != nil {
		t.Fatalf("Validate: %v", err)
	}
	// Bad config in payload.
	spec.Payload = []byte(`{"version": 99}`)
	if err := (&Planner{}).Validate(spec); err == nil {
		t.Fatalf("expected validate error for bad version")
	}
}

func TestName(t *testing.T) {
	if got := (&Planner{}).Name(); got != "tds" {
		t.Fatalf("Name = %q, want tds", got)
	}
}

// --- 回归测试: 三个 CRITICAL bug 修复 (txnBegins 大小写 / LOGIN7 TDSVersion
// 字节序 / PRELOGIN VERSION 数据长度) ---

// TestTxnBeginsCaseInsensitive 验证 Bug 1: txnBegins 此前 upperTrim 转大写
// 后却与小写字面量比较，导致永远返回 false。修复后 BEGIN TRAN / begin tran
// / Begin Transaction 等大小写写法都应被识别为事务开启语句。
func TestTxnBeginsCaseInsensitive(t *testing.T) {
	cases := []struct {
		text string
		want bool
	}{
		{"BEGIN TRAN", true},
		{"begin tran", true},
		{"Begin Transaction", true},
		{"BEGIN TRANSACTION", true},
		{"BEGIN", true},
		{"BEGIN;", true},
		{"BEGIN TRAN ", true}, // upperTrim 不去尾空格，字面量显式覆盖
		{"select 1", false},
		{"COMMIT", false},
		{"ROLLBACK", false},
		{"", false},
	}
	for _, c := range cases {
		if got := txnBegins(c.text); got != c.want {
			t.Errorf("txnBegins(%q) = %v, want %v", c.text, got, c.want)
		}
	}
}

// TestValidateTransactionIDWithBeginTran 验证 Bug 1 的端到端影响: 当 SQL Batch
// 含 "BEGIN TRAN" 且 session 设了 transaction_id 时，Validate 应通过
// (修复前 seenBegin 永远为 false，会误报 V-TDS-036)。
func TestValidateTransactionIDWithBeginTran(t *testing.T) {
	cfg := defaultCfg()
	cfg.Sessions[0].TransactionID = 1
	cfg.Sessions[0].Requests[0] = RequestSpec{
		Type: RequestSQLBatch,
		Sql: &SqlBatchSpec{Statements: []StatementSpec{
			{Text: "BEGIN TRAN"},
		}},
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ValidateConfig with BEGIN TRAN + transaction_id: %v", err)
	}
	// 大小写混合也应工作。
	cfg.Sessions[0].Requests[0].Sql.Statements[0].Text = "begin tran"
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("ValidateConfig with lowercase begin tran: %v", err)
	}
}

// TestLogin7TDSVersionBigEndian 验证 Bug 2: LOGIN7 TDSVersion 必须以大端
// 网络序上线路 (spec footnote 72 + MS-TDS 4.2 示例 7.2 wire = 02 00 09 72)。
// 修复前 putLE32 会产出 72 09 00 02 与规范示例不符。
func TestLogin7TDSVersionBigEndian(t *testing.T) {
	// 7.2: 常量 0x02000972 的 BE 编码 = 02 00 09 72 (MS-TDS 4.2 示例)。
	cfg := defaultCfg()
	cfg.Version = TDSVersion72
	pkt := buildLogin7Packet(cfg)
	p, _ := ParsePacket(pkt)
	if got := hex.EncodeToString(p.Body[4:8]); got != "02000972" {
		t.Fatalf("7.2 TDSVersion wire = %s, want 02000972 (BE)", got)
	}
	// 7.4: 常量 0x04000074 的 BE 编码 = 04 00 00 74 (MS-TDS 4.4 示例)。
	cfg.Version = TDSVersion74
	pkt = buildLogin7Packet(cfg)
	p, _ = ParsePacket(pkt)
	if got := hex.EncodeToString(p.Body[4:8]); got != "04000074" {
		t.Fatalf("7.4 TDSVersion wire = %s, want 04000074 (BE)", got)
	}
}

// TestLogin7TDSVersionRoundTrip 验证 Bug 2 的解析器侧: ParseLogin7 应以 BE
// 读取 TDSVersion，使 builder↔parser 往返一致。
func TestLogin7TDSVersionRoundTrip(t *testing.T) {
	for _, v := range []TDSVersion{TDSVersion71, TDSVersion72, TDSVersion73A, TDSVersion73B, TDSVersion74} {
		cfg := defaultCfg()
		cfg.Version = v
		pkt := buildLogin7Packet(cfg)
		p, _ := ParsePacket(pkt)
		res, err := ParseLogin7(p.Body)
		if err != nil {
			t.Fatalf("ParseLogin7(v=%08x): %v", uint32(v), err)
		}
		if res.TDSVersion != uint32(v) {
			t.Errorf("v=%08x: round-trip TDSVersion = %08x, want %08x", uint32(v), res.TDSVersion, uint32(v))
		}
	}
}

// TestPreLoginVersionDataSixBytes 验证 Bug 3: PRELOGIN VERSION 数据应为 6 字节
// (UL_VERSION 4B BE + US_SUBBUILD 2B BE)。修复前误写成 8 字节 (4B + 4B)，
// PL_OPTION_LENGTH 会写成 0x0008 而非规范的 0x0006。
func TestPreLoginVersionDataSixBytes(t *testing.T) {
	cfg := defaultCfg()
	pkt := buildPreLoginPacket(cfg, 1)
	p, _ := ParsePacket(pkt)
	res, err := ParsePreLogin(p.Body)
	if err != nil {
		t.Fatalf("ParsePreLogin: %v", err)
	}
	verData := res.Options[PLVersion]
	if len(verData) != 6 {
		t.Fatalf("VERSION data len = %d, want 6 (UL_VERSION 4B + US_SUBBUILD 2B)", len(verData))
	}
	// UL_VERSION BE = 09 00 00 00 (major=9)。
	if got := hex.EncodeToString(verData[0:4]); got != "09000000" {
		t.Fatalf("UL_VERSION = %s, want 09000000 (BE)", got)
	}
	// US_SUBBUILD BE = 00 00 (与 MS-TDS 4.1 示例一致)。
	if got := hex.EncodeToString(verData[4:6]); got != "0000" {
		t.Fatalf("US_SUBBUILD = %s, want 0000 (BE)", got)
	}
}

// TestPreLoginVersionOptionLengthField 验证 Bug 3 的线路字段: PRELOGIN 选项表
// 中 VERSION 选项的 PL_OPTION_LENGTH 字段应为 0x0006 (BE)。修复前为 0x0008。
func TestPreLoginVersionOptionLengthField(t *testing.T) {
	cfg := defaultCfg()
	pkt := buildPreLoginPacket(cfg, 1)
	// body[0]=VERSION token, body[1:3]=PL_OFFSET BE, body[3:5]=PL_OPTION_LENGTH BE。
	body := pkt[8:] // 跳过 8B 包头
	if body[0] != PLVersion {
		t.Fatalf("first option token = 0x%02x, want 0x00 (VERSION)", body[0])
	}
	got := binary.BigEndian.Uint16(body[3:5])
	if got != 0x0006 {
		t.Fatalf("VERSION PL_OPTION_LENGTH = 0x%04x, want 0x0006", got)
	}
}

// --- Bug 4: MARS OutstandingRequestCount 动态化 ---
//
// 修复前 computeOutstanding(sessIdx) = sessIdx+1，导致 2 会话时 A 的请求
// outstanding=1、B 的请求 outstanding=2 (静态递增)。但 spec §4.4 MARS 状态机
// 定义 "OutstandingRequestCount = 当前该连接上活动请求数"，即每个请求的
// outstanding 应反映该连接上同时活动的 session 总数。修复后 2 会话时
// A/B 请求均为 2、3 会话时均为 3 (T-186 / T-192)。

// TestBug4MarsOutstandingDynamicTwoSessions 验证 2 会话 MARS 时每条请求的
// OutstandingRequestCount=2 (此前 sessIdx+1 让 A=1, B=2，与 T-186 不符)。
func TestBug4MarsOutstandingDynamicTwoSessions(t *testing.T) {
	cfg := defaultCfg()
	cfg.MarsEnabled = true
	cfg.Sessions = []SessionSpec{
		{ID: "A", Requests: []RequestSpec{{Type: RequestSQLBatch, Sql: &SqlBatchSpec{Statements: []StatementSpec{{Text: "SELECT 1"}}}}}},
		{ID: "B", Requests: []RequestSpec{{Type: RequestSQLBatch, Sql: &SqlBatchSpec{Statements: []StatementSpec{{Text: "SELECT 2"}}}}}},
	}
	pkts := mustPlan(t, &Planner{}, tdsSpec(cfg))
	ups := upPayloads(t, pkts)
	var sqlBatches [][]byte
	for _, p := range ups {
		if len(p) >= 8 && p[0] == TypeSQLBatch {
			sqlBatches = append(sqlBatches, p)
		}
	}
	if len(sqlBatches) != 2 {
		t.Fatalf("SQL batch packets = %d, want 2", len(sqlBatches))
	}
	for i, p := range sqlBatches {
		pkt, _ := ParsePacket(p)
		ah, err := ParseAllHeaders(pkt.Body)
		if err != nil {
			t.Fatalf("ParseAllHeaders[%d]: %v", i, err)
		}
		if ah.OutstandingCount != 2 {
			t.Fatalf("outstanding[%d] = %d, want 2 (动态=活动 session 总数)", i, ah.OutstandingCount)
		}
	}
}

// TestBug4MarsOutstandingDynamicThreeSessions 验证 3 会话 MARS 时每条请求的
// OutstandingRequestCount=3 (对应 T-192)。修复前会让 A=1, B=2, C=3。
func TestBug4MarsOutstandingDynamicThreeSessions(t *testing.T) {
	cfg := defaultCfg()
	cfg.MarsEnabled = true
	cfg.Sessions = []SessionSpec{
		{ID: "A", Requests: []RequestSpec{{Type: RequestSQLBatch, Sql: &SqlBatchSpec{Statements: []StatementSpec{{Text: "SELECT 1"}}}}}},
		{ID: "B", Requests: []RequestSpec{{Type: RequestSQLBatch, Sql: &SqlBatchSpec{Statements: []StatementSpec{{Text: "SELECT 2"}}}}}},
		{ID: "C", Requests: []RequestSpec{{Type: RequestSQLBatch, Sql: &SqlBatchSpec{Statements: []StatementSpec{{Text: "SELECT 3"}}}}}},
	}
	pkts := mustPlan(t, &Planner{}, tdsSpec(cfg))
	ups := upPayloads(t, pkts)
	for _, p := range ups {
		if len(p) < 8 || p[0] != TypeSQLBatch {
			continue
		}
		pkt, _ := ParsePacket(p)
		ah, err := ParseAllHeaders(pkt.Body)
		if err != nil {
			t.Fatalf("ParseAllHeaders: %v", err)
		}
		if ah.OutstandingCount != 3 {
			t.Fatalf("outstanding = %d, want 3 (3 会话 MARS)", ah.OutstandingCount)
		}
	}
}

// TestBug4NonMarsOutstandingAutoCommit 验证非 MARS (AutoCommit) 时 outstanding=1
// 不受动态化影响 (spec §2.5: AutoCommit 下 OutstandingRequestCount=1)。
func TestBug4NonMarsOutstandingAutoCommit(t *testing.T) {
	cfg := defaultCfg() // MarsEnabled=false 默认
	pkts := mustPlan(t, &Planner{}, tdsSpec(cfg))
	ups := upPayloads(t, pkts)
	for _, p := range ups {
		if len(p) < 8 || p[0] != TypeSQLBatch {
			continue
		}
		pkt, _ := ParsePacket(p)
		ah, err := ParseAllHeaders(pkt.Body)
		if err != nil {
			t.Fatalf("ParseAllHeaders: %v", err)
		}
		if ah.OutstandingCount != 1 {
			t.Fatalf("non-MARS outstanding = %d, want 1 (AutoCommit)", ah.OutstandingCount)
		}
	}
}

// --- Bug 5: FeatureExts 非空时自动设 OptionFlags3 fExtension bit4 ---
//
// 修复前 buildLogin7Packet 仅在注释中要求调用者手工置 OptionFlags3 bit4，
// 但默认配置与 Validate 均未置位，导致 FeatureExt 数据存在时服务器不读取
// ibExtension/cbExtension (spec §3.2: fExtension=1 才会解析扩展字段)。

// TestBug5FeatureExtSetsExtensionBit 验证 FeatureExts 非空时 LOGIN7 OptionFlags3
// 自动置位 fExtension (bit4=0x10)，无需调用者手工设 OptionFlags3。
func TestBug5FeatureExtSetsExtensionBit(t *testing.T) {
	cfg := defaultCfg()
	cfg.Version = TDSVersion74
	cfg.FeatureExts = []FeatureExt{{ID: 0x01}} // SESSIONRECOVERY, 无 Data
	pkt := buildLogin7Packet(cfg)
	p, err := ParsePacket(pkt)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	// OptionFlags3 在 body[27] (spec §3.2 fixed header layout)。
	if p.Body[27]&0x10 == 0 {
		t.Fatalf("OptionFlags3 = 0x%02x, want bit4 (fExtension) set", p.Body[27])
	}
}

// TestBug5NoFeatureExtClearsExtensionBit 验证 FeatureExts 为空时 OptionFlags3
// 不置 fExtension bit (保持默认 0x00 或调用者指定值)。
func TestBug5NoFeatureExtClearsExtensionBit(t *testing.T) {
	cfg := defaultCfg()
	cfg.Version = TDSVersion74
	// 无 FeatureExts
	pkt := buildLogin7Packet(cfg)
	p, _ := ParsePacket(pkt)
	if p.Body[27]&0x10 != 0 {
		t.Fatalf("OptionFlags3 = 0x%02x, want bit4 (fExtension) cleared when no FeatureExts", p.Body[27])
	}
}

// TestBug5FeatureExtPreservesCallerFlags 验证调用者已设的 OptionFlags3 其它位
// 不会被 fExtension 自动置位覆盖 (OR 语义，不清零已有位)。
func TestBug5FeatureExtPreservesCallerFlags(t *testing.T) {
	cfg := defaultCfg()
	cfg.Version = TDSVersion74
	// 调用者手工设了 bit1 (fSendYukonBinaryXML) + bit3 (fUnknownCollationHandling)
	flags3 := byte(0x0A) // bit1 + bit3
	cfg.Login = &LoginSpec{OptionFlags3: &flags3}
	cfg.FeatureExts = []FeatureExt{{ID: 0x01}}
	pkt := buildLogin7Packet(cfg)
	p, _ := ParsePacket(pkt)
	// 期望 = 调用者值 0x0A | fExtension(0x10) = 0x1A
	if p.Body[27] != 0x1A {
		t.Fatalf("OptionFlags3 = 0x%02x, want 0x1A (caller 0x0A | fExtension 0x10)", p.Body[27])
	}
}

// --- Bug 6: FEATUREEXTACK 支持自定义 ack_data 字段 ---
//
// 修复前 FEATUREEXTACK 对每个 FeatureId 一律回写长度为 0 的 FeatureAckData。
// 但 spec §3.14 定义 FeatureAckOpt = (FeatureId FeatureAckDataLen FeatureAckData)，
// 允许自定义回执数据 (如 FEDAUTH 的 Nonce+Signature)。

// TestBug6FeatureExtAckCustomAckData 验证 FeatureExt.AckData 字段能控制
// FEATUREEXTACK 中每个 feature 的回执数据内容与长度字段。
func TestBug6FeatureExtAckCustomAckData(t *testing.T) {
	cfg := defaultCfg()
	cfg.Version = TDSVersion74
	// FEDAUTH (0x02) ack_data = 32B Nonce+Signature (示例: 32 个 0xAA)
	cfg.FeatureExts = []FeatureExt{{ID: 0x02, AckData: strings.Repeat("AA", 32)}}
	resp := buildLoginResponse(cfg)
	p, err := ParsePacket(resp)
	if err != nil {
		t.Fatalf("ParsePacket: %v", err)
	}
	res, err := ParseResponse(p.Body, true, cfg.Version)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if !res.FeatureExtAck {
		t.Fatalf("FEATUREEXTACK not present")
	}
	// 直接断言 FEATUREEXTACK 字节: AE + [02 + len(4B LE=20 00 00 00) + 32B 0xAA] + FF
	// 在 token stream 中查找 0xAE
	var ackBytes []byte
	for i := 0; i < len(p.Body); i++ {
		if p.Body[i] == TokenFeatureExtAck {
			ackBytes = p.Body[i:]
			break
		}
	}
	if ackBytes == nil {
		t.Fatalf("FEATUREEXTACK token not found in response")
	}
	// ackBytes[0]=AE, [1]=FeatureId=0x02, [2:6]=FeatureAckDataLen LE, [6:38]=32B data, [38]=FF terminator
	if ackBytes[1] != 0x02 {
		t.Fatalf("FeatureId = 0x%02x, want 0x02 (FEDAUTH)", ackBytes[1])
	}
	ackLen := binary.LittleEndian.Uint32(ackBytes[2:6])
	if ackLen != 32 {
		t.Fatalf("FeatureAckDataLen = %d, want 32", ackLen)
	}
	// 数据应为 32 个 0xAA
	for i := 0; i < 32; i++ {
		if ackBytes[6+i] != 0xAA {
			t.Fatalf("FeatureAckData[%d] = 0x%02x, want 0xAA", i, ackBytes[6+i])
		}
	}
	// 终止符 0xFF
	if ackBytes[38] != 0xFF {
		t.Fatalf("terminator = 0x%02x, want 0xFF", ackBytes[38])
	}
}

// TestBug6FeatureExtAckEmptyAckData 验证 AckData 为空时回退到 0 长度 (此前行为)。
func TestBug6FeatureExtAckEmptyAckData(t *testing.T) {
	cfg := defaultCfg()
	cfg.Version = TDSVersion74
	cfg.FeatureExts = []FeatureExt{{ID: 0x01}} // 无 AckData
	resp := buildLoginResponse(cfg)
	p, _ := ParsePacket(resp)
	// 找到 FEATUREEXTACK
	var ackBytes []byte
	for i := 0; i < len(p.Body); i++ {
		if p.Body[i] == TokenFeatureExtAck {
			ackBytes = p.Body[i:]
			break
		}
	}
	if ackBytes == nil {
		t.Fatalf("FEATUREEXTACK token not found")
	}
	// ackBytes[0]=AE, [1]=FeatureId=0x01, [2:6]=len=0, [6]=FF
	if ackBytes[1] != 0x01 {
		t.Fatalf("FeatureId = 0x%02x, want 0x01", ackBytes[1])
	}
	if l := binary.LittleEndian.Uint32(ackBytes[2:6]); l != 0 {
		t.Fatalf("FeatureAckDataLen = %d, want 0 (empty AckData)", l)
	}
	if ackBytes[6] != 0xFF {
		t.Fatalf("terminator = 0x%02x, want 0xFF", ackBytes[6])
	}
}

// TestBug6ValidateAckDataHex 验证 ValidateConfig 校验 ack_data 必须是合法 hex。
func TestBug6ValidateAckDataHex(t *testing.T) {
	cfg := defaultCfg()
	cfg.Version = TDSVersion74
	cfg.FeatureExts = []FeatureExt{{ID: 0x01, AckData: "zz"}}
	if err := ValidateConfig(cfg); err == nil {
		t.Fatalf("expected error for non-hex ack_data")
	}
}

// --- Bug 7: cellDataLen 补 BYTELEN 类型 + TypeVector ---
//
// 修复前 cellDataLen 未覆盖 BYTELEN char/binary 类型 (CHARTYPE/VARCHARTYPE/
// BINARYTYPE/VARBINARYTYPE) 与 VECTORTYPE，导致 COLMETADATA 列含这些类型时
// ParseResponse 落入 default 分支报 "unknown cell type"。

// TestBug7CellDataLenByteLenCharBinary 验证 BYTELEN char/binary 类型
// (CHAR/VARCHAR/BINARY/VARBINARY) 的 ROW cell 解析: 非 NULL = 1B 长度 + 数据,
// NULL = 1B GEN_NULL (0x00)。
func TestBug7CellDataLenByteLenCharBinary(t *testing.T) {
	for _, tc := range []struct {
		name     string
		typeInfo []byte
	}{
		{"CHAR", []byte{TypeChar}},
		{"VARCHAR", []byte{TypeVarChar}},
		{"BINARY", []byte{TypeBinary}},
		{"VARBINARY", []byte{TypeVarBinary}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// 非 NULL: 长度=5 + 5 字节数据 "hello"
			cellData := append([]byte{5}, []byte("hello")...)
			n, err := cellDataLen(cellData, tc.typeInfo)
			if err != nil {
				t.Fatalf("cellDataLen non-NULL: %v", err)
			}
			if n != 6 {
				t.Fatalf("non-NULL cellDataLen = %d, want 6 (1B len + 5B data)", n)
			}
			// NULL: GEN_NULL (1B 0x00)
			n, err = cellDataLen([]byte{0x00}, tc.typeInfo)
			if err != nil {
				t.Fatalf("cellDataLen NULL: %v", err)
			}
			if n != -1 {
				t.Fatalf("NULL cellDataLen = %d, want -1 (GEN_NULL 1B)", n)
			}
		})
	}
}

// TestBug7CellDataLenTypeVector 验证 VECTORTYPE 的 ROW cell 解析:
// 非 NULL = 2B LE 长度 + (8B VECTOR 头 + NN*sizeof(T)), NULL = 2B 0x0000
// (GEN_NULL 语义 + USHORTLEN 2B 前缀宽度, spec §2.4.4 第 1485-1489 行)。
func TestBug7CellDataLenTypeVector(t *testing.T) {
	ti := []byte{TypeVector}
	// 非 NULL: 2B 长度=11 + 8B VECTOR 头 (A9 01 02 00 00 00 00 00) + 3B 数据
	// 总 cellData = 2 + 11 = 13 字节
	vecPayload := []byte{0xA9, 0x01, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x12, 0x34, 0x56}
	cellData := make([]byte, 2+len(vecPayload))
	binary.LittleEndian.PutUint16(cellData[0:2], uint16(len(vecPayload)))
	copy(cellData[2:], vecPayload)
	n, err := cellDataLen(cellData, ti)
	if err != nil {
		t.Fatalf("cellDataLen non-NULL VECTOR: %v", err)
	}
	if n != 2+len(vecPayload) {
		t.Fatalf("non-NULL VECTOR cellDataLen = %d, want %d", n, 2+len(vecPayload))
	}
	// NULL: 2B 长度=0x0000 (GEN_NULL)
	n, err = cellDataLen([]byte{0x00, 0x00}, ti)
	if err != nil {
		t.Fatalf("cellDataLen NULL VECTOR: %v", err)
	}
	if n != -2 {
		t.Fatalf("NULL VECTOR cellDataLen = %d, want -2 (2B GEN_NULL)", n)
	}
}

// TestBug7ParseResponseByteLenCharRow 验证含 BYTELEN char 列的完整
// COLMETADATA + ROW 响应能被 ParseResponse 正确解析 (修复前会报错)。
func TestBug7ParseResponseByteLenCharRow(t *testing.T) {
	// COLMETADATA: 1 列 VARCHAR "c1" (TYPE_INFO = token + 1B BYTELEN maxlen)
	cm := BuildColMetadata([]ColMetadataColumn{
		{UserType: 0, Flags: 0, TypeInfo: []byte{TypeVarChar, 0xFF}, ColName: "c1"},
	}, false)
	// ROW: 长度=3 + "foo"
	row := BuildRow(append([]byte{3}, []byte("foo")...))
	tokens := append(cm, row...)
	done, _ := BuildDone(TokenDone, DONECount, 0, 1, true)
	tokens = append(tokens, done...)
	res, err := ParseResponse(tokens, true, TDSVersion74)
	if err != nil {
		t.Fatalf("ParseResponse with VARCHAR column: %v", err)
	}
	if res.ColCount != 1 {
		t.Fatalf("ColCount = %d, want 1", res.ColCount)
	}
	if res.RowCount != 1 {
		t.Fatalf("RowCount = %d, want 1", res.RowCount)
	}
}

// TestBug7ParseResponseVectorRow 验证含 VECTOR 列的完整 COLMETADATA + ROW
// 响应能被 ParseResponse 正确解析 (修复前会报 "unknown cell type 0xf5")。
func TestBug7ParseResponseVectorRow(t *testing.T) {
	// COLMETADATA: 1 列 VECTOR (带 SCALE=0x00 单精度 float)
	cm := BuildColMetadata([]ColMetadataColumn{
		{UserType: 0, Flags: 0, TypeInfo: []byte{TypeVector, 0x00}, ColName: "v1"},
	}, false)
	// ROW: 2B 长度 + 8B VECTOR 头 + 3*4B float32 数据
	vecPayload := []byte{0xA9, 0x01, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x80, 0x3F, 0x00, 0x00, 0x40, 0x40, 0x00, 0x80, 0x40}
	cellData := make([]byte, 2+len(vecPayload))
	binary.LittleEndian.PutUint16(cellData[0:2], uint16(len(vecPayload)))
	copy(cellData[2:], vecPayload)
	row := BuildRow(cellData)
	tokens := append(cm, row...)
	done, _ := BuildDone(TokenDone, DONECount, 0, 1, true)
	tokens = append(tokens, done...)
	res, err := ParseResponse(tokens, true, TDSVersion74)
	if err != nil {
		t.Fatalf("ParseResponse with VECTOR column: %v", err)
	}
	if res.ColCount != 1 {
		t.Fatalf("ColCount = %d, want 1", res.ColCount)
	}
	if res.RowCount != 1 {
		t.Fatalf("RowCount = %d, want 1", res.RowCount)
	}
}

// --- R3-NEW-01 (CRITICAL) 回归测试: RETURNVALUE token 解析 pos 偏移错误 ---
//
// 修复前 parser.go 第 660 行 `pos += 2` 只跳过 ParamOrdinal 却漏掉 TokenType
// 字节，导致 ParamName.BYTELEN 读到 ParamOrdinal 第二个字节、整条 RETURNVALUE
// 解析链全部错位。修复后 `pos += 3` (TokenType+ParamOrdinal)，并校验 ParamName
// 长度边界。

// buildReturnValueToken 构造一个 RETURNVALUE token (spec §3.13):
//
//	TokenType(0xAC) + ParamOrdinal(2B LE) + ParamName(B_VARCHAR)
//	+ Status(1B) + UserType(4B LE) + Flags(2B LE) + TypeInfo + Value
//
// 仅用于测试: typeInfo 由调用方提供 (覆盖 typeInfoLen/cellDataLen 行为),
// value 由调用方提供完整 TYPE_VARBYTE 编码。
func buildReturnValueToken(paramOrdinal uint16, paramName string, status byte,
	userType uint32, flags uint16, typeInfo []byte, value []byte) []byte {
	var out []byte
	out = append(out, TokenReturnValue)
	po := make([]byte, 2)
	binary.LittleEndian.PutUint16(po, paramOrdinal)
	out = append(out, po...)
	out = append(out, bVarChar(paramName)...)
	out = append(out, status)
	ut := make([]byte, 4)
	binary.LittleEndian.PutUint32(ut, userType)
	out = append(out, ut...)
	fl := make([]byte, 2)
	binary.LittleEndian.PutUint16(fl, flags)
	out = append(out, fl...)
	out = append(out, typeInfo...)
	out = append(out, value...)
	return out
}

// TestR3NEW01ReturnValueParseInt4 验证修复后 RETURNVALUE token 能被正确解析:
// ParamName=B_VARCHAR("@out"), TypeInfo=TypeInt4(0x38, 1B 定长), Value=4B int32=42。
// 修复前 pos+=2 会把 ParamOrdinal 高位字节当作 ParamName 长度，导致解析失败或
// 读取越界。
func TestR3NEW01ReturnValueParseInt4(t *testing.T) {
	// TypeInt4 (0x38): typeInfoLen=1, cellDataLen=4 (定长，无长度前缀)。
	typeInfo := []byte{TypeInt4}
	// Value: int32 LE = 42 (4B)。
	val := make([]byte, 4)
	binary.LittleEndian.PutUint32(val, 42)
	rv := buildReturnValueToken(1, "@out", 0x01, 0, 0, typeInfo, val)

	res, err := ParseResponse(rv, true, TDSVersion74)
	if err != nil {
		t.Fatalf("ParseResponse RETURNVALUE: %v", err)
	}
	if res.ReturnValues != 1 {
		t.Fatalf("ReturnValues = %d, want 1", res.ReturnValues)
	}
}

// TestR3NEW01ReturnValueTruncation 验证新增的 ParamName 长度边界校验: 当
// ParamName 声明的 BYTELEN 超出剩余负载时，ParseResponse 应返回 error 而非
// 错位解析。
//
// 构造的输入在修复前会被静默误解析:
//
//	[0xAC, 0x01, 0x00, 0x0A, 0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x38, 0x2A]
//
// 修复前 pos+=2 把 body[2]=0x00 (ParamOrdinal 高字节) 当作 ParamName 长度，
// 于是 pos 错位到 body[10]=0x38 (恰好是 TypeInt4)，typeInfoLen/cellDataLen
// 均"成功"返回，pos 越界 (15>12) 被外层循环条件静默掩盖——返回成功且
// ReturnValues=1。修复后 pos+=3 读到真实 BYTELEN=0x0A (10 字符=20B)，超出
// 剩余负载 (12-4=8B)，必须报错。
func TestR3NEW01ReturnValueTruncation(t *testing.T) {
	// TokenType(1) + ParamOrdinal(2) + ParamName BYTELEN=0x0A (声称 10 字符
	// =20B) + 截断的 ParamName 数据 + 2 字节尾部。
	rv := []byte{TokenReturnValue, 0x01, 0x00, 0x0A,
		0x41, 0x00, 0x42, 0x00, 0x43, 0x00, 0x38, 0x2A}
	if _, err := ParseResponse(rv, true, TDSVersion74); err == nil {
		t.Fatalf("expected truncation error for RETURNVALUE ParamName out of range")
	}
}

// --- R3-NEW-02 (HIGH) 回归测试: ENVCHANGE Type 15 Promote Transaction ---
//
// 修复前 parseEnvChange 对 Type 15 落入 default 分支按 B_VARBYTE 风格解析，
// 但 Type 15 的 2B Length 字段恒为 0x01 (仅含 Type 字节)，NewValue 的 L_VARBYTE
// (4B LE 长度 + DTC token 数据) 与 OldValue (%x00) 都在 Length 之外。修复后
// 调用点 ParseResponse 检测 Type==15 时单独读 L_VARBYTE+OldValue，并正确推进 pos。

// buildEnvChangeType15 手工构造 ENVCHANGE Type 15 的完整线路字节:
//
//	TokenType(0xE3) + Length(2B LE)=0x0001 + Type(1B)=0x0F
//	+ L_VARBYTE(4B LE 长度 + DTC token 数据)  ← 在 Length 之外
//	+ OldValue(%x00)                          ← 在 Length 之外
//
// dtcToken 是 NewValue 的 DTC token 数据 (不含 4B 长度前缀)。
func buildEnvChangeType15(dtcToken []byte) []byte {
	var out []byte
	out = append(out, TokenEnvChange)
	// Length = 0x0001 (仅覆盖 Type 字节)。
	out = append(out, 0x01, 0x00)
	// Type = 0x0F (15)。
	out = append(out, 0x0F)
	// NewValue: L_VARBYTE = 4B LE 长度 + DTC token 数据。
	lv := make([]byte, 4)
	binary.LittleEndian.PutUint32(lv, uint32(len(dtcToken)))
	out = append(out, lv...)
	out = append(out, dtcToken...)
	// OldValue: %x00。
	out = append(out, 0x00)
	return out
}

// TestR3NEW02EnvChangeType15Parse 验证 Type 15 Promote Transaction 能被解析:
// NewValue 应为完整 L_VARBYTE (4B 长度前缀 + DTC token 数据)，OldValue 应为空。
func TestR3NEW02EnvChangeType15Parse(t *testing.T) {
	dtcToken := []byte{0x00, 0x01, 0x02, 0x03, 0x04} // 5 字节示例 DTC token
	ec := buildEnvChangeType15(dtcToken)
	res, err := ParseResponse(ec, true, TDSVersion74)
	if err != nil {
		t.Fatalf("ParseResponse ENVCHANGE Type 15: %v", err)
	}
	if len(res.EnvChanges) != 1 {
		t.Fatalf("envchange count = %d, want 1", len(res.EnvChanges))
	}
	env := res.EnvChanges[0]
	if env.Type != 15 {
		t.Fatalf("envchange type = %d, want 15", env.Type)
	}
	// NewValue 应为完整 L_VARBYTE: 4B 长度前缀(0x05 0x00 0x00 0x00) + 5B DTC token。
	wantNew := append([]byte{0x05, 0x00, 0x00, 0x00}, dtcToken...)
	if !bytesEqual(env.NewValue, wantNew) {
		t.Fatalf("NewValue = %x, want %x", env.NewValue, wantNew)
	}
	// OldValue 应为空 (nil)。
	if env.OldValue != nil {
		t.Fatalf("OldValue = %x, want nil", env.OldValue)
	}
}

// TestR3NEW02EnvChangeType15FollowedByDone 验证 Type 15 后跟另一个 token 时
// pos 推进正确。修复前 pos 只跳过 Length=0x01 覆盖的部分 (TokenType+Length+Type
// =4 字节)，残留的 L_VARBYTE+OldValue 会被下一个 token 误解析，导致解析失败。
// 修复后 pos 跳过 TokenType+Length+Type+L_VARBYTE+OldValue，下一个 token (DONE)
// 能被正确识别。
func TestR3NEW02EnvChangeType15FollowedByDone(t *testing.T) {
	dtcToken := []byte{0xAA, 0xBB, 0xCC} // 3 字节 DTC token
	ec := buildEnvChangeType15(dtcToken)
	done, _ := BuildDone(TokenDone, DONEFinal, 0, 0, true)
	tokens := append(ec, done...)
	res, err := ParseResponse(tokens, true, TDSVersion74)
	if err != nil {
		t.Fatalf("ParseResponse: %v", err)
	}
	if len(res.EnvChanges) != 1 {
		t.Fatalf("envchange count = %d, want 1", len(res.EnvChanges))
	}
	if env := res.EnvChanges[0]; env.Type != 15 {
		t.Fatalf("envchange type = %d, want 15", env.Type)
	}
	if len(res.Dones) != 1 {
		t.Fatalf("done count = %d, want 1 (残留字节未正确跳过?)", len(res.Dones))
	}
}

// --- R3-NEW-03 (MEDIUM) 回归测试: obfuscatePassword 显式括号 ---
//
// Go 中 | 与 ^ 同优先级且左结合，原表达式 (b << 4) | (b >> 4) ^ 0xA5 实际计算
// 等同 ((b << 4) | (b >> 4)) ^ 0xA5，结果正确但易误读为 (b << 4) | ((b >> 4) ^
// 0xA5)。修复后加显式括号 ((b << 4) | (b >> 4)) ^ 0xA5，语义不变但意图清晰。
// 此测试通过逐字节对比验证两种写法结果一致，并锁定期望输出。

// TestR3NEW03ObfuscatePasswordExplicitParen 验证修复后的 obfuscatePassword
// 仍产生规范期望的输出: 高低 nibble 交换后异或 0xA5。
func TestR3NEW03ObfuscatePasswordExplicitParen(t *testing.T) {
	// 选取覆盖 nibble 边界的字节: 'p'=0x70, 'a'=0x61, 's'=0x73。
	pw := "pas"
	ucs := encodeUTF16(pw) // 6 字节: 0x70 0x00 0x61 0x00 0x73 0x00
	obf := obfuscatePassword(pw)
	if len(obf) != len(ucs) {
		t.Fatalf("obf length = %d, want %d", len(obf), len(ucs))
	}
	// 逐字节验证: swap_nibbles(b) ^ 0xA5。
	for i, b := range ucs {
		swapped := (b << 4) | (b >> 4) // 高低 nibble 交换 (byte 范围内)
		want := swapped ^ 0xA5
		if obf[i] != want {
			t.Errorf("obf[%d] = 0x%02x, want 0x%02x (b=0x%02x)", i, obf[i], want, b)
		}
	}
	// 锁定期望输出 (回归基线): swap_nibbles(0x70)=0x07, ^0xA5=0xA2;
	// 0x00→0x00→0xA5; 0x61→0x16→0xB3; 0x73→0x37→0x92。
	wantHex := "a2a5b3a592a5"
	if got := hex.EncodeToString(obf); got != wantHex {
		t.Fatalf("obf hex = %s, want %s", got, wantHex)
	}
}

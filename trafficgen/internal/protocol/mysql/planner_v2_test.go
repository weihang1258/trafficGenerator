package mysql

// Coverage tests for MySQL planner features added for prepared
// statements, transactions, multi-type result sets, custom OK/ERR,
// and full session scenarios.
//
// These tests are spec-driven (each corresponds to a MySQL protocol
// section) and follow the failing-first principle: any test in this
// file would have failed before the planner changes were implemented.

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// ===========================================================================
// 1. COM_STMT_PREPARE response ("prepare-ok" reply mode)
// ===========================================================================

// prepare-ok basic layout: PREPARE_OK body = 0x00 + stmt_id(4) +
// num_cols(2) + num_params(2) + reserved(1) + warning_count(2) = 12 bytes.
func TestMySQL_PrepareOK_BasicLayout(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x16, Body: "SELECT 1", ReplyMode: "prepare-ok",
			StmtID: 1, WarningCount: 0,
			ColDefs: []core.MySQLColDef{{Name: "1", OrgName: "1", Type: mysqlTypeLongLong, Charset: 33, Length: 1}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Layout: handshake(3) + greeting(1) + response(1) + authOK(1) +
	//   COM_STMT_PREPARE up(1) + prepare-ok reply:
	//     PREPARE_OK(1) + col_def(1) + EOF(1) = 3 down packets
	//   teardown(4) = 14 packets total
	if len(cfgs) != 14 {
		t.Fatalf("len=%d, want 14", len(cfgs))
	}
	// Find the down reply (after the COM_STMT_PREPARE up at cfgs[6]).
	// Replies start at cfgs[7].
	prepareOK := cfgs[7].Payload[4:] // strip 4-byte header
	if len(prepareOK) != 12 {
		t.Fatalf("PREPARE_OK body len=%d, want 12", len(prepareOK))
	}
	if prepareOK[0] != 0x00 {
		t.Errorf("status=0x%02x, want 0x00", prepareOK[0])
	}
	stmtID := binary.LittleEndian.Uint32(prepareOK[1:5])
	if stmtID != 1 {
		t.Errorf("stmt_id=%d, want 1", stmtID)
	}
	numCols := binary.LittleEndian.Uint16(prepareOK[5:7])
	if numCols != 1 {
		t.Errorf("num_cols=%d, want 1", numCols)
	}
	numParams := binary.LittleEndian.Uint16(prepareOK[7:9])
	if numParams != 0 {
		t.Errorf("num_params=%d, want 0", numParams)
	}
	if prepareOK[9] != 0x00 {
		t.Errorf("reserved=0x%02x, want 0x00", prepareOK[9])
	}
	warnings := binary.LittleEndian.Uint16(prepareOK[10:12])
	if warnings != 0 {
		t.Errorf("warning_count=%d, want 0", warnings)
	}
}

// prepare-ok with num_params > 0 emits param ColDefs + EOF + col ColDefs + EOF.
func TestMySQL_PrepareOK_WithParams(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x16, Body: "SELECT ?", ReplyMode: "prepare-ok",
			StmtID: 7,
			Params: []core.MySQLColDef{{Name: "?", OrgName: "?", Type: mysqlTypeVarchar, Charset: 33, Length: 255}},
			ColDefs: []core.MySQLColDef{{Name: "?", OrgName: "?", Type: mysqlTypeVarchar, Charset: 33, Length: 255}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Layout: handshake(3) + greeting(1) + response(1) + authOK(1) +
	//   STMT_PREPARE up(1) + reply: PREPARE_OK(1) + param def(1) + EOF(1) + col def(1) + EOF(1) = 5
	//   teardown(4) = 16 packets
	if len(cfgs) != 16 {
		t.Fatalf("len=%d, want 16", len(cfgs))
	}
	// Replies: cfgs[7] = PREPARE_OK, cfgs[8] = param def, cfgs[9] = EOF, cfgs[10] = col def, cfgs[11] = EOF.
	prepareOK := cfgs[7].Payload[4:]
	numParams := binary.LittleEndian.Uint16(prepareOK[7:9])
	if numParams != 1 {
		t.Errorf("num_params=%d, want 1", numParams)
	}
	// EOF packet body[0] = 0xfe
	if cfgs[9].Payload[4] != 0xfe {
		t.Errorf("EOF marker=0x%02x, want 0xfe", cfgs[9].Payload[4])
	}
	if cfgs[11].Payload[4] != 0xfe {
		t.Errorf("second EOF marker=0x%02x, want 0xfe", cfgs[11].Payload[4])
	}
}

// prepare-ok with no params and no cols (e.g. "DO 1") emits only PREPARE_OK.
func TestMySQL_PrepareOK_NoParamsNoCols(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x16, Body: "DO 1", ReplyMode: "prepare-ok", StmtID: 42},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Layout: handshake(3) + greeting(1) + response(1) + authOK(1) +
	//   STMT_PREPARE up(1) + PREPARE_OK(1) = 2 down packets
	//   teardown(4) = 12 packets
	if len(cfgs) != 12 {
		t.Fatalf("len=%d, want 12", len(cfgs))
	}
	prepareOK := cfgs[7].Payload[4:]
	numCols := binary.LittleEndian.Uint16(prepareOK[5:7])
	if numCols != 0 {
		t.Errorf("num_cols=%d, want 0", numCols)
	}
	numParams := binary.LittleEndian.Uint16(prepareOK[7:9])
	if numParams != 0 {
		t.Errorf("num_params=%d, want 0", numParams)
	}
}

// prepare-ok reply seq starts at 1 (server reply for command seq=0).
func TestMySQL_PrepareOK_SeqStartsAtOne(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x16, Body: "SELECT 1", ReplyMode: "prepare-ok", StmtID: 1},
	}
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[7].Payload[3] != 0x01 {
		t.Errorf("PREPARE_OK seq=%d, want 1", cfgs[7].Payload[3])
	}
}

// ===========================================================================
// 2. Binary protocol result row format ("binary-result" reply mode)
// ===========================================================================

// binary-result now emits column defs (previously missing!).
func TestMySQL_BinaryResult_EmitsColumnDefs(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x17, StmtID: 1, ReplyMode: "binary-result",
			ColDefs: []core.MySQLColDef{
				{Name: "id", OrgName: "id", Type: mysqlTypeLongLong, Charset: 33, Length: 11},
				{Name: "name", OrgName: "name", Type: mysqlTypeVarString, Charset: 33, Length: 50},
			},
			Rows: []core.MySQLRow{{Values: []string{"1", "alice"}}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Layout: handshake(3) + greeting(1) + response(1) + authOK(1) +
	//   STMT_EXECUTE up(1) + reply:
	//     column_count(1) + col_def(2) + EOF(1) + row(1) + EOF(1) = 6 down packets
	//   teardown(4) = 17 packets
	if len(cfgs) != 17 {
		t.Fatalf("len=%d, want 17", len(cfgs))
	}
	// First reply body = column_count (lenenc-int = 2 for 2 cols).
	colCountReply := cfgs[7].Payload[4:]
	if colCountReply[0] != 0x02 {
		t.Errorf("col_count=0x%02x, want 0x02", colCountReply[0])
	}
	// Second reply body = col_def for "id" (lenenc-encoded name).
	if !bytes.Contains(cfgs[8].Payload[4:], []byte("id")) {
		t.Errorf("first col_def missing 'id'")
	}
	// Third reply body = col_def for "name".
	if !bytes.Contains(cfgs[9].Payload[4:], []byte("name")) {
		t.Errorf("second col_def missing 'name'")
	}
	// Fourth reply body = EOF (0xfe).
	if cfgs[10].Payload[4] != 0xfe {
		t.Errorf("EOF marker=0x%02x, want 0xfe", cfgs[10].Payload[4])
	}
	// Fifth reply body = binary row (cfgs[11]).
	rowBody := cfgs[11].Payload[4:]
	if rowBody[0] != 0x00 {
		t.Errorf("binary row header=0x%02x, want 0x00", rowBody[0])
	}
	// Last reply = EOF.
	if cfgs[12].Payload[4] != 0xfe {
		t.Errorf("final EOF marker=0x%02x, want 0xfe", cfgs[12].Payload[4])
	}
}

// binary-result row header is always 0x00 (binary row marker).
func TestMySQL_BinaryResult_RowHeaderZero(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x17, StmtID: 1, ReplyMode: "binary-result",
			ColDefs: []core.MySQLColDef{{Name: "v", OrgName: "v", Type: mysqlTypeTiny, Charset: 33, Length: 4}},
			Rows:    []core.MySQLRow{{Values: []string{"42"}}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Layout: handshake(3) + greeting(1) + response(1) + authOK(1) +
	//   STMT_EXECUTE up(1) + col_count(1) + col_def(1) + EOF(1) + row(1) + EOF(1) + teardown(4) = 16.
	if len(cfgs) != 16 {
		t.Fatalf("len=%d, want 16", len(cfgs))
	}
	rowBody := cfgs[10].Payload[4:]
	if rowBody[0] != 0x00 {
		t.Errorf("row header=0x%02x, want 0x00", rowBody[0])
	}
}

// binary-result null bitmap uses bit_offset=2 (different from text rows).
func TestMySQL_BinaryResult_NullBitmapOffset(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x17, StmtID: 1, ReplyMode: "binary-result",
			ColDefs: []core.MySQLColDef{
				{Name: "a", OrgName: "a", Type: mysqlTypeTiny, Charset: 33, Length: 4},
				{Name: "b", OrgName: "b", Type: mysqlTypeTiny, Charset: 33, Length: 4},
			},
			Rows: []core.MySQLRow{{IsNull: []bool{true, false}, Values: []string{"", "2"}}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	rowBody := cfgs[11].Payload[4:]
	// body = 0x00 + 1-byte bitmap + values
	// bitmap with offset 2: col 0 null at bit (0+2)=2 of byte 0 -> 0x04
	if rowBody[1] != 0x04 {
		t.Errorf("null bitmap byte=0x%02x, want 0x04 (offset 2, col 0 null)", rowBody[1])
	}
}

// binary-result: integer values are fixed-width little-endian.
func TestMySQL_BinaryResult_LongLong8Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x17, StmtID: 1, ReplyMode: "binary-result",
			ColDefs: []core.MySQLColDef{{Name: "v", OrgName: "v", Type: mysqlTypeLongLong, Charset: 33, Length: 20}},
			Rows:    []core.MySQLRow{{Values: []string{"42"}}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Layout: handshake(3) + greeting(1) + response(1) + authOK(1) +
	//   STMT_EXECUTE up(1) + col_count(1) + col_def(1) + EOF(1) + row(1) + EOF(1) + teardown(4) = 16.
	if len(cfgs) != 16 {
		t.Fatalf("len=%d, want 16", len(cfgs))
	}
	rowBody := cfgs[10].Payload[4:]
	// rowBody: 0x00 + bitmap(1 byte for 1 col) + 8 bytes LE int = 10 bytes.
	if len(rowBody) != 10 {
		t.Fatalf("row body len=%d, want 10", len(rowBody))
	}
	// 8-byte LE for 42.
	val := binary.LittleEndian.Uint64(rowBody[2:10])
	if val != 42 {
		t.Errorf("value=%d, want 42", val)
	}
}

// binary-result: string values are length-encoded strings.
func TestMySQL_BinaryResult_StringAsLenenc(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x17, StmtID: 1, ReplyMode: "binary-result",
			ColDefs: []core.MySQLColDef{{Name: "v", OrgName: "v", Type: mysqlTypeVarchar, Charset: 33, Length: 50}},
			Rows:    []core.MySQLRow{{Values: []string{"hello"}}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	rowBody := cfgs[10].Payload[4:]
	// rowBody: 0x00 + bitmap(1) + lenenc-string("hello") = 8 bytes.
	if len(rowBody) != 8 {
		t.Fatalf("row body len=%d, want 8", len(rowBody))
	}
	if rowBody[2] != 0x05 {
		t.Errorf("lenenc length=0x%02x, want 0x05", rowBody[2])
	}
	if string(rowBody[3:]) != "hello" {
		t.Errorf("string=%q, want 'hello'", rowBody[3:])
	}
}

// ===========================================================================
// 3. Custom ERR packet ("err-custom" reply mode)
// ===========================================================================

// err-custom uses user-specified ErrCode/ErrSQLState/ErrMessage.
func TestMySQL_ErrCustom_DuplicateKey1062(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "INSERT INTO t VALUES (1)", ReplyMode: "err-custom",
			ErrCode: 1062, ErrSQLState: "23000", ErrMessage: "Duplicate entry '1' for key 'PRIMARY'"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	errBody := cfgs[7].Payload[4:]
	if errBody[0] != 0xff {
		t.Errorf("ERR marker=0x%02x, want 0xff", errBody[0])
	}
	errCode := binary.LittleEndian.Uint16(errBody[1:3])
	if errCode != 1062 {
		t.Errorf("error_code=%d, want 1062", errCode)
	}
	if !bytes.Contains(errBody, []byte("23000")) {
		t.Errorf("missing SQLSTATE 23000")
	}
	if !bytes.Contains(errBody, []byte("Duplicate entry")) {
		t.Errorf("missing custom message")
	}
}

// err-custom with no ErrSQLState falls back to "HY000".
func TestMySQL_ErrCustom_DefaultSQLState(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "BAD", ReplyMode: "err-custom",
			ErrCode: 1146, ErrMessage: "Table 'x.y' doesn't exist"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	errBody := cfgs[7].Payload[4:]
	if !bytes.Contains(errBody, []byte("HY000")) {
		t.Errorf("missing default SQLSTATE HY000")
	}
}

// ===========================================================================
// 4. Custom OK packet ("ok-custom" reply mode) + StatusFlags
// ===========================================================================

// ok-custom uses user-specified AffectedRows/LastInsertID/StatusFlags/Warnings.
func TestMySQL_OkCustom_AllFields(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "UPDATE t SET x=1", ReplyMode: "ok-custom",
			AffectedRows: 100, LastInsertID: 999, StatusFlags: serverStatusInTrans, Warnings: 5},
	}
	cfgs := drain(mustPlan(t, p, spec))
	okBody := cfgs[7].Payload[4:]
	if okBody[0] != 0x00 {
		t.Errorf("OK marker=0x%02x, want 0x00", okBody[0])
	}
	// Body layout: 0x00 + lenenc(affected) + lenenc(last_id) + status(2 LE) + warnings(2 LE).
	// 100 fits in 1 byte (0x64). 999 needs 2-byte lenenc (0xfc, 0xe7, 0x03).
	if okBody[1] != 0x64 {
		t.Errorf("affected_rows lenenc=0x%02x, want 0x64 (100)", okBody[1])
	}
	if okBody[2] != 0xfc || okBody[3] != 0xe7 || okBody[4] != 0x03 {
		t.Errorf("last_insert_id lenenc=%02x %02x %02x, want fc e7 03 (999)", okBody[2], okBody[3], okBody[4])
	}
	status := binary.LittleEndian.Uint16(okBody[5:7])
	if status != serverStatusInTrans {
		t.Errorf("status_flags=0x%04x, want 0x0001", status)
	}
	warnings := binary.LittleEndian.Uint16(okBody[7:9])
	if warnings != 5 {
		t.Errorf("warnings=%d, want 5", warnings)
	}
}

// "ok" mode with StatusFlags overrides the default (SERVER_STATUS_AUTOCOMMIT).
func TestMySQL_Ok_OverrideStatusFlags(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "BEGIN", ReplyMode: "ok", StatusFlags: serverStatusInTrans},
	}
	cfgs := drain(mustPlan(t, p, spec))
	okBody := cfgs[7].Payload[4:]
	status := binary.LittleEndian.Uint16(okBody[3:5])
	if status != serverStatusInTrans {
		t.Errorf("status_flags=0x%04x, want 0x0001 (IN_TRANS)", status)
	}
}

// Transaction scenario: BEGIN -> INSERT -> COMMIT all use status flags.
func TestMySQL_Transaction_StatusFlagsPropagation(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "BEGIN", ReplyMode: "ok", StatusFlags: serverStatusInTrans},
		{Opcode: 0x03, Body: "INSERT INTO t VALUES (1)", ReplyMode: "ok-insert", StatusFlags: serverStatusInTrans},
		{Opcode: 0x03, Body: "COMMIT", ReplyMode: "ok", StatusFlags: serverStatusAutocommit},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// BEGIN reply at cfgs[7].
	beginStatus := binary.LittleEndian.Uint16(cfgs[7].Payload[4+3 : 4+5])
	if beginStatus != serverStatusInTrans {
		t.Errorf("BEGIN status=0x%04x, want IN_TRANS", beginStatus)
	}
	// INSERT reply at cfgs[9] (cfgs[7]=begin reply, cfgs[8]=INSERT cmd, cfgs[9]=INSERT reply).
	insertStatus := binary.LittleEndian.Uint16(cfgs[9].Payload[4+3 : 4+5])
	if insertStatus != serverStatusInTrans {
		t.Errorf("INSERT status=0x%04x, want IN_TRANS", insertStatus)
	}
	// COMMIT reply at cfgs[11].
	commitStatus := binary.LittleEndian.Uint16(cfgs[11].Payload[4+3 : 4+5])
	if commitStatus != serverStatusAutocommit {
		t.Errorf("COMMIT status=0x%04x, want AUTOCOMMIT", commitStatus)
	}
}

// ===========================================================================
// 5. "no-reply" mode (COM_QUIT / COM_STMT_CLOSE)
// ===========================================================================

// no-reply mode emits no down packets for the command.
func TestMySQL_NoReply_COM_QUIT(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x01, ReplyMode: "no-reply"}, // COM_QUIT
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Layout: handshake(3) + greeting(1) + response(1) + authOK(1) +
	//   COM_QUIT up(1) + (no reply) + teardown(4) = 11 packets
	if len(cfgs) != 11 {
		t.Fatalf("len=%d, want 11", len(cfgs))
	}
	// Verify there's no down PSH-ACK packet between COM_QUIT and teardown.
	quitIdx := 6
	for i := quitIdx + 1; i < quitIdx+5 && i < len(cfgs); i++ {
		if cfgs[i].Direction == "down" && cfgs[i].L4.Flags == 0x18 {
			t.Errorf("cfgs[%d] is unexpected down reply", i)
		}
	}
}

// no-reply for COM_STMT_CLOSE (0x19) also emits no reply.
func TestMySQL_NoReply_COM_STMT_CLOSE(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x19, Body: string([]byte{0x01, 0x00, 0x00, 0x00}), ReplyMode: "no-reply"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + greeting(1) + response(1) + authOK(1) + STMT_CLOSE up(1) + teardown(4) = 11.
	if len(cfgs) != 11 {
		t.Fatalf("len=%d, want 11", len(cfgs))
	}
}

// ===========================================================================
// 6. COM_STMT_EXECUTE request auto-encoding
// ===========================================================================

// COM_STMT_EXECUTE auto-encodes request body when Body is empty and StmtID > 0.
func TestMySQL_StmtExecute_AutoEncodeBody(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x17, StmtID: 42, IterationCount: 1, StmtFlags: 0, ReplyMode: "binary-result",
			ColDefs: []core.MySQLColDef{{Name: "v", OrgName: "v", Type: mysqlTypeLongLong, Charset: 33, Length: 20}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	cmdBody := cfgs[6].Payload[4:] // strip 4-byte header
	// Expected: 0x17 + stmt_id(4 LE) + flags(1) + iteration_count(4 LE) = 10 bytes (no params).
	want := []byte{
		0x17,
		0x2a, 0x00, 0x00, 0x00, // stmt_id=42
		0x00,             // flags
		0x01, 0x00, 0x00, 0x00, // iteration_count=1
	}
	if !bytes.Equal(cmdBody, want) {
		t.Errorf("STMT_EXECUTE body=%x, want %x", cmdBody, want)
	}
}

// COM_STMT_EXECUTE with StmtParams auto-encodes null bitmap + types + values.
func TestMySQL_StmtExecute_AutoEncodeWithParams(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x17, StmtID: 7, IterationCount: 1, ReplyMode: "binary-result",
			ColDefs: []core.MySQLColDef{{Name: "v", OrgName: "v", Type: mysqlTypeLongLong, Charset: 33, Length: 20}},
			StmtParams: []core.MySQLStmtParam{
				{Type: mysqlTypeLongLong, Value: "100"},
			},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	cmdBody := cfgs[6].Payload[4:]
	// 0x17 + stmt_id(4) + flags(1) + iter_count(4) +
	//   null_bitmap(1 byte) + new_params_bind_flag(1) + param_type(2) + value(8 LE) = 22 bytes.
	if len(cmdBody) != 22 {
		t.Fatalf("body len=%d, want 22", len(cmdBody))
	}
	// null bitmap byte 0 = 0x00 (param 0 not null).
	if cmdBody[10] != 0x00 {
		t.Errorf("null bitmap=0x%02x, want 0x00", cmdBody[10])
	}
	if cmdBody[11] != 0x01 {
		t.Errorf("new_params_bind_flag=0x%02x, want 0x01", cmdBody[11])
	}
	// param type = 0x08 0x00 (LONGLONG, not unsigned).
	if cmdBody[12] != 0x08 || cmdBody[13] != 0x00 {
		t.Errorf("param type=%02x %02x, want 08 00", cmdBody[12], cmdBody[13])
	}
	// value = 100 LE uint64.
	val := binary.LittleEndian.Uint64(cmdBody[14:22])
	if val != 100 {
		t.Errorf("param value=%d, want 100", val)
	}
}

// COM_STMT_EXECUTE with IsNull param sets the null bitmap bit.
func TestMySQL_StmtExecute_NullParam(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x17, StmtID: 1, ReplyMode: "binary-result",
			StmtParams: []core.MySQLStmtParam{{Type: mysqlTypeLongLong, IsNull: true}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	cmdBody := cfgs[6].Payload[4:]
	// null bitmap (1 byte for 1 param, offset 0) = 0x01.
	if cmdBody[10] != 0x01 {
		t.Errorf("null bitmap=0x%02x, want 0x01", cmdBody[10])
	}
	// new_params_bind_flag(1) + param_type(2) = 3 bytes, no value (NULL).
	// Total = 10 (header) + 1 (bitmap) + 1 (bind flag) + 2 (param type) = 14 bytes.
	if len(cmdBody) != 14 {
		t.Errorf("body len=%d, want 14 (header + bitmap + bind flag + param type)", len(cmdBody))
	}
}

// COM_STMT_EXECUTE with user-provided Body takes precedence over auto-encode.
func TestMySQL_StmtExecute_UserBodyTakesPrecedence(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x17, StmtID: 999, Body: "RAW_BODY", ReplyMode: "ok"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	cmdBody := cfgs[6].Payload[4:]
	want := append([]byte{0x17}, []byte("RAW_BODY")...)
	if !bytes.Equal(cmdBody, want) {
		t.Errorf("body=%x, want %x (raw body)", cmdBody, want)
	}
}

// ===========================================================================
// 7. Multi-type text result set (different column types in single result)
// ===========================================================================

func TestMySQL_MultiTypeResultSet(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "SELECT * FROM t", ReplyMode: "result-set",
			ColDefs: []core.MySQLColDef{
				{Name: "id", OrgName: "id", Type: mysqlTypeLongLong, Charset: 33, Length: 11, Flags: 0x0003},
				{Name: "name", OrgName: "name", Type: mysqlTypeVarString, Charset: 33, Length: 50},
				{Name: "created_at", OrgName: "created_at", Type: mysqlTypeDatetime, Charset: 33, Length: 19},
				{Name: "active", OrgName: "active", Type: mysqlTypeTiny, Charset: 33, Length: 1},
			},
			Rows: []core.MySQLRow{{Values: []string{"1", "alice", "2026-07-31 12:00:00", "1"}}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + greeting(1) + response(1) + authOK(1) +
	//   cmd up(1) + reply:
	//     col_count(1) + col_def(4) + EOF(1) + row(1) + EOF(1) = 8 down packets
	//   teardown(4) = 19 packets
	if len(cfgs) != 19 {
		t.Fatalf("len=%d, want 19", len(cfgs))
	}
	// First col_def body contains "id" name.
	if !bytes.Contains(cfgs[8].Payload[4:], []byte("id")) {
		t.Errorf("col def for 'id' missing")
	}
	// All four column names should be present in their respective col defs.
	for i, name := range []string{"id", "name", "created_at", "active"} {
		if !bytes.Contains(cfgs[8+i].Payload[4:], []byte(name)) {
			t.Errorf("col def %d missing name %q", i, name)
		}
	}
}

// ===========================================================================
// 8. Large result set (many rows)
// ===========================================================================

func TestMySQL_LargeResultSet_20Rows(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	rows := make([]core.MySQLRow, 20)
	for i := range rows {
		rows[i] = core.MySQLRow{Values: []string{string(rune('A' + i%26)), "data"}}
	}
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "SELECT * FROM t", ReplyMode: "result-set",
			ColDefs: []core.MySQLColDef{
				{Name: "id", OrgName: "id", Type: mysqlTypeLongLong, Charset: 33, Length: 11},
				{Name: "name", OrgName: "name", Type: mysqlTypeVarString, Charset: 33, Length: 50},
			},
			Rows: rows,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + greeting(1) + response(1) + authOK(1) + cmd up(1) +
	//   col_count(1) + col_def(2) + EOF(1) + rows(20) + EOF(1) = 25 down packets
	//   teardown(4) = 36 packets
	if len(cfgs) != 36 {
		t.Fatalf("len=%d, want 36", len(cfgs))
	}
	// Last reply packet before teardown should be EOF.
	lastReply := cfgs[len(cfgs)-5] // 4 teardown packets + 1 final EOF
	if lastReply.Payload[4] != 0xfe {
		t.Errorf("final EOF marker=0x%02x, want 0xfe", lastReply.Payload[4])
	}
}

// ===========================================================================
// 9. Full session scenario (multi-command session)
// ===========================================================================

func TestMySQL_FullSession_HandshakeLoginQueryQuit(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		// SET NAMES utf8mb4 (text protocol, OK reply)
		{Opcode: 0x03, Body: "SET NAMES utf8mb4", ReplyMode: "ok"},
		// SELECT 1 (result-set with 1 row)
		{Opcode: 0x03, Body: "SELECT 1", ReplyMode: "result-set",
			ColDefs: []core.MySQLColDef{{Name: "1", OrgName: "1", Type: mysqlTypeLongLong, Charset: 33, Length: 1}},
			Rows:    []core.MySQLRow{{Values: []string{"1"}}},
		},
		// INSERT (ok-insert reply)
		{Opcode: 0x03, Body: "INSERT INTO t VALUES (1)", ReplyMode: "ok-insert"},
		// COM_QUIT (no-reply)
		{Opcode: 0x01, ReplyMode: "no-reply"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Layout: handshake(3) + greeting(1) + response(1) + authOK(1) = 6
	//   cmd0 SET NAMES up(1) + OK reply(1) = 2
	//   cmd1 SELECT up(1) + col_count(1) + col_def(1) + EOF(1) + row(1) + EOF(1) = 6
	//   cmd2 INSERT up(1) + OK reply(1) = 2
	//   cmd3 COM_QUIT up(1) + (no reply) = 1
	//   teardown(4)
	// Total = 6 + 2 + 6 + 2 + 1 + 4 = 21.
	if len(cfgs) != 21 {
		t.Fatalf("len=%d, want 21", len(cfgs))
	}
	// cmd0 at cfgs[6]: SET NAMES
	if cfgs[6].Payload[4] != 0x03 {
		t.Errorf("cmd0 opcode=0x%02x, want 0x03", cfgs[6].Payload[4])
	}
	if !bytes.Contains(cfgs[6].Payload[4:], []byte("SET NAMES utf8mb4")) {
		t.Errorf("cmd0 missing 'SET NAMES utf8mb4'")
	}
	// COM_QUIT is the last up PSH-ACK before teardown. Verify no down
	// PSH-ACK reply between COM_QUIT and the first FIN-ACK.
	for i := len(cfgs) - 4 - 1; i > 0; i-- {
		c := cfgs[i]
		if c.Direction == "up" && c.L4.Flags == 0x18 {
			// This should be COM_QUIT.
			if c.Payload[4] != 0x01 {
				t.Errorf("last up PSH-ACK opcode=0x%02x, want 0x01 (COM_QUIT)", c.Payload[4])
			}
			break
		}
	}
}

// ===========================================================================
// 10. Validate tests for new reply modes
// ===========================================================================

func TestMySQL_Validate_AcceptsNewReplyModes(t *testing.T) {
	p := NewPlanner()
	for _, mode := range []string{"ok-custom", "err-custom", "prepare-ok", "no-reply"} {
		spec := validMySQLSpec()
		spec.MySQL.Commands = []core.MySQLCommand{{Opcode: 0x0e, ReplyMode: mode}}
		if err := p.Validate(spec); err != nil {
			t.Errorf("ReplyMode=%q: Validate err=%v", mode, err)
		}
	}
}

func TestMySQL_Validate_RejectsUnknownMode(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{{Opcode: 0x0e, ReplyMode: "nonexistent"}}
	if err := p.Validate(spec); err == nil {
		t.Errorf("expected error for unknown ReplyMode")
	}
}

// ===========================================================================
// 11. encodeBinaryValue type coverage
// ===========================================================================

func TestMySQL_BinaryValue_IntegerTypes(t *testing.T) {
	if got := encodeBinaryValue(mysqlTypeTiny, false, "42", ""); !bytes.Equal(got, []byte{0x2a}) {
		t.Errorf("TINY=%x, want 0x2a", got)
	}
	if got := encodeBinaryValue(mysqlTypeShort, false, "256", ""); !bytes.Equal(got, []byte{0x00, 0x01}) {
		t.Errorf("SHORT=%x, want 00 01", got)
	}
	if got := encodeBinaryValue(mysqlTypeLong, false, "1", ""); !bytes.Equal(got, []byte{0x01, 0x00, 0x00, 0x00}) {
		t.Errorf("LONG=%x, want 01 00 00 00", got)
	}
}

func TestMySQL_BinaryValue_StringTypes(t *testing.T) {
	if got := encodeBinaryValue(mysqlTypeVarchar, false, "ab", ""); !bytes.Equal(got, []byte{0x02, 'a', 'b'}) {
		t.Errorf("VARCHAR=%x, want 02 61 62", got)
	}
}

// ===========================================================================
// 12. StatusFlags propagation in EOF packets for result-set
// ===========================================================================

// result-set with StatusFlags propagates to BOTH the first and last EOF.
func TestMySQL_ResultSet_PropagatesStatusFlags(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x03, Body: "SELECT 1", ReplyMode: "result-set",
			ColDefs: []core.MySQLColDef{{Name: "1", OrgName: "1", Type: mysqlTypeLongLong, Charset: 33, Length: 1}},
			StatusFlags: serverStatusInTrans,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// handshake(3) + greeting(1) + response(1) + authOK(1) + cmd up(1) +
	//   col_count(1) + col_def(1) + EOF(1) + (no rows) + EOF(1) = 5 down packets
	//   teardown(4) = 15 packets
	if len(cfgs) != 15 {
		t.Fatalf("len=%d, want 15", len(cfgs))
	}
	// First EOF at cfgs[9] (after col_count + col_def): body = 0xfe + warnings(2) + status_flags(2).
	firstEOF := cfgs[9].Payload[4:]
	if firstEOF[0] != 0xfe {
		t.Errorf("first EOF marker=0x%02x, want 0xfe", firstEOF[0])
	}
	status := binary.LittleEndian.Uint16(firstEOF[3:5])
	if status != serverStatusInTrans {
		t.Errorf("first EOF status=0x%04x, want IN_TRANS", status)
	}
	// Last EOF at cfgs[10] (after rows, which are empty).
	lastEOF := cfgs[10].Payload[4:]
	status2 := binary.LittleEndian.Uint16(lastEOF[3:5])
	if status2 != serverStatusInTrans {
		t.Errorf("last EOF status=0x%04x, want IN_TRANS", status2)
	}
}

// ===========================================================================
// 13. binary-result also propagates StatusFlags to EOFs
// ===========================================================================

func TestMySQL_BinaryResult_PropagatesStatusFlags(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x17, StmtID: 1, ReplyMode: "binary-result",
			ColDefs: []core.MySQLColDef{{Name: "v", OrgName: "v", Type: mysqlTypeLongLong, Charset: 33, Length: 20}},
			StatusFlags: serverStatusInTrans,
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Find the EOF packets. Layout: handshake(3) + greeting(1) + response(1) + authOK(1) +
	//   STMT_EXECUTE up(1) + col_count(1) + col_def(1) + EOF(1) + (no rows) + EOF(1) = 5
	//   teardown(4) = 16.
	firstEOF := cfgs[10].Payload[4:]
	status := binary.LittleEndian.Uint16(firstEOF[3:5])
	if status != serverStatusInTrans {
		t.Errorf("first EOF status=0x%04x, want IN_TRANS", status)
	}
}

// ===========================================================================
// 14. End-to-end: full prepared statement flow
// ===========================================================================

func TestMySQL_PreparedStatementFlow_STMT_PREPARE_EXECUTE_CLOSE(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		// COM_STMT_PREPARE
		{Opcode: 0x16, Body: "SELECT ?", ReplyMode: "prepare-ok",
			StmtID: 1,
			Params: []core.MySQLColDef{{Name: "?", OrgName: "?", Type: mysqlTypeVarchar, Charset: 33, Length: 255}},
			ColDefs: []core.MySQLColDef{{Name: "?", OrgName: "?", Type: mysqlTypeVarchar, Charset: 33, Length: 255}},
		},
		// COM_STMT_EXECUTE (auto-encoded body, binary result)
		{Opcode: 0x17, StmtID: 1, ReplyMode: "binary-result",
			ColDefs: []core.MySQLColDef{{Name: "?", OrgName: "?", Type: mysqlTypeVarchar, Charset: 33, Length: 255}},
			Rows:    []core.MySQLRow{{Values: []string{"hello"}}},
			StmtParams: []core.MySQLStmtParam{{Type: mysqlTypeVarchar, Value: "hello"}},
		},
		// COM_STMT_CLOSE
		{Opcode: 0x19, Body: string([]byte{0x01, 0x00, 0x00, 0x00}), ReplyMode: "no-reply"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	// Verify that the command opcodes appear in order.
	// Up commands at cfgs[6], cfgs[13], cfgs[20] (after greeting+auth).
	expectedOpcodes := []uint8{0x16, 0x17, 0x19}
	cmdIdx := 6
	for i, op := range expectedOpcodes {
		actualIdx := cmdIdx
		// Find next up PSH-ACK after the previous one.
		for j := actualIdx; j < len(cfgs); j++ {
			if cfgs[j].Direction == "up" && cfgs[j].L4.Flags == 0x18 {
				actualIdx = j
				break
			}
		}
		if cfgs[actualIdx].Payload[4] != op {
			t.Errorf("cmd[%d] opcode=0x%02x, want 0x%02x", i, cfgs[actualIdx].Payload[4], op)
		}
		cmdIdx = actualIdx + 1
	}
	// Total: handshake(3) + greeting(1) + response(1) + authOK(1) = 6
	//   cmd0 STMT_PREPARE up(1) + PREPARE_OK(1) + param def(1) + EOF(1) + col def(1) + EOF(1) = 5
	//   cmd1 STMT_EXECUTE up(1) + col_count(1) + col_def(1) + EOF(1) + row(1) + EOF(1) = 6
	//   cmd2 STMT_CLOSE up(1) + (no reply) = 1
	//   teardown(4) = 23 packets
	if len(cfgs) != 23 {
		t.Fatalf("len=%d, want 23", len(cfgs))
	}
}

// ===========================================================================
// 15. COM_STMT_EXECUTE auto-encode: unsigned flag
// ===========================================================================

func TestMySQL_StmtExecute_UnsignedFlag(t *testing.T) {
	p := NewPlanner()
	spec := validMySQLSpec()
	spec.MySQL.Commands = []core.MySQLCommand{
		{Opcode: 0x17, StmtID: 1, ReplyMode: "binary-result",
			StmtParams: []core.MySQLStmtParam{{Type: mysqlTypeLongLong, Unsigned: true, Value: "100"}},
		},
	}
	cfgs := drain(mustPlan(t, p, spec))
	cmdBody := cfgs[6].Payload[4:]
	// param type = 0x08 0x80 (LONGLONG + UNSIGNED flag in MSB).
	if cmdBody[12] != 0x08 || cmdBody[13] != 0x80 {
		t.Errorf("param type=%02x %02x, want 08 80 (unsigned)", cmdBody[12], cmdBody[13])
	}
}
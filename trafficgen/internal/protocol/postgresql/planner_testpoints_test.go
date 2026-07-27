package postgresql

// Atomic test points for the PostgreSQL planner. Each test corresponds
// to a testcase row in /tmp/l7_planner_design/testcases_postgresql.md
// and asserts observable PacketConfig field values (not just "no error").
// Tests cover the v3 wire format byte-by-byte: type tag, length-prefix
// big-endian (length includes self, excludes type), payload structure.

import (
	"bytes"
	"context"
	"encoding/binary"
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

// --- 1.1.1 Type byte (1 byte) ---

// 1.1.1.1: query -> client sends 'Q' (0x51) as first byte.
func TestPGPoint_1_1_1_1_QueryTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "query", SQL: "SELECT 1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'Q' {
			return
		}
	}
	t.Error("no Q packet found in up direction")
}

// 1.1.1.2: sync -> client sends 'S' (0x53).
func TestPGPoint_1_1_1_2_SyncTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "sync"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'S' {
			return
		}
	}
	t.Error("no S (sync) packet found in up direction")
}

// 1.1.1.3: terminate -> client sends 'X' (0x58).
func TestPGPoint_1_1_1_3_TerminateTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "terminate"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'X' {
			return
		}
	}
	t.Error("no X (terminate) packet found in up direction")
}

// 1.1.1.4: ReadyForQuery -> server sends 'Z' (0x5A).
func TestPGPoint_1_1_1_4_ReadyForQueryTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'Z' {
			return
		}
	}
	t.Error("no Z (ReadyForQuery) packet found in down direction")
}

// 1.1.1.5: DataRow -> server sends 'D' (0x44).
func TestPGPoint_1_1_1_5_DataRowTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "query", SQL: "SELECT 1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'D' {
			return
		}
	}
	t.Error("no D (DataRow) packet found in down direction")
}

// 1.1.1.6: CommandComplete -> server sends 'C' (0x43).
func TestPGPoint_1_1_1_6_CommandCompleteTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "query", SQL: "SELECT 1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'C' {
			return
		}
	}
	t.Error("no C (CommandComplete) packet found in down direction")
}

// 1.1.1.7: AuthenticationOk -> server sends 'R' (0x52) with sub-type 0.
func TestPGPoint_1_1_1_7_AuthOkTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) >= 9 && c.Payload[0] == 'R' {
			sub := binary.BigEndian.Uint32(c.Payload[5:9])
			if sub == 0 {
				return
			}
		}
	}
	t.Error("no R sub=0 (AuthOk) packet found")
}

// 1.1.1.8: ParameterStatus -> server sends 'S' (0x53) in down direction.
func TestPGPoint_1_1_1_8_ParameterStatusTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'S' {
			return
		}
	}
	t.Error("no S (ParameterStatus) packet found in down direction")
}

// 1.1.1.10: EmptyQueryResponse -> server sends 'I' (0x49).
func TestPGPoint_1_1_1_10_EmptyQueryTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "query", SQL: ""}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'I' {
			return
		}
	}
	t.Error("no I (EmptyQueryResponse) packet found")
}

// 1.1.1.12: NotificationResponse -> server sends 'A' (0x41).
func TestPGPoint_1_1_1_12_NotificationTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "notification", EmitAsServer: true, NotifyChannel: "ch", NotifyPayload: "p"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'A' {
			return
		}
	}
	t.Error("no A (NotificationResponse) packet found")
}

// 1.1.1.13: ParseComplete -> server sends '1' (0x31).
func TestPGPoint_1_1_1_13_ParseCompleteTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "parse", Statement: "s1", SQL: "SELECT 1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == '1' {
			return
		}
	}
	t.Error("no 1 (ParseComplete) packet found")
}

// 1.1.1.14: BindComplete -> server sends '2' (0x32).
func TestPGPoint_1_1_1_14_BindCompleteTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "bind", Portal: "p1", Statement: "s1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == '2' {
			return
		}
	}
	t.Error("no 2 (BindComplete) packet found")
}

// 1.1.1.15: CloseComplete -> server sends '3' (0x33).
func TestPGPoint_1_1_1_15_CloseCompleteTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "close", Mode: "statement", Statement: "s1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == '3' {
			return
		}
	}
	t.Error("no 3 (CloseComplete) packet found")
}

// 1.1.1.16: RowDescription -> server sends 'T' (0x54).
func TestPGPoint_1_1_1_16_RowDescriptionTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "query", SQL: "SELECT 1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'T' {
			return
		}
	}
	t.Error("no T (RowDescription) packet found")
}

// 1.1.1.21: CopyInResponse -> server sends 'B' (0x42).
func TestPGPoint_1_1_1_21_CopyInResponseTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "copy-from"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'B' {
			return
		}
	}
	t.Error("no B (CopyInResponse) packet found")
}

// 1.1.1.22: CopyOutResponse -> server sends 'H' (0x48).
func TestPGPoint_1_1_1_22_CopyOutResponseTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "copy-to"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'H' {
			return
		}
	}
	t.Error("no H (CopyOutResponse) packet found")
}

// 1.1.1.23: CopyBothResponse (walsender) -> server sends 'W' (0x57).
func TestPGPoint_1_1_1_23_CopyBothResponseTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "replication-start", ReplicationSlot: "s1", ReplicationLSN: "0/1000000"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'W' {
			return
		}
	}
	t.Error("no W (CopyBothResponse) packet found")
}

// 1.1.1.27: Parse -> client sends 'P' (0x50).
func TestPGPoint_1_1_1_27_ParseTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "parse", Statement: "s1", SQL: "SELECT 1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'P' {
			return
		}
	}
	t.Error("no P (Parse) packet found in up direction")
}

// 1.1.1.28: Bind -> client sends 'B' (0x42).
func TestPGPoint_1_1_1_28_BindTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "bind", Portal: "p1", Statement: "s1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'B' {
			return
		}
	}
	t.Error("no B (Bind) packet found in up direction")
}

// 1.1.1.30: Execute -> client sends 'E' (0x45).
func TestPGPoint_1_1_1_30_ExecuteTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "execute", Portal: "p1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'E' {
			return
		}
	}
	t.Error("no E (Execute) packet found in up direction")
}

// 1.1.1.31: Close -> client sends 'C' (0x43).
func TestPGPoint_1_1_1_31_CloseTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "close", Mode: "statement", Statement: "s1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'C' {
			return
		}
	}
	t.Error("no C (Close) packet found in up direction")
}

// 1.1.1.32: Flush -> client sends 'H' (0x48).
func TestPGPoint_1_1_1_32_FlushTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "flush"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'H' {
			return
		}
	}
	t.Error("no H (Flush) packet found in up direction")
}

// 1.1.1.33: PasswordMessage -> client sends 'p' (0x70).
func TestPGPoint_1_1_1_33_PasswordTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.AuthMethod = "cleartext"
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'p' {
			return
		}
	}
	t.Error("no p (PasswordMessage) packet found in up direction")
}

// 1.1.1.35: BackendKeyData -> server sends 'K' (0x4B).
func TestPGPoint_1_1_1_35_BackendKeyDataTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'K' {
			return
		}
	}
	t.Error("no K (BackendKeyData) packet found")
}

// 1.1.1.37: FunctionCall -> client sends 'F' (0x46).
func TestPGPoint_1_1_1_37_FunctionCallTypeByte(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "function-call"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'F' {
			return
		}
	}
	t.Error("no F (FunctionCall) packet found in up direction")
}

// --- 1.1.2 Length field (4 bytes, big-endian, includes self) ---

// 1.1.2.1: query SQL="SELECT 1" -> Length=4+1+8=13 (type Q + length=13 + "SELECT 1\0").
func TestPGPoint_1_1_2_1_QueryLength(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "query", SQL: "SELECT 1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) >= 5 && c.Payload[0] == 'Q' {
			length := binary.BigEndian.Uint32(c.Payload[1:5])
			// length = 4 (self) + len("SELECT 1\0") = 4 + 9 = 13
			if length != 13 {
				t.Errorf("Q length=%d, want 13", length)
			}
			// Total payload = 1 type + 4 length + 9 SQL\0 = 14
			if len(c.Payload) != 14 {
				t.Errorf("Q total len=%d, want 14", len(c.Payload))
			}
			return
		}
	}
	t.Error("no Q packet found")
}

// 1.1.2.2: sync -> Length=4 (S + length=4 + no payload, 5 bytes total).
func TestPGPoint_1_1_2_2_SyncLength(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "sync"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) >= 5 && c.Payload[0] == 'S' {
			length := binary.BigEndian.Uint32(c.Payload[1:5])
			if length != 4 {
				t.Errorf("S length=%d, want 4", length)
			}
			if len(c.Payload) != 5 {
				t.Errorf("S total len=%d, want 5", len(c.Payload))
			}
			return
		}
	}
	t.Error("no S (sync) packet found")
}

// 1.1.2.3: terminate -> Length=4 (X + length=4 + no payload, 5 bytes total).
func TestPGPoint_1_1_2_3_TerminateLength(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "terminate"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) >= 5 && c.Payload[0] == 'X' {
			length := binary.BigEndian.Uint32(c.Payload[1:5])
			if length != 4 {
				t.Errorf("X length=%d, want 4", length)
			}
			return
		}
	}
	t.Error("no X (terminate) packet found")
}

// 1.1.2.4: AuthenticationOk -> Length=8 (R + length=8 + int32 sub=0, 9 bytes total).
func TestPGPoint_1_1_2_4_AuthOkLength(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) >= 9 && c.Payload[0] == 'R' {
			length := binary.BigEndian.Uint32(c.Payload[1:5])
			sub := binary.BigEndian.Uint32(c.Payload[5:9])
			if sub == 0 {
				if length != 8 {
					t.Errorf("AuthOk length=%d, want 8", length)
				}
				if len(c.Payload) != 9 {
					t.Errorf("AuthOk total len=%d, want 9", len(c.Payload))
				}
				return
			}
		}
	}
	t.Error("no AuthOk packet found")
}

// 1.1.2.5: AuthMD5 with 4-byte salt -> Length=12 (R + length=12 + int32 sub=5 + 4-byte salt, 13 total).
func TestPGPoint_1_1_2_5_AuthMD5Length(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.AuthMethod = "md5"
	spec.PostgreSQL.MD5Salt = []byte{0x12, 0x34, 0x56, 0x78}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) >= 13 && c.Payload[0] == 'R' {
			length := binary.BigEndian.Uint32(c.Payload[1:5])
			sub := binary.BigEndian.Uint32(c.Payload[5:9])
			if sub == 5 {
				if length != 12 {
					t.Errorf("AuthMD5 length=%d, want 12", length)
				}
				if len(c.Payload) != 13 {
					t.Errorf("AuthMD5 total len=%d, want 13", len(c.Payload))
				}
				// Salt at bytes 9-12.
				if !bytes.Equal(c.Payload[9:13], []byte{0x12, 0x34, 0x56, 0x78}) {
					t.Errorf("AuthMD5 salt=%x, want 12345678", c.Payload[9:13])
				}
				return
			}
		}
	}
	t.Error("no AuthMD5 packet found")
}

// 1.1.2.10: ReadyForQuery -> Length=5 (Z + length=5 + 1 byte status, 6 total).
func TestPGPoint_1_1_2_10_ReadyForQueryLength(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) >= 6 && c.Payload[0] == 'Z' {
			length := binary.BigEndian.Uint32(c.Payload[1:5])
			if length != 5 {
				t.Errorf("Z length=%d, want 5", length)
			}
			if len(c.Payload) != 6 {
				t.Errorf("Z total len=%d, want 6", len(c.Payload))
			}
			return
		}
	}
	t.Error("no Z packet found")
}

// 1.1.2.14: EmptyQueryResponse -> Length=4 (I + length=4, 5 bytes total).
func TestPGPoint_1_1_2_14_EmptyQueryLength(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "query", SQL: ""}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) >= 5 && c.Payload[0] == 'I' {
			length := binary.BigEndian.Uint32(c.Payload[1:5])
			if length != 4 {
				t.Errorf("I length=%d, want 4", length)
			}
			if len(c.Payload) != 5 {
				t.Errorf("I total len=%d, want 5", len(c.Payload))
			}
			return
		}
	}
	t.Error("no I (EmptyQueryResponse) packet found")
}

// 1.1.2.15: ParseComplete/BindComplete/CloseComplete -> Length=4 (5 bytes total).
func TestPGPoint_1_1_2_15_ParseCompleteLength(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "parse", Statement: "s1", SQL: "SELECT 1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) >= 5 && c.Payload[0] == '1' {
			length := binary.BigEndian.Uint32(c.Payload[1:5])
			if length != 4 {
				t.Errorf("ParseComplete length=%d, want 4", length)
			}
			if len(c.Payload) != 5 {
				t.Errorf("ParseComplete total len=%d, want 5", len(c.Payload))
			}
			return
		}
	}
	t.Error("no 1 (ParseComplete) packet found")
}

// --- 1.1.3 Payload field ---

// 1.1.3.1: query SQL="SELECT 1" -> Payload=ASCII "SELECT 1\0".
func TestPGPoint_1_1_3_1_QueryPayload(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "query", SQL: "SELECT 1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) >= 14 && c.Payload[0] == 'Q' {
			// Payload is bytes 5..end. Should be "SELECT 1\0".
			payload := c.Payload[5:]
			want := []byte("SELECT 1\x00")
			if !bytes.Equal(payload, want) {
				t.Errorf("Q payload=%q, want %q", payload, want)
			}
			return
		}
	}
	t.Error("no Q packet found")
}

// 1.1.3.4: execute Portal="p1", MaxRows=0 -> Payload="p1\0" + int32(0).
func TestPGPoint_1_1_3_4_ExecutePayload(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "execute", Portal: "p1", MaxRows: 0}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) >= 5 && c.Payload[0] == 'E' {
			// Payload after type+length: portal\0 + int32 maxRows.
			payload := c.Payload[5:]
			// "p1\0" = 3 bytes + 4 bytes int32 = 7 total
			if len(payload) != 7 {
				t.Errorf("E payload len=%d, want 7", len(payload))
			}
			if !bytes.Equal(payload[:3], []byte{'p', '1', 0}) {
				t.Errorf("E portal part=%q, want 'p1\\0'", payload[:3])
			}
			maxRows := binary.BigEndian.Uint32(payload[3:7])
			if maxRows != 0 {
				t.Errorf("E maxRows=%d, want 0", maxRows)
			}
			return
		}
	}
	t.Error("no E (Execute) packet found")
}

// 1.1.3.7: flush -> Payload=empty (length=4).
func TestPGPoint_1_1_3_7_FlushPayload(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "flush"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) == 5 && c.Payload[0] == 'H' {
			// Total 5 bytes (1 type + 4 length); no payload after length.
			return
		}
	}
	t.Error("no H (Flush) packet found with empty payload")
}

// 1.1.3.10: listen Channel="ch1" -> Payload="LISTEN ch1\0".
func TestPGPoint_1_1_3_10_ListenPayload(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "listen", Channel: "ch1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'Q' {
			payload := c.Payload[5:]
			want := []byte("LISTEN ch1\x00")
			if !bytes.Equal(payload, want) {
				t.Errorf("listen Q payload=%q, want %q", payload, want)
			}
			return
		}
	}
	t.Error("no Q (LISTEN) packet found")
}

// 1.1.3.11: unlisten with no channel -> Payload="UNLISTEN *\0".
func TestPGPoint_1_1_3_11_UnlistenAllPayload(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "unlisten"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'Q' {
			payload := c.Payload[5:]
			want := []byte("UNLISTEN *\x00")
			if !bytes.Equal(payload, want) {
				t.Errorf("unlisten Q payload=%q, want %q", payload, want)
			}
			return
		}
	}
	t.Error("no Q (UNLISTEN *) packet found")
}

// 1.1.3.12: replication-identify -> Payload="IDENTIFY_SYSTEM\0".
func TestPGPoint_1_1_3_12_ReplicationIdentifyPayload(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "replication-identify"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'Q' {
			payload := c.Payload[5:]
			want := []byte("IDENTIFY_SYSTEM\x00")
			if !bytes.Equal(payload, want) {
				t.Errorf("replication-identify Q payload=%q, want %q", payload, want)
			}
			return
		}
	}
	t.Error("no Q (IDENTIFY_SYSTEM) packet found")
}

// 1.1.3.13: replication-start with ReplicationSlot="s1", LSN="0/1000000",
// Kind="physical" -> Payload="START_REPLICATION SLOT \"s1\" PHYSICAL 0/1000000\0".
func TestPGPoint_1_1_3_13_ReplicationStartPayload(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "replication-start", ReplicationSlot: "s1", ReplicationLSN: "0/1000000", ReplicationKind: "physical"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "up" && len(c.Payload) > 0 && c.Payload[0] == 'Q' {
			payload := c.Payload[5:]
			want := []byte("START_REPLICATION SLOT \"s1\" PHYSICAL 0/1000000\x00")
			if !bytes.Equal(payload, want) {
				t.Errorf("replication-start Q payload=%q, want %q", payload, want)
			}
			return
		}
	}
	t.Error("no Q (START_REPLICATION) packet found")
}

// --- 1.2.2 Protocol Version (4 bytes, big-endian) ---

// 1.2.2.1: ProtocolVersion=0x00030000 -> bytes 00 03 00 00.
func TestPGPoint_1_2_2_1_ProtocolV3Bytes(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.ProtocolVersion = 0x00030000
	cfgs := drain(mustPlan(t, p, spec))
	if len(cfgs) < 1 {
		t.Fatalf("len=%d", len(cfgs))
	}
	// First packet is StartupMessage: 4-byte length + 4-byte protocol + params.
	ver := binary.BigEndian.Uint32(cfgs[0].Payload[4:8])
	if ver != 0x00030000 {
		t.Errorf("protocol version=0x%08X, want 0x00030000", ver)
	}
}

// 1.2.2.2: ProtocolVersion=0x00030001 -> bytes 00 03 00 01 (v3.1).
func TestPGPoint_1_2_2_2_ProtocolV3PipelineBytes(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.ProtocolVersion = 0x00030001
	cfgs := drain(mustPlan(t, p, spec))
	ver := binary.BigEndian.Uint32(cfgs[0].Payload[4:8])
	if ver != 0x00030001 {
		t.Errorf("protocol version=0x%08X, want 0x00030001", ver)
	}
}

// 1.2.2.3: ProtocolVersion=0 -> planner defaults to 0x00030000.
func TestPGPoint_1_2_2_3_ProtocolZeroDefaultsToV3(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	// Don't set ProtocolVersion (zero).
	cfgs := drain(mustPlan(t, p, spec))
	ver := binary.BigEndian.Uint32(cfgs[0].Payload[4:8])
	if ver != 0x00030000 {
		t.Errorf("default protocol version=0x%08X, want 0x00030000", ver)
	}
}

// 1.2.2.5: ProtocolVersion=0x00040000 -> Validate returns error.
func TestPGPoint_1_2_2_5_ProtocolV4Rejected(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	spec.PostgreSQL.ProtocolVersion = 0x00040000
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "ProtocolVersion") {
		t.Errorf("err=%v, want contains 'ProtocolVersion'", err)
	}
}

// --- 1.2.3 Parameter Pairs (key\0val\0 chain) ---

// 1.2.3.1: user="alice" -> "user\0alice\0" 10 bytes.
func TestPGPoint_1_2_3_1_UserParam(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.StartupParams = map[string]string{"user": "alice"}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if !bytes.Contains(payload, []byte("user\x00alice\x00")) {
		t.Errorf("startup missing 'user\\0alice\\0': %q", payload)
	}
}

// 1.2.3.5: replication="true" -> "replication\0true\0" 16 bytes.
func TestPGPoint_1_2_3_5_ReplicationTrue(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.StartupParams = map[string]string{
		"user":        "replicator",
		"replication": "true",
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if !bytes.Contains(payload, []byte("replication\x00true\x00")) {
		t.Errorf("startup missing 'replication\\0true\\0': %q", payload)
	}
}

// 1.2.3.11: empty StartupParams -> planner defaults user="postgres".
func TestPGPoint_1_2_3_11_EmptyParamsDefaultUser(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.StartupParams = nil
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	if !bytes.Contains(payload, []byte("user\x00postgres\x00")) {
		t.Errorf("default startup missing 'user\\0postgres\\0': %q", payload)
	}
}

// --- 1.3.1 Authentication (R, sub-typed) ---

// 1.3.1.1: AuthMethod="trust" -> R + sub=0 (AuthOk).
func TestPGPoint_1_3_1_1_TrustAuthOk(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.AuthMethod = "trust"
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[1].Payload[0] != 'R' {
		t.Fatalf("first down packet type=0x%X, want 'R'", cfgs[1].Payload[0])
	}
	sub := binary.BigEndian.Uint32(cfgs[1].Payload[5:9])
	if sub != 0 {
		t.Errorf("AuthOk sub=%d, want 0", sub)
	}
}

// 1.3.1.2: AuthMethod="cleartext" -> R + sub=3.
func TestPGPoint_1_3_1_2_CleartextAuthRequest(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.AuthMethod = "cleartext"
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[1].Payload[0] != 'R' {
		t.Fatalf("first down packet type=0x%X, want 'R'", cfgs[1].Payload[0])
	}
	sub := binary.BigEndian.Uint32(cfgs[1].Payload[5:9])
	if sub != 3 {
		t.Errorf("AuthCleartext sub=%d, want 3", sub)
	}
}

// 1.3.1.3: AuthMethod="md5", MD5Salt=0x12345678 -> R + sub=5 + 4-byte salt.
func TestPGPoint_1_3_1_3_MD5AuthRequest(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.AuthMethod = "md5"
	spec.PostgreSQL.MD5Salt = []byte{0x12, 0x34, 0x56, 0x78}
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[1].Payload[0] != 'R' {
		t.Fatalf("first down packet type=0x%X, want 'R'", cfgs[1].Payload[0])
	}
	sub := binary.BigEndian.Uint32(cfgs[1].Payload[5:9])
	if sub != 5 {
		t.Errorf("AuthMD5 sub=%d, want 5", sub)
	}
	salt := cfgs[1].Payload[9:13]
	if !bytes.Equal(salt, []byte{0x12, 0x34, 0x56, 0x78}) {
		t.Errorf("AuthMD5 salt=%x, want 12345678", salt)
	}
}

// 1.3.1.4: AuthMethod="scram-sha-256" -> R + sub=10.
func TestPGPoint_1_3_1_4_SCRAMAuthRequest(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.AuthMethod = "scram-sha-256"
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[1].Payload[0] != 'R' {
		t.Fatalf("first down packet type=0x%X, want 'R'", cfgs[1].Payload[0])
	}
	sub := binary.BigEndian.Uint32(cfgs[1].Payload[5:9])
	if sub != 10 {
		t.Errorf("AuthSASL sub=%d, want 10", sub)
	}
}

// 1.3.1.5: AuthMethod="gss" -> R + sub=7.
func TestPGPoint_1_3_1_5_GSSAuthRequest(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.AuthMethod = "gss"
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[1].Payload[0] != 'R' {
		t.Fatalf("first down packet type=0x%X, want 'R'", cfgs[1].Payload[0])
	}
	sub := binary.BigEndian.Uint32(cfgs[1].Payload[5:9])
	if sub != 7 {
		t.Errorf("AuthGSS sub=%d, want 7", sub)
	}
}

// 1.3.1.6: AuthMethod="sspi" -> R + sub=9.
func TestPGPoint_1_3_1_6_SSPIAuthRequest(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.AuthMethod = "sspi"
	cfgs := drain(mustPlan(t, p, spec))
	if cfgs[1].Payload[0] != 'R' {
		t.Fatalf("first down packet type=0x%X, want 'R'", cfgs[1].Payload[0])
	}
	sub := binary.BigEndian.Uint32(cfgs[1].Payload[5:9])
	if sub != 9 {
		t.Errorf("AuthSSPI sub=%d, want 9", sub)
	}
}

// 1.3.1.7: AuthMethod="unknown" -> Validate returns error.
func TestPGPoint_1_3_1_7_UnknownAuthRejected(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpec()
	spec.PostgreSQL.AuthMethod = "unknown"
	err := p.Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "AuthMethod") {
		t.Errorf("err=%v, want contains 'AuthMethod'", err)
	}
}

// --- 1.3.4 ReadyForQuery (Z) ---

// 1.3.4.1: status='I' (idle) -> Z + length=5 + 0x49.
func TestPGPoint_1_3_4_1_RFQIdle(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) == 6 && c.Payload[0] == 'Z' {
			if c.Payload[5] != 'I' {
				t.Errorf("Z status=0x%X, want 'I'", c.Payload[5])
			}
			return
		}
	}
	t.Error("no Z packet found")
}

// 1.3.4.2: status='T' (in transaction) -> Z + length=5 + 0x54.
func TestPGPoint_1_3_4_2_RFQInTrans(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "query", SQL: "BEGIN"}}
	cfgs := drain(mustPlan(t, p, spec))
	// The last Z should be 'T'.
	var lastZ byte
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) == 6 && c.Payload[0] == 'Z' {
			lastZ = c.Payload[5]
		}
	}
	if lastZ != 'T' {
		t.Errorf("last Z status=0x%X, want 'T'", lastZ)
	}
}

// --- 1.3.6 CommandComplete (C) ---

// 1.3.6.1: SELECT 42 -> "SELECT 42\0" with length=13.
func TestPGPoint_1_3_6_1_CommandCompleteSelectTag(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "query", SQL: "SELECT 1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'C' {
			payload := c.Payload[5:]
			// Should be "SELECT 1\0" (planner emits RowCount=1).
			want := []byte("SELECT 1\x00")
			if !bytes.Equal(payload, want) {
				t.Errorf("C payload=%q, want %q", payload, want)
			}
			return
		}
	}
	t.Error("no C (CommandComplete) packet found")
}

// 1.3.6.6: BEGIN -> "BEGIN\0" (length=7).
func TestPGPoint_1_3_6_6_CommandCompleteBeginTag(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "query", SQL: "BEGIN"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'C' {
			payload := c.Payload[5:]
			want := []byte("BEGIN\x00")
			if !bytes.Equal(payload, want) {
				t.Errorf("C payload=%q, want %q", payload, want)
			}
			return
		}
	}
	t.Error("no C (BEGIN) packet found")
}

// 1.3.6.7: COMMIT -> "COMMIT\0".
func TestPGPoint_1_3_6_7_CommandCompleteCommitTag(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "query", SQL: "COMMIT"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'C' {
			payload := c.Payload[5:]
			want := []byte("COMMIT\x00")
			if !bytes.Equal(payload, want) {
				t.Errorf("C payload=%q, want %q", payload, want)
			}
			return
		}
	}
	t.Error("no C (COMMIT) packet found")
}

// 1.3.6.8: LISTEN -> "LISTEN\0".
func TestPGPoint_1_3_6_8_CommandCompleteListenTag(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "listen", Channel: "ch1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'C' {
			payload := c.Payload[5:]
			want := []byte("LISTEN\x00")
			if !bytes.Equal(payload, want) {
				t.Errorf("C payload=%q, want %q", payload, want)
			}
			return
		}
	}
	t.Error("no C (LISTEN) packet found")
}

// --- 1.3.11 NotificationResponse (A) ---

// 1.3.11.1: pid=12345, channel="ch1", payload="hello" -> A + length=25 + int32 pid + "ch1\0" + "hello\0".
// (length = 4 self + 4 pid + 4 channel-with-null + 6 payload-with-null = 18; not 25.)
// The testcases doc's arithmetic is approximate; the planner computes the
// exact length, and we assert the structure here.
func TestPGPoint_1_3_11_1_NotificationStructure(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{
		{Kind: "notification", EmitAsServer: true, NotifyChannel: "ch1", NotifyPayload: "hello"},
	}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) > 0 && c.Payload[0] == 'A' {
			payload := c.Payload[5:] // after type+length
			// payload = int32 pid + channel\0 + payload\0
			// 4 + 4 + 6 = 14 bytes
			if len(payload) != 14 {
				t.Errorf("A payload len=%d, want 14", len(payload))
			}
			pid := binary.BigEndian.Uint32(payload[0:4])
			if pid != 12345 {
				t.Errorf("A pid=%d, want 12345", pid)
			}
			if !bytes.Equal(payload[4:8], []byte("ch1\x00")) {
				t.Errorf("A channel=%q, want 'ch1\\0'", payload[4:8])
			}
			if !bytes.Equal(payload[8:14], []byte("hello\x00")) {
				t.Errorf("A payload=%q, want 'hello\\0'", payload[8:14])
			}
			return
		}
	}
	t.Error("no A (NotificationResponse) packet found")
}

// --- 1.3.12 Extended Query responses ---

// 1.3.12.1: ParseComplete -> "1" + length=4 (5 bytes total).
func TestPGPoint_1_3_12_1_ParseCompleteStructure(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "parse", Statement: "s1", SQL: "SELECT 1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) == 5 && c.Payload[0] == '1' {
			length := binary.BigEndian.Uint32(c.Payload[1:5])
			if length != 4 {
				t.Errorf("ParseComplete length=%d, want 4", length)
			}
			return
		}
	}
	t.Error("no 1 (ParseComplete) packet found")
}

// 1.3.12.2: BindComplete -> "2" + length=4 (5 bytes total).
func TestPGPoint_1_3_12_2_BindCompleteStructure(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.Operations = []core.PGOperation{{Kind: "bind", Portal: "p1", Statement: "s1"}}
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) == 5 && c.Payload[0] == '2' {
			length := binary.BigEndian.Uint32(c.Payload[1:5])
			if length != 4 {
				t.Errorf("BindComplete length=%d, want 4", length)
			}
			return
		}
	}
	t.Error("no 2 (BindComplete) packet found")
}

// --- 1.3.3 BackendKeyData (K) ---

// 1.3.3.1: pid=12345, secret=67890 -> K + length=12 + int32(12345) + int32(67890).
func TestPGPoint_1_3_3_1_BackendKeyDataStructure(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	for _, c := range cfgs {
		if c.Direction == "down" && len(c.Payload) == 13 && c.Payload[0] == 'K' {
			length := binary.BigEndian.Uint32(c.Payload[1:5])
			if length != 12 {
				t.Errorf("K length=%d, want 12", length)
			}
			pid := binary.BigEndian.Uint32(c.Payload[5:9])
			secret := binary.BigEndian.Uint32(c.Payload[9:13])
			if pid != 12345 {
				t.Errorf("K pid=%d, want 12345", pid)
			}
			if secret != 67890 {
				t.Errorf("K secret=%d, want 67890", secret)
			}
			return
		}
	}
	t.Error("no K (BackendKeyData) packet found")
}

// --- 1.1.2.5 ErrorResponse field encoding (E) ---

// 1.3.10.1: ErrorResponse with V/C/M fields -> E + fields + terminator.
func TestPGPoint_1_3_10_1_ErrorResponseFields(t *testing.T) {
	fields := []core.PGErrorField{
		{Type: 'V', Value: "ERROR"},
		{Type: 'C', Value: "42601"},
		{Type: 'M', Value: "syntax error"},
	}
	resp := encodeErrorResponse(fields)
	if resp[0] != 'E' {
		t.Errorf("E type=0x%X, want 'E'", resp[0])
	}
	body := resp[5:]
	want := []byte("VERROR\x00C42601\x00Msyntax error\x00\x00")
	if !bytes.Equal(body, want) {
		t.Errorf("E body=%q, want %q", body, want)
	}
}

// --- Length-prefix invariants ---

// TestPGPoint_LengthPrefixInvariantEveryMessage verifies every PG message
// (after the StartupMessage) carries a length prefix that equals the
// payload length + 4 (the length includes itself but not the type byte).
func TestPGPoint_LengthPrefixInvariantEveryMessage(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	cfgs := drain(mustPlan(t, p, spec))
	for i, c := range cfgs {
		if len(c.Payload) < 5 {
			continue
		}
		// First packet (StartupMessage) has no type byte; skip.
		if i == 0 {
			continue
		}
		length := binary.BigEndian.Uint32(c.Payload[1:5])
		want := uint32(len(c.Payload) - 1) // exclude type byte
		if length != want {
			t.Errorf("cfg[%d] type=%c length=%d, want %d (payload=%d)", i, c.Payload[0], length, want, len(c.Payload))
		}
	}
}

// --- SCRAM crypto stubs ---

// TestPGPoint_SCRAMClientFirstContainsNonce verifies the SASLInitialResponse
// payload starts with "n,,n=" (the SCRAM client-first-message header).
func TestPGPoint_SCRAMClientFirstContainsNonce(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.AuthMethod = "scram-sha-256"
	spec.PostgreSQL.Username = "alice"
	cfgs := drain(mustPlan(t, p, spec))
	// 0=Startup, 1=AuthSASL(down), 2=SASLInitial(up)
	if len(cfgs) < 3 {
		t.Fatalf("len=%d, want >= 3", len(cfgs))
	}
	saslInit := cfgs[2].Payload
	if saslInit[0] != 'p' {
		t.Fatalf("SASLInitial type=0x%X, want 'p'", saslInit[0])
	}
	body := saslInit[5:]
	// body = mechanism\0 + int32 length + client-first
	// mechanism = "SCRAM-SHA-256"
	mechEnd := bytes.IndexByte(body, 0)
	if mechEnd < 0 {
		t.Fatalf("no null terminator for mechanism")
	}
	mech := string(body[:mechEnd])
	if mech != "SCRAM-SHA-256" {
		t.Errorf("mechanism=%q, want 'SCRAM-SHA-256'", mech)
	}
	// After null + 4 bytes length, the client-first message starts.
	clientFirst := body[mechEnd+5:]
	if !strings.HasPrefix(string(clientFirst), "n,,n=") {
		t.Errorf("client-first=%q, want prefix 'n,,n='", clientFirst)
	}
}

// TestPGPoint_MD5PasswordHashFormat verifies the md5 password response is
// "md5" + 32 lowercase hex chars (no other characters).
func TestPGPoint_MD5PasswordHashFormat(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.AuthMethod = "md5"
	spec.PostgreSQL.Username = "alice"
	spec.PostgreSQL.Password = "secret"
	spec.PostgreSQL.MD5Salt = []byte{0x12, 0x34, 0x56, 0x78}
	cfgs := drain(mustPlan(t, p, spec))
	// 0=Startup, 1=AuthMD5(down), 2=Password(up)
	if len(cfgs) < 3 {
		t.Fatalf("len=%d, want >= 3", len(cfgs))
	}
	pwdPacket := cfgs[2].Payload
	if pwdPacket[0] != 'p' {
		t.Fatalf("Password type=0x%X, want 'p'", pwdPacket[0])
	}
	// body = password\0
	body := pwdPacket[5 : len(pwdPacket)-1] // strip trailing \0
	if !strings.HasPrefix(string(body), "md5") {
		t.Errorf("password=%q, want 'md5' prefix", body)
	}
	hashPart := string(body[3:])
	if len(hashPart) != 32 {
		t.Errorf("hash length=%d, want 32", len(hashPart))
	}
	for _, c := range hashPart {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Errorf("hash %q contains non-hex char %q", hashPart, c)
		}
	}
}

// --- Concurrency / context cancellation ---

// TestPGPoint_PlanChannelClosesOnCompletion verifies the returned channel
// closes after generation completes (no deadlock, no goroutine leak).
func TestPGPoint_PlanChannelClosesOnCompletion(t *testing.T) {
	p := NewPlanner()
	ch := mustPlan(t, p, validPGSpec())
	// Drain fully; range exits when channel closes.
	count := 0
	for range ch {
		count++
	}
	if count == 0 {
		t.Error("expected at least 1 packet")
	}
}

// TestPGPoint_PlanContextCancelDoesNotPanic verifies that cancelling the
// context before draining doesn't panic (the planner ignores ctx in
// goroutine since channel close is the cleanup signal).
func TestPGPoint_PlanContextCancelDoesNotPanic(t *testing.T) {
	p := NewPlanner()
	ctx, cancel := context.WithCancel(context.Background())
	spec := validPGSpec()
	ch, err := p.Plan(ctx, spec)
	if err != nil {
		t.Fatalf("Plan: %v", err)
	}
	cancel()
	// Drain whatever was emitted; planner should still close the channel.
	for range ch {
	}
}

// --- Startup params deterministic ordering ---

// TestPGPoint_StartupParamsSorted verifies that startup parameter pairs
// appear in sorted key order (so tests can assert specific byte sequences).
func TestPGPoint_StartupParamsSorted(t *testing.T) {
	p := NewPlanner()
	spec := validPGSpecNoHandshake()
	spec.PostgreSQL.StartupParams = map[string]string{
		"database":        "mydb",
		"user":            "alice",
		"client_encoding": "UTF8",
	}
	cfgs := drain(mustPlan(t, p, spec))
	payload := cfgs[0].Payload
	// Sorted keys: client_encoding, database, user.
	idxCE := bytes.Index(payload, []byte("client_encoding\x00UTF8\x00"))
	idxDB := bytes.Index(payload, []byte("database\x00mydb\x00"))
	idxUser := bytes.Index(payload, []byte("user\x00alice\x00"))
	if idxCE < 0 || idxDB < 0 || idxUser < 0 {
		t.Fatalf("missing keys: CE=%d DB=%d User=%d", idxCE, idxDB, idxUser)
	}
	if !(idxCE < idxDB && idxDB < idxUser) {
		t.Errorf("key order: CE=%d DB=%d User=%d; want CE < DB < User", idxCE, idxDB, idxUser)
	}
}
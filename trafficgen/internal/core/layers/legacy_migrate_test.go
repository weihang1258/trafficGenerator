package layers_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/protocol/a2a"
	_ "github.com/trafficgen/trafficgen/internal/protocol/dnp3"
	_ "github.com/trafficgen/trafficgen/internal/protocol/doip"
	_ "github.com/trafficgen/trafficgen/internal/protocol/enip"
	_ "github.com/trafficgen/trafficgen/internal/protocol/gbt32960"
	_ "github.com/trafficgen/trafficgen/internal/protocol/mqtt"
	"github.com/trafficgen/trafficgen/internal/protocol/nfs"
	_ "github.com/trafficgen/trafficgen/internal/protocol/smb"
	_ "github.com/trafficgen/trafficgen/internal/protocol/socks5"
	"github.com/trafficgen/trafficgen/internal/protocol/tds"
)

// TestLegacyPlannerRegression_ChainSufficient verifies that for every
// protocol registered via legacy NewPlanner() in cmd/server/main.go AND
// migrated to NewChainPlanner, the chain path alone produces a non-empty
// packet stream from a minimal FlowSpec. This is the regression gate for
// Task 4.1 batch 1 — if a future chain migration breaks output, this
// test fails BEFORE the protocol gets flipped in main.go.
//
// The list must match the protocols whose main.go registration is
// flipped from <proto>.NewPlanner() to layers.NewChainPlanner(<proto>).
// Each entry is a minimal spec exercising the chain's terminal + transport
// (handlers for the protocol's mandatory config live in
// internal/protocol/<proto>/).
func TestLegacyPlannerRegression_ChainSufficient(t *testing.T) {
	cases := []struct {
		proto string
		spec  core.FlowSpec
	}{
		// socks5: tcp 终结层，配置在 FlowSpec.Socks（core.SocksConfig）。
		{"socks5", core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			SrcPort: 36164, DstPort: 1080,
			Socks: &core.SocksConfig{},
		}},
		// mqtt: tcp 终结层，配置在 FlowSpec.MQTT（core.MQTTConfig）。
		{"mqtt", core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			SrcPort: 36164, DstPort: 1883,
			MQTT: &core.MQTTConfig{},
		}},
		// gbt32960: tcp 终结层，配置在 FlowSpec.GBT32960（vehicle 必填四件）。
		{"gbt32960", core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			SrcPort: 20000, DstPort: 10020,
			SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
			GBT32960: &core.GBT32960Config{
				Role:                         "vehicle",
				VIN:                          "LXXXXXXXXXXXXXXX1",
				LoginSerialNumber:            1,
				RechargeableSubsysCount:      1,
				RechargeableSubsysCodeLength: 1,
				RechargeableSubsysCodes:      []string{"00"},
			},
		}},
		// tftp: udp 终结层，配置在 FlowSpec.TFTP。
		{"tftp", core.FlowSpec{
			SrcIP: "10.0.0.100", DstIP: "10.0.0.1",
			SrcPort: 49152, DstPort: 69,
			TFTP: &core.TFTPConfig{
				Filename:           "file.bin",
				Mode:               "read",
				BlocksCount:        1,
				DataPayloadPattern: []byte("x"),
			},
		}},
		// doip: tcp 终结层（Activation + Diagnostic 单包），配置在 FlowSpec.DoIP。
		{"doip", core.FlowSpec{
			SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
			SrcPort: 12345, DstPort: 13400,
			DoIP: &core.DoIPConfig{
				Activation: &core.DoIPActivation{
					Direction:      "up",
					ActivationType: 0x00,
					ResponseCode:   0x10,
				},
				Messages: []core.DoIPMessage{{
					Direction: "up",
					UserData:  []byte{0x22, 0xF1, 0x90, 0x01},
				}},
			},
		}},
		// smb: tcp 终结层，配置在 FlowSpec.SMB（空 config 合法）。
		{"smb", core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 49152, DstPort: 445,
			SMB: &core.SMBConfig{},
		}},
		// nfs: tcp 终结层，配置走 FlowSpec.Metadata["nfs"]（外部类型）。
		{"nfs", nfsMinimalSpec()},
		// tds: tcp 终结层，配置走 FlowSpec.Payload（JSON 编码 TDSConfig）。
		{"tds", tdsMinimalSpec()},
		// enip: tcp 终结层，配置在 FlowSpec.ENIP（ENIPConfig）。
		{"enip", core.FlowSpec{
			SrcIP: "192.168.1.100", DstIP: "192.168.1.1",
			SrcPort: 49152, DstPort: 44818,
			ENIP: &core.ENIPConfig{
				Transport: "tcp",
				Commands:  []core.ENIPCommand{{Command: 0x0004}}, // CmdListServices
			},
		}},
		// modbus: tcp 终结层，配置在 FlowSpec.MODBUS。
		{"modbus", core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
			SrcPort: 1234, DstPort: 502,
			MODBUS: &core.MODBUSConfig{
				Transactions: []core.MODBUSOperation{{FunctionCode: 3, StartingAddress: 0, Quantity: 4}},
			},
		}},
		// dnp3: tcp 终结层，配置在 FlowSpec.DNP3（空 config 也合法）。
		{"dnp3", core.FlowSpec{
			SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
			SrcPort: 5000, DstPort: 20000,
			DNP3: &core.DNP3Config{Scenario: "reset_link"},
		}},
		// a2a: tcp 终结层，配置走 FlowSpec.Payload（JSON 编码 A2AConfig）。
		{"a2a", a2aMinimalSpec()},
	}
	for _, c := range cases {
		t.Run(c.proto, func(t *testing.T) {
			ch, err := layers.NewChainPlanner(c.proto).Plan(context.Background(), c.spec)
			if err != nil {
				t.Fatalf("Plan err: %v", err)
			}
			n := 0
			for range ch {
				n++
			}
			if n == 0 {
				t.Errorf("chain produced 0 packets for %s — chain path insufficient", c.proto)
			}
		})
	}
}

// nfsMinimalSpec returns the minimal NFSv3 spec carrying one GETATTR op
// via spec.Metadata["nfs"]（外部类型 nfs.NFSConfig）。
func nfsMinimalSpec() core.FlowSpec {
	cfg := &nfs.NFSConfig{
		Version: 3,
		Ops: []nfs.NFSOp{
			{Procedure: 18}, // NFS3ProcGETATTR = 18
		},
	}
	return nfs.AttachSpec(core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "10.0.0.2",
		SrcPort: 50000, DstPort: 2049,
	}, cfg)
}

// tdsMinimalSpec returns the minimal TDS spec carrying one PRELOGIN session
// via spec.Payload（JSON 编码 TDSConfig）。
func tdsMinimalSpec() core.FlowSpec {
	cfg := &tds.TDSConfig{
		Sessions: []tds.SessionSpec{{
			ID: "s1",
			Requests: []tds.RequestSpec{{
				Type: tds.RequestSQLBatch,
				Sql:  &tds.SqlBatchSpec{Statements: []tds.StatementSpec{{Text: "select 'foo'"}}},
			}},
		}},
	}
	raw, _ := json.Marshal(cfg)
	return core.FlowSpec{
		SrcIP: "10.0.0.1", DstIP: "20.0.0.1",
		SrcPort: 50000, DstPort: 1433,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Payload: raw,
	}
}

// a2aMinimalSpec returns the minimal A2A spec carrying one message-send
// task via spec.Payload（JSON 编码 A2AConfig）。
func a2aMinimalSpec() core.FlowSpec {
	cfg := &a2a.A2AConfig{
		BaseURL: "https://agent.example.com/a2a",
		AgentCard: &a2a.A2AAgentCard{
			Name: "test", Description: "d", URL: "u", Version: "1.0",
			ProtocolVersion:    "0.3.0",
			Capabilities:       &a2a.A2AAgentCapabilities{},
			Skills:             []a2a.A2AAgentSkill{{ID: "s1", Name: "test", Description: "d", Tags: []string{"test"}}},
			DefaultInputModes:  []string{"text"},
			DefaultOutputModes: []string{"text"},
		},
		Tasks: []a2a.A2ATask{{
			Method: a2a.MethodMessageSend,
			Message: a2a.A2AMessage{
				Role:      "user",
				Parts:     []a2a.A2APart{{Kind: "text", Text: "hello"}},
				MessageID: "m-001",
				Kind:      a2a.DefaultMessageKind,
			},
			RequestID: json.RawMessage(`"req-001"`),
		}},
	}
	raw, _ := json.Marshal(cfg)
	return core.FlowSpec{
		SrcIP: "192.168.1.1", DstIP: "192.168.1.2",
		SrcPort: 12345, DstPort: 443,
		SrcMAC: "aa:bb:cc:dd:ee:ff", DstMAC: "11:22:33:44:55:66",
		Payload: raw,
	}
}

package layers_test

import (
	"context"
	"encoding/json"

	"github.com/trafficgen/trafficgen/internal/core"
	grpcproto "github.com/trafficgen/trafficgen/internal/protocol/grpc"
	gtpproto "github.com/trafficgen/trafficgen/internal/protocol/gtp"
	ikeproto "github.com/trafficgen/trafficgen/internal/protocol/ike"
	ikenatproto "github.com/trafficgen/trafficgen/internal/protocol/ike_nat_t"
	imapproto "github.com/trafficgen/trafficgen/internal/protocol/imap"
	l2tpproto "github.com/trafficgen/trafficgen/internal/protocol/l2tp"
	mysqlproto "github.com/trafficgen/trafficgen/internal/protocol/mysql"
	openvpnproto "github.com/trafficgen/trafficgen/internal/protocol/openvpn"
	pop3proto "github.com/trafficgen/trafficgen/internal/protocol/pop3"
	rdpproto "github.com/trafficgen/trafficgen/internal/protocol/rdp"
	redisproto "github.com/trafficgen/trafficgen/internal/protocol/redis"
	ssproto "github.com/trafficgen/trafficgen/internal/protocol/shadowsocks"
	smtpproto "github.com/trafficgen/trafficgen/internal/protocol/smtp"
	sshproto "github.com/trafficgen/trafficgen/internal/protocol/ssh"
	vmessproto "github.com/trafficgen/trafficgen/internal/protocol/vmess"
	wgproto "github.com/trafficgen/trafficgen/internal/protocol/wireguard"
)

// legacySpecJSON builds the flat config map for a protocol and runs it
// through the exported core.ConvertFlatSpec — the production entry point.
// Both the chain and legacy paths in the equivalence test receive the SAME
// resulting FlowSpec, so schema defaults (DstPort, TCP sub-config
// presence) apply equally to both sides. This mirrors what the API layer
// does for every task.
func legacySpecJSON(protocol string, fields map[string]interface{}) core.FlowSpec {
	cfg := map[string]interface{}{"protocol": protocol}
	for k, v := range fields {
		cfg[k] = v
	}
	raw, _ := json.Marshal(cfg)
	var m map[string]interface{}
	_ = json.Unmarshal(raw, &m) // normalize numbers to float64
	return core.ConvertFlatSpec(m, protocol)
}

// chainEquivalenceBatch2LegacyAdapters maps each batch-2 protocol to its
// legacy NewPlanner().Plan entry point. Aliased imports avoid collision with
// the blank chain-registration imports in chain_equivalence_batch2_test.go.
func grpcPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return grpcproto.NewPlanner().Plan(ctx, spec)
}

func gtpPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return gtpproto.NewPlanner().Plan(ctx, spec)
}

func ikePlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return ikeproto.NewPlanner().Plan(ctx, spec)
}

func ikeNatTPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return ikenatproto.NewPlanner().Plan(ctx, spec)
}

func imapPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return imapproto.NewPlanner().Plan(ctx, spec)
}

func l2tpPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return l2tpproto.NewPlanner().Plan(ctx, spec)
}

func mysqlPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return mysqlproto.NewPlanner().Plan(ctx, spec)
}

func openvpnPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return openvpnproto.NewPlanner().Plan(ctx, spec)
}

func pop3Plan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return pop3proto.NewPlanner().Plan(ctx, spec)
}

func rdpPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return rdpproto.NewPlanner().Plan(ctx, spec)
}

func redisPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return redisproto.NewPlanner().Plan(ctx, spec)
}

func shadowsocksPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return ssproto.NewPlanner().Plan(ctx, spec)
}

func smtpPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return smtpproto.NewPlanner().Plan(ctx, spec)
}

func sshPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return sshproto.NewPlanner().Plan(ctx, spec)
}

func vmessPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return vmessproto.NewPlanner().Plan(ctx, spec)
}

func wireguardPlan(ctx context.Context, spec core.FlowSpec) (<-chan core.PacketConfig, error) {
	return wgproto.NewPlanner().Plan(ctx, spec)
}

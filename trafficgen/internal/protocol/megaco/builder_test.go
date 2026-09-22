package megaco

// 事务级 errorDescriptor（RFC 3525 §8.2.3）builder/validator 单测。
// 离线套件 case_26（transaction_level_error）已覆盖端到端正路径；这里锁
// builder 的长/缩/IA 渲染分支与 validator 的互斥/类型校验负路径。
import (
	"strings"
	"testing"

	"github.com/trafficgen/trafficgen/internal/core"
)

func txErrReply() core.MegacoTransaction {
	return core.MegacoTransaction{
		Type:  "reply",
		ID:    "1",
		Error: &core.MegacoError{Code: 430, Text: "Unknown TerminationID"},
	}
}

func TestBuildTransaction_TxLevelError_LongForm(t *testing.T) {
	got := buildTransaction(txErrReply(), "long")
	want := `Reply = 1 { Error = 430 { "Unknown TerminationID" } }`
	if got != want {
		t.Errorf("long form: got %q, want %q", got, want)
	}
}

func TestBuildTransaction_TxLevelError_AbbrevForm(t *testing.T) {
	got := buildTransaction(txErrReply(), "abbrev")
	want := `P = 1 { ER = 430 { "Unknown TerminationID" } }`
	if got != want {
		t.Errorf("abbrev form: got %q, want %q", got, want)
	}
}

func TestBuildTransaction_TxLevelError_IA(t *testing.T) {
	tx := txErrReply()
	tx.ImmAckRequired = true
	got := buildTransaction(tx, "long")
	want := `Reply = 1 { IA, Error = 430 { "Unknown TerminationID" } }`
	if got != want {
		t.Errorf("IA prefix: got %q, want %q", got, want)
	}
}

func TestBuildErrorBlock_NilSafe(t *testing.T) {
	if got := buildErrorBlock(nil, "long"); got != "" {
		t.Errorf("nil error block: got %q, want empty", got)
	}
}

// specShape 构造一个最小合法 spec：先发一条注册 request，再跟一条由
// replyTx 指定形态的回复。
func specShape(replyTx core.MegacoTransaction) core.FlowSpec {
	req := core.MegacoTransaction{
		Type: "request", ID: "1",
		Actions: []core.MegacoAction{{
			Context: "-",
			Commands: []core.MegacoCommand{{
				Name: "ServiceChange", Termination: "ROOT",
				Descriptor: &core.MegacoDescriptor{
					Services: &core.MegacoServices{Method: "Restart", Reason: "901 Cold Boot"},
				},
			}},
		}},
	}
	return core.FlowSpec{Megaco: &core.MegacoConfig{
		Sessions: []core.MegacoSession{{
			Role: "mg",
			Events: []core.MegacoEvent{
				{Kind: "message", Direction: "c2s", Transactions: []core.MegacoTransaction{req}},
				{Kind: "message", Direction: "s2c", Transactions: []core.MegacoTransaction{replyTx}},
			},
		}},
	}}
}

func TestValidate_TxLevelError_OK(t *testing.T) {
	tx := txErrReply()
	tx.ID = "same_as_request:0"
	if err := Validate(specShape(tx)); err != nil {
		t.Errorf("transaction-level error reply rejected: %v", err)
	}
}

func TestValidate_TxLevelError_WithActionsRejected(t *testing.T) {
	tx := txErrReply()
	tx.ID = "same_as_request:0"
	tx.Actions = []core.MegacoAction{{
		Context:  "-",
		Commands: []core.MegacoCommand{{Name: "ServiceChange", Termination: "ROOT"}},
	}}
	err := Validate(specShape(tx))
	if err == nil || !strings.Contains(err.Error(), "both error descriptor and actions") {
		t.Errorf("error+actions reply: got %v, want 'both error descriptor and actions' rejection", err)
	}
}

func TestValidate_TxLevelError_OnRequestRejected(t *testing.T) {
	req := core.MegacoTransaction{
		Type: "request", ID: "1",
		Error: &core.MegacoError{Code: 430, Text: "Unknown TerminationID"},
		Actions: []core.MegacoAction{{
			Context:  "-",
			Commands: []core.MegacoCommand{{Name: "ServiceChange", Termination: "ROOT"}},
		}},
	}
	spec := core.FlowSpec{Megaco: &core.MegacoConfig{
		Sessions: []core.MegacoSession{{
			Role:   "mg",
			Events: []core.MegacoEvent{{Kind: "message", Direction: "c2s", Transactions: []core.MegacoTransaction{req}}},
		}},
	}}
	err := Validate(spec)
	if err == nil || !strings.Contains(err.Error(), "only valid on type=reply") {
		t.Errorf("request carrying error: got %v, want 'only valid on type=reply' rejection", err)
	}
}

// D-MEGACO-1 复评3 cosmetic 收口：pending 空 id 自然面可达且带 (transaction)
// 锚词（复评3 F3 闭合的断言面——此前锚词修复零测试断言）。
func TestValidate_PendingMissingIDAnchored(t *testing.T) {
	tx := core.MegacoTransaction{Type: "pending", ID: ""}
	err := Validate(specShape(tx))
	if err == nil || !strings.Contains(err.Error(), "(transaction)") {
		t.Fatalf("pending missing id must carry (transaction) anchor, got %v", err)
	}
}

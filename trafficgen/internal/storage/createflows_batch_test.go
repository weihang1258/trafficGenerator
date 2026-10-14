package storage

import (
	"testing"

	"github.com/google/uuid"
)

// 第14轮 B15（客户端实测）：≥415 流 pcap 解析入库失败 "too many SQL
// variables"——批 500 按 54 列时代设定，FlowModel 增列后 500×79 越过
// SQLite 32766 参数上限。红例：450 流批量写库必须成功（修前恰好越界）。
func TestCreateFlowsBatchBeyondVariableLimit(t *testing.T) {
	db, _ := newTestDB(t)
	repo := &PcapRepository{db: db}
	asset := uuid.New().String()
	flows := make([]FlowModel, 450)
	for i := range flows {
		flows[i] = flowFixture(asset, "u", "tcp|10.0.0.1|"+itoa(40000+i)+"|10.0.0.2|80")
		flows[i].ID = uuid.New().String()
		flows[i].SrcPort = uint16(40000 + i)
	}
	if err := repo.CreateFlows(flows); err != nil {
		t.Fatalf("CreateFlows(450): %v（B15 批大小回归）", err)
	}
	var n int64
	if err := db.Model(&FlowModel{}).Where("pcap_asset_id = ?", asset).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 450 {
		t.Fatalf("count=%d, want 450", n)
	}
}

func itoa(v int) string {
	if v == 0 {
		return "0"
	}
	var b [20]byte
	p := len(b)
	for v > 0 {
		p--
		b[p] = byte('0' + v%10)
		v /= 10
	}
	return string(b[p:])
}

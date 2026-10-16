package storage

// D-PERF-1 验收基准（保留）：pcap_packets 写入矩阵——现状/pragma/索引/
// 多行单语句。BUG-14 修复的过门标准：多行路径 ≥9000 rows/s（现状 4 倍）。
import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	sqlite "github.com/glebarez/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func benchInsert(t *testing.T, name, dsnSuffix string, dropIdx bool, rows, batch int) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "b.db")+dsnSuffix), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("%s open: %v", name, err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("%s migrate: %v", name, err)
	}
	if dropIdx {
		for _, idx := range []string{"idx_pkt_direction", "idx_pkt_l4", "idx_pkt_anomaly", "idx_packets_direction", "idx_packets_l4_protocol", "idx_packets_anomaly_flag"} {
			db.Exec("DROP INDEX IF EXISTS " + idx)
		}
	}
	pkts := make([]PacketModel, 0, 500)
	for i := 0; i < 500; i++ {
		pkts = append(pkts, PacketModel{
			ID: fmt.Sprintf("p-%s-%d", "bench", i), PcapAssetID: "bench-asset",
			FlowID: fmt.Sprintf("flow-%d", i%8), UserID: "u1",
			IndexInFlow: i, Direction: "up", L4Protocol: "udp",
			Length: 512, PayloadLen: 512,
		})
	}
	start := time.Now()
	for off := 0; off < rows; off += 500 {
		for i := range pkts {
			pkts[i].ID = fmt.Sprintf("p-%s-%d-%d", "bench", off, i)
		}
		rowsBatch := pkts
		if err := db.CreateInBatches(&rowsBatch, batch).Error; err != nil {
			t.Fatalf("%s insert: %v", name, err)
		}
	}
	el := time.Since(start)
	t.Logf("%-40s %d rows in %v = %.0f rows/s", name, rows, el.Round(time.Millisecond), float64(rows)/el.Seconds())
}

func benchMultiRow(t *testing.T, name, dsn string, rows int) {
	t.Helper()
	db, err := gorm.Open(sqlite.Open(filepath.Join(t.TempDir(), "b.db")+dsn), &gorm.Config{Logger: logger.Discard})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if err := AutoMigrate(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	start := time.Now()
	for off := 0; off < rows; off += 500 {
		values, args := "", []interface{}{}
		for i := 0; i < 500; i++ {
			id := fmt.Sprintf("p-%s-%d-%d", "bench", off, i)
			if i > 0 {
				values += ","
			}
			values += "(?,?,?,?,?,?,?,?,?,?,?,?,?)"
			args = append(args, id, "bench-asset", fmt.Sprintf("flow-%d", i%8), "u1", 0, 512, i, "up", "udp", "", "", "", -1)
		}
		if err := db.Exec("INSERT INTO pcap_packets (id,pcap_asset_id,flow_id,user_id,raw_offset,length,index_in_flow,direction,l4_protocol,anomaly_flag,frag_group_id,frag_offset,payload_hash) VALUES "+values, args...).Error; err != nil {
			t.Fatalf("%s insert: %v", name, err)
		}
	}
	el := time.Since(start)
	t.Logf("%-40s %d rows in %v = %.0f rows/s", name, rows, el.Round(time.Millisecond), float64(rows)/el.Seconds())
}

func TestBenchPcapInsert(t *testing.T) {
	if os.Getenv("PERF_BENCH") == "" {
		t.Skip("perf benchmark: run with PERF_BENCH=1 (~15s; D-PERF-1 验收基准)")
	}
	rows := 50000
	// 验收门：生产形态（30 列 + 批 25）≥8000 rows/s @空库生产 DSN
	// （434 万行大表实测 8581；旧形批 500 = 2245~2455）。
	benchInsert(t, "生产形 (30列+批25+WAL/NORMAL DSN)", "?_journal_mode=WAL&_busy_timeout=60000&_txlock=immediate", false, rows, 25)
	benchInsert(t, "旧形对照 (30列+批500)", "?_journal_mode=WAL&_busy_timeout=60000&_txlock=immediate", false, rows, 500)
}

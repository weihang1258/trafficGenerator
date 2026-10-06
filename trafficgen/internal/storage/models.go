// Package storage provides database access.
package storage

import (
	"fmt"
	"time"

	"gorm.io/gorm"
)

// TaskModel represents a task in the database.
type TaskModel struct {
	ID           string    `gorm:"primaryKey;size:64"`
	UserID       string    `gorm:"size:64;not null;index"` // 用户ID，数据隔离
	Name         string    `gorm:"size:255;not null"`
	Description  string    `gorm:"size:1024"`
	StrategyIDs  string    `gorm:"type:text"`              // JSON: ["id1", "id2"]
	Protocol     string    `gorm:"size:32"`                // Primary protocol (from first strategy)
	BatchConfig  string    `gorm:"type:text"`              // JSON: BatchSpec for mixed-traffic tasks
	OutputType   string    `gorm:"size:32"`                // "port_group" or "pcap"
	OutputConfig string    `gorm:"type:text"`              // JSON output configuration
	FlowControl  string    `gorm:"type:text"`              // JSON: {"type": "bps", "value": 1000000000}
	Status       string    `gorm:"size:32;not null;index"` // "pending", "running", "stopped", "completed", "error"
	Progress     float64   `gorm:"default:0"`
	ErrorMessage string    `gorm:"size:1024"`
	// 实发统计：onEngineProgress 回填（progress>=100 绕过节流强制落库）。
	// 任务响应 Stats 即源于此——客户端"实发 N 条"靠它闭环。
	PacketsSent int64 `gorm:"default:0"`
	BytesSent   int64 `gorm:"default:0"`
	FlowsCount  int64 `gorm:"default:0"`
	// pcap 产物自动注册资产库的结果（AutoRegisterTaskPcap 回填）：
	// PcapAssetID=注册成功的资产 id；PcapAssetNote=跳过/失败原因（超阈值
	// 时含主动注册指引），注册成功时留空（响应层会补默认提示语）。
	PcapAssetID   string `gorm:"size:64;index"`
	PcapAssetNote string `gorm:"size:1024"`
	CreatedAt     time.Time `gorm:"autoCreateTime"`
	UpdatedAt     time.Time `gorm:"autoUpdateTime"`
	StartedAt     *time.Time
	CompletedAt   *time.Time
}

// TableName returns the table name.
func (TaskModel) TableName() string {
	return "tasks"
}

// StrategyModel represents a strategy in the database.
type StrategyModel struct {
	ID          string    `gorm:"primaryKey;size:64"`
	UserID      string    `gorm:"size:64;not null;index"` // 用户ID，数据隔离
	Name        string    `gorm:"size:255;not null"`
	Mode        string    `gorm:"size:16;not null;default:'synth'"` // synth | replay；replay 时 Protocol 仅为信息性，真实协议由 pcap 决定
	Protocol    string    `gorm:"size:32;not null;index"`
	Config      string    `gorm:"type:text"`              // JSON 配置（synth=FlowSpec 字段；replay=ReplaySpec JSON）
	FlowControl string    `gorm:"type:text"`              // JSON: {"type": "flows", "value": 1}
	ConfigHash  string    `gorm:"size:64;index"`    // 配置哈希，幂等创建
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
}

// TableName returns the table name.
func (StrategyModel) TableName() string {
	return "strategies"
}

// HistoryModel represents a task history record.
type HistoryModel struct {
	ID           string    `gorm:"primaryKey;size:64"`
	TaskID       string    `gorm:"size:64;not null;index"`
	Name         string    `gorm:"size:255;not null"`
	Protocol     string    `gorm:"size:32;not null"`
	Status       string    `gorm:"size:32;not null"`
	PacketsSent  int64     `gorm:"default:0"`
	BytesSent    int64     `gorm:"default:0"`
	Duration     int       `gorm:"default:0"` // seconds
	Error        string    `gorm:"size:1024"`
	CreatedAt    time.Time `gorm:"autoCreateTime"`
	CompletedAt  *time.Time
}

// TableName returns the table name.
func (HistoryModel) TableName() string {
	return "history"
}

// UserModel represents a user in the database.
type UserModel struct {
	ID           string    `gorm:"primaryKey;size:64"`
	Username     string    `gorm:"size:64;not null;uniqueIndex"`
	PasswordHash string    `gorm:"size:256;not null"`
	Email        string    `gorm:"size:128;uniqueIndex"`
	Role         string    `gorm:"size:32;not null;default:'user'"`
	Enabled      bool      `gorm:"default:true"`
	CreatedAt    time.Time `gorm:"autoCreateTime"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime"`
	LastLoginAt  *time.Time
}

// TableName returns the table name.
func (UserModel) TableName() string {
	return "users"
}

// PortAllocationModel represents a port allocation.
type PortAllocationModel struct {
	ID          uint      `gorm:"primaryKey;autoIncrement"`
	Interface   string    `gorm:"size:64;not null;index"`
	Port        uint16    `gorm:"not null;index"`
	TaskID      string    `gorm:"size:64;index"`
	AllocatedAt time.Time `gorm:"autoCreateTime"`
	ExpiresAt   *time.Time
}

// TableName returns the table name.
func (PortAllocationModel) TableName() string {
	return "port_allocations"
}

// PortModel represents a network port.
type PortModel struct {
	ID            string    `gorm:"primaryKey;size:64"`
	Name          string    `gorm:"size:255;not null;uniqueIndex"`
	Type          string    `gorm:"size:20;not null"`  // "libpcap" or "dpdk"
	PCIAddress    string    `gorm:"size:255"`          // PCIe address for DPDK
	Status        string    `gorm:"size:20;not null;default:'idle';index"` // "idle", "using", "maintenance"
	CurrentTaskID string    `gorm:"size:64;index"`
	CreatedAt     time.Time `gorm:"autoCreateTime"`
	UpdatedAt     time.Time `gorm:"autoUpdateTime"`
}

// TableName returns the table name.
func (PortModel) TableName() string {
	return "ports"
}

// PortGroupModel represents a port group.
type PortGroupModel struct {
	ID          string    `gorm:"primaryKey;size:64"`
	Name        string    `gorm:"size:255;not null;uniqueIndex"`
	PortsConfig string    `gorm:"type:text"` // JSON: [{"interface": "eth0", "weight": 1}]
	CreatedAt   time.Time `gorm:"autoCreateTime"`
	UpdatedAt   time.Time `gorm:"autoUpdateTime"`
}

// TableName returns the table name.
func (PortGroupModel) TableName() string {
	return "port_groups"
}

// TokenModel represents a JWT token for validation.
type TokenModel struct {
	ID        string    `gorm:"primaryKey;size:64"`
	UserID    string    `gorm:"size:64;not null;index"`
	TokenHash string    `gorm:"size:255;not null;uniqueIndex"`
	ExpiresAt time.Time `gorm:"not null;index"`
	Status    string    `gorm:"size:20;not null;default:'active'"` // "active", "revoked"
	CreatedAt time.Time `gorm:"autoCreateTime"`
}

// TableName returns the table name.
func (TokenModel) TableName() string {
	return "tokens"
}

// SettingsModel stores application settings (singleton row, id="default").
type SettingsModel struct {
	ID         string    `gorm:"primaryKey;size:32"`
	MaxTasks   int       `gorm:"default:100"`
	BufferSize int       `gorm:"default:4096"`
	LogLevel   string    `gorm:"size:16;default:'info'"`
	UpdatedAt  time.Time `gorm:"autoUpdateTime"`
}

// TableName returns the table name.
func (SettingsModel) TableName() string {
	return "settings"
}

// PcapAssetModel represents an imported PCAP file asset (§15.2). The pcap file
// on disk is the source of truth; this table holds asset-level metadata +
// global statistics. Flow/packet details live in FlowModel/PacketModel.
type PcapAssetModel struct {
	ID               string    `gorm:"primaryKey;size:64"`
	UserID           string    `gorm:"size:64;not null;index"` // 用户隔离
	Name             string    `gorm:"size:255;not null"`
	OriginalFilename string    `gorm:"size:255"`
	StoragePath      string    `gorm:"size:512;not null"` // 磁盘 data/pcaps/{id}.pcap
	PayloadsPath     string    `gorm:"size:512"`          // data/pcaps/{id}.payloads（重组 L7 流）
	TrigramIndexPath string    `gorm:"size:512"`          // trigram 索引文件
	FileHash         string    `gorm:"size:64;index"`     // sha256，去重 + 完整性
	FileSize         int64
	Status           string `gorm:"size:32;not null;index"` // importing|ready|error|reindexing
	ParseError       string `gorm:"size:1024"`
	ParserVersion    string `gorm:"size:32"` // 解析引擎版本
	Tags             string `gorm:"size:256"` // 标签，逗号分隔（v1 字段，v2 做 UI 检索）
	Notes            string `gorm:"type:text"` // 备注
	// 全局统计（查询/筛选/排序用）
	PacketCount  int64
	ByteCount    int64
	FlowCount    int64
	DurationUs   int64 // 微秒
	LinkType     int   // DLT_*
	Snaplen      int
	ProtocolDist string `gorm:"type:text"` // JSON: {"tcp":120,"udp":30}
	CreatedAt    time.Time `gorm:"autoCreateTime"`
	UpdatedAt    time.Time `gorm:"autoUpdateTime"`
}

// TableName returns the table name.
func (PcapAssetModel) TableName() string {
	return "pcap_assets"
}

// FlowModel is the per-flow full aggregation (§17.3). Flows are far fewer than
// packets; each flow stores full aggregate metadata. Field values that can be
// recomputed are NOT stored (L2-L7 per-packet fields come from dynamic re-parse).
type FlowModel struct {
	ID          string `gorm:"primaryKey;size:64"`
	PcapAssetID string `gorm:"size:64;not null;index"` // 归属 pcap
	UserID      string `gorm:"size:64;not null;index"` // 用户隔离

	// 标识
	FlowKey    string `gorm:"size:128;index"` // 归一化 flow key
	L4Protocol string `gorm:"size:16;index"`  // tcp|udp|icmp|arp
	IPVersion  int                            // 4|6
	SrcIP      string `gorm:"size:45;index"`
	SrcPort    uint16
	DstIP      string `gorm:"size:45;index"`
	DstPort    uint16

	// 方向分类
	Client       string `gorm:"size:64"`  // client 端点 ip:port
	Server       string `gorm:"size:64"`  // server 端点 ip:port
	DirMethod    string `gorm:"size:16"`  // syn|port|first_packet
	DirConfident bool                   // 分类可信度
	DirStatus    string `gorm:"size:16"` // classified|uncertain

	// 统计
	PacketCount int64
	ByteCount   int64
	C2SPackets  int64 // c2s 包数
	C2SBytes    int64
	S2CPackets  int64
	S2CBytes    int64
	FirstTsUs   int64 // 首包时间（微秒）
	LastTsUs    int64
	DurationUs  int64

	// TCP 专属
	HandshakeStatus string `gorm:"size:16"` // none|partial|complete
	C2SInitSeq      uint32                  // 初始 seq
	S2CInitSeq      uint32
	SeqRange        string `gorm:"size:64"`   // JSON [min,max]
	FlagsSummary    string `gorm:"type:text"` // JSON {syn:n,fin:n,rst:n,...}
	MSS             uint16
	WindowScale     int
	WindowRange     string `gorm:"size:64"`
	TCPOptions      string `gorm:"type:text"` // JSON 出现的选项
	RetransCount    int64                     // 重传数
	OutOfOrderCount int64                     // 乱序数

	// L7 元数据
	L7Protocol  string `gorm:"size:16;index"` // http|dns|tls|raw|...
	L7Metadata  string `gorm:"type:text"`     // JSON，按协议展开（完整详情）
	L7Method    string `gorm:"size:16;index"` // HTTP method
	L7Host      string `gorm:"size:255;index"` // HTTP host / TLS SNI
	L7QueryName string `gorm:"size:255;index"` // DNS 查询名

	// 重组引用（流级最高层负载地址）
	StreamFile         string `gorm:"size:512"` // {pcap_id}.payloads
	C2SOffset          int64                    // c2s 重组流偏移
	C2SLength          int64
	S2COffset          int64
	S2CLength          int64
	C2SBodyOffset      int64 // L7 body 在 c2s 流内偏移
	C2SBodyLength      int64
	S2CBodyOffset      int64
	S2CBodyLength      int64
	ReassemblyComplete bool   // 重组完整性
	GapInfo            string `gorm:"size:256"` // 缺口信息

	// 改写偏移布局（回放 byte-patch 用，封装恒定，每流一份）
	OffsetLayout string `gorm:"type:text"` // JSON 字段->偏移

	// 完整性
	ParserVersion string `gorm:"size:32"` // 解析时用的版本

	CreatedAt time.Time `gorm:"autoCreateTime"`
}

// TableName returns the table name.
func (FlowModel) TableName() string {
	return "pcap_flows"
}

// PacketModel is the per-packet minimal index (§17.4). ~120 bytes/packet. L2-L7
// field values are NOT stored (re-parsed on demand via RawOffset). Composite
// index (PcapAssetID, FlowID, IndexInFlow) supports in-flow ordered pagination.
type PacketModel struct {
	ID          string `gorm:"primaryKey;size:64"`
	PcapAssetID string `gorm:"size:64;not null;index"`
	FlowID      string `gorm:"size:64;not null;index"`
	UserID      string `gorm:"size:64;not null;index"`

	RawOffset   int64 // pcap 文件中字节偏移（定位/重解析入口）
	Length      int   // 包长
	TimestampUs int64 `gorm:"index"` // 时间（排序/pacing/显示）
	IndexInFlow int                                // 流内序号
	Direction   string `gorm:"size:4;index"`                        // c2s|s2c
	L4Protocol  string `gorm:"size:16;index"`                       // tcp|udp|icmp|arp
	PayloadHash string `gorm:"size:64;index"`                       // 负载 sha256（等值断言用）
	AnomalyFlag string `gorm:"size:16;index"`                       // truncated|oversize|undersize|""（异常标记）
	FragGroupID string `gorm:"size:64;index"`                       // IP 分片组 ID（IPID+src+dst），无分片则空
	FragOffset  int    // 分片偏移（8字节单位），非分片包 -1

	CreatedAt time.Time `gorm:"autoCreateTime"`
}

// TableName returns the table name.
func (PacketModel) TableName() string {
	return "pcap_packets"
}

// AutoMigrate runs auto migration for all models.
func AutoMigrate(db *gorm.DB) error {
	if err := db.AutoMigrate(
		&TaskModel{},
		&StrategyModel{},
		&HistoryModel{},
		&UserModel{},
		&PortAllocationModel{},
		&PortModel{},
		&PortGroupModel{},
		&TokenModel{},
		&SettingsModel{},
		&PcapAssetModel{},
		&FlowModel{},
		&PacketModel{},
	); err != nil {
		return fmt.Errorf("auto migrate: %w", err)
	}
	// Ensure the composite index for in-flow ordered pagination exists. AutoMigrate
	// creates indexes declared in struct tags, but on a pre-existing table that was
	// migrated before this index was added, the tag-driven creation may be skipped;
	// CREATE INDEX IF NOT EXISTS is idempotent and works on both SQLite and Postgres.
	if err := db.Exec("CREATE INDEX IF NOT EXISTS idx_pkt_flow_seq ON pcap_packets (pcap_asset_id, flow_id, index_in_flow)").Error; err != nil {
		return fmt.Errorf("create pcap_packets composite index: %w", err)
	}
	// Unique constraint on (user_id, file_hash) for concurrent-import dedup
	// (§15.6: "同 hash 并发导入只跑一次"). Without it, two simultaneous uploads
	// of the same file both pass the GetAssetByHash check-then-create race and
	// create duplicate records. The unique index makes the second Create fail,
	// and the handler re-fetches the existing asset. IF NOT EXISTS is idempotent.
	if err := db.Exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_pcaps_user_hash ON pcap_assets (user_id, file_hash)").Error; err != nil {
		return fmt.Errorf("create pcap_assets user_hash unique index: %w", err)
	}
	return nil
}

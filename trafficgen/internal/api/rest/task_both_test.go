package rest

// Spec-driven tests for output_type=both (NIC primary + best-effort shadow
// pcap). Spec sources: schemas/v1/task.json both arms, the v1 design rulings
// (shadow degrade-not-fail, Start-side default path, both×dual rejected),
// and the review findings each test pins (branch coverage, idempotency,
// truncation validity).

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	sqlite "github.com/glebarez/sqlite"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/output"
	"github.com/trafficgen/trafficgen/internal/protocol/udp"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
)

// ---- stubs ----

type stubWriter struct {
	mu        sync.Mutex
	frames    int
	writes    [][]byte
	err       error // sticky write error
	closeErr  error // Close return value
	closed    bool
	truncated bool // Truncated() probe (shadowSink)
	timedN    int  // >0 means the TimedWriter path was used
	onWrite   func([][]byte) error
}

func (s *stubWriter) WritePackets(p [][]byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.onWrite != nil {
		if err := s.onWrite(p); err != nil {
			s.err = err
			return err
		}
	}
	if s.err != nil {
		return s.err
	}
	s.frames += len(p)
	s.writes = append(s.writes, p...)
	return nil
}

func (s *stubWriter) WriteTimedPackets(packets []core.PacketOutput) error {
	s.mu.Lock()
	s.timedN++
	s.mu.Unlock()
	frames := make([][]byte, len(packets))
	for i, p := range packets {
		frames[i] = p.Data
	}
	return s.WritePackets(frames)
}

func (s *stubWriter) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.closed = true
	return s.closeErr
}

// Truncated implements the shadowSink probe.
func (s *stubWriter) Truncated() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.truncated
}

// ---- shadowWriter unit tests (error tiering + §12 dispatch) ----

func testOuts(n int, withTime bool) []core.PacketOutput {
	outs := make([]core.PacketOutput, n)
	for i := range outs {
		outs[i] = core.PacketOutput{Data: []byte{byte(i)}}
		if withTime {
			outs[i].Timestamp = time.Unix(1700000000, int64(i))
		}
	}
	return outs
}

// Ruling: primary (NIC) error must propagate (fail the task), shadow errors
// must not.
func TestShadowWriter_PrimaryErrorPropagates(t *testing.T) {
	primary := &stubWriter{err: fmt.Errorf("nic gone")}
	shadow := &stubWriter{}
	sw := &shadowWriter{primary: primary, shadow: shadow}
	if err := sw.WriteTimedPackets(testOuts(3, true)); err == nil {
		t.Fatalf("primary error must propagate, got nil")
	}
	if shadow.frames != 0 {
		t.Errorf("shadow must not be written after primary failure, got %d frames", shadow.frames)
	}
}

// Ruling: shadow failure degrades — nil error to the pipeline, exactly one
// note callback, further shadow writes skipped (no spam), NIC keeps running.
func TestShadowWriter_ShadowErrorDegrades(t *testing.T) {
	primary := &stubWriter{}
	shadow := &stubWriter{}
	notes := []string{}
	sw := &shadowWriter{primary: primary, shadow: shadow,
		onShadowNote: func(msg string) { notes = append(notes, msg) }}
	shadow.onWrite = func([][]byte) error { return fmt.Errorf("disk full") }

	for i := 0; i < 5; i++ {
		if err := sw.WriteTimedPackets(testOuts(2, true)); err != nil {
			t.Fatalf("write %d: shadow failure must not fail the write, got %v", i, err)
		}
	}
	if len(notes) != 1 {
		t.Fatalf("note callbacks = %d, want exactly 1", len(notes))
	}
	if !strings.Contains(notes[0], "disk full") {
		t.Errorf("note %q missing cause", notes[0])
	}
	if primary.frames != 10 {
		t.Errorf("NIC frames = %d, want 10 (wire unaffected)", primary.frames)
	}
}

// §12: the shadow (pcap) side must receive the scheduled send timestamps —
// shadowWriter implements TimedWriter and the sink must see WriteTimed, not
// the time.Now() fallback.
func TestShadowWriter_TimedDispatch(t *testing.T) {
	primary := &stubWriter{}
	shadow := &stubWriter{}
	sw := &shadowWriter{primary: primary, shadow: shadow}
	outs := testOuts(3, true)
	if err := sw.WriteTimedPackets(outs); err != nil {
		t.Fatalf("write: %v", err)
	}
	if shadow.timedN == 0 {
		t.Errorf("shadow must go through WriteTimedPackets (§12), got plain path")
	}
	if primary.timedN != 0 {
		t.Errorf("NIC side has no schedule; got %d timed writes", primary.timedN)
	}
	if primary.frames != 3 || shadow.frames != 3 {
		t.Errorf("frames primary=%d shadow=%d, want 3/3", primary.frames, shadow.frames)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !primary.closed || !shadow.closed {
		t.Errorf("both sides must be closed (primary=%v shadow=%v)", primary.closed, shadow.closed)
	}
}

// ---- PCAPWriter cap: planned ceiling, valid file, complete records ----

func TestPCAPWriterCap_TruncatesAtRecordBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "capped.pcap")
	// 24B header + records of (16+8)B each. Cap fits 2 records + header only.
	w, err := output.NewPCAPWriterWithCap(path, 24+2*24+10)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pkt := make([]byte, 8)
	if err := w.Write([][]byte{pkt, pkt, pkt, pkt, pkt}); err != nil {
		t.Fatalf("write: %v (cap stop is not an error)", err)
	}
	if !w.Truncated() {
		t.Errorf("Truncated() = false, want true")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// File must remain a valid pcap with exactly 2 complete records.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(raw) != 24+2*24 {
		t.Fatalf("file size = %d, want %d (2 records, header included)", len(raw), 24+2*24)
	}
	for off := 24; off < len(raw); off += 24 {
		recLen := binary.LittleEndian.Uint32(raw[off+8 : off+12])
		if int(recLen) != 8 {
			t.Errorf("record at %d: caplen=%d, want complete 8-byte record", off, recLen)
		}
	}
}

// Cap=0 must stay unbounded (existing pcap output unchanged).
func TestPCAPWriterCap_ZeroIsUnbounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "uncapped.pcap")
	w, err := output.NewPCAPWriterWithCap(path, 0)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	pkt := make([]byte, 64)
	if err := w.Write([][]byte{pkt, pkt, pkt, pkt}); err != nil {
		t.Fatalf("write: %v", err)
	}
	if w.Truncated() {
		t.Errorf("uncapped writer must never set truncated")
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
}

// ---- StrategyModelToTask: both keeps the shadow path AND routes to NIC ----

func TestStrategyModelToTask_Both(t *testing.T) {
	tm := &storage.TaskModel{
		ID: "t1", OutputType: "both",
		OutputConfig: `{"port_group_id":"pg1","pcap_path":"pcap/shadow.pcap"}`,
	}
	task, err := core.StrategyModelToTask(tm, &storage.StrategyModel{ID: "s1", Mode: "synth", Protocol: "udp", Config: "{}"}, "eth9")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if task.OutputMode != "interface" {
		t.Errorf("OutputMode = %q, want interface", task.OutputMode)
	}
	if task.Interface != "eth9" {
		t.Errorf("Interface = %q, want eth9", task.Interface)
	}
	if task.PcapFile != "pcap/shadow.pcap" {
		t.Errorf("PcapFile = %q, want shadow path kept", task.PcapFile)
	}

	// port_group regression: shadow field must stay cleared.
	tm.OutputType = "port_group"
	task, err = core.StrategyModelToTask(tm, &storage.StrategyModel{ID: "s1", Mode: "synth", Protocol: "udp", Config: "{}"}, "eth9")
	if err != nil {
		t.Fatalf("convert: %v", err)
	}
	if task.PcapFile != "" {
		t.Errorf("port_group PcapFile = %q, want empty", task.PcapFile)
	}
}

// ---- handler gates ----

func newBothTestDB(t *testing.T) *storage.DB {
	t.Helper()
	gormDB, err := gorm.Open(sqlite.Open(t.TempDir()+"/both.db"), &gorm.Config{})
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if err := storage.AutoMigrate(gormDB); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	return &storage.DB{DB: gormDB}
}

func setupPortGroupRow(t *testing.T, db *storage.DB, id, iface string) {
	t.Helper()
	ports, _ := json.Marshal([]map[string]interface{}{{"interface": iface, "weight": 1}})
	if err := db.Create(&storage.PortGroupModel{ID: id, Name: "pg-" + id, PortsConfig: string(ports)}).Error; err != nil {
		t.Fatalf("create port group: %v", err)
	}
}

// v1 ruling: both×dual is rejected, not silently degraded.
func TestCreate_BothWithInterface2_Rejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newBothTestDB(t)
	h := NewTaskHandlerWithCallbacks(db, nil, nil, false)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/tasks", h.Create)

	body := `{"name":"t","strategy_ids":["s"],"output_type":"both","output_config":{"port_group_id":"pg","interface2":"eth2"}}`
	req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d body=%s, want 400", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), errBothDual) {
		t.Errorf("message %q missing errBothDual", w.Body.String())
	}
}

// Start-side default: a both task without pcap_path gets a task-id derived
// shadow path, persisted into output_config BEFORE writer creation. Writer
// creation itself fails on the fake iface (no real NIC in unit tests) — the
// assertion is that the path was already persisted when it does.
func TestStart_BothDefaultShadowPathPersisted(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newBothTestDB(t)
	setupPortGroupRow(t, db, "pg1", "definitely-not-an-iface-0")
	sid := "st-1"
	if err := db.Create(&storage.StrategyModel{ID: sid, UserID: "u1", Name: "s", Mode: "synth", Protocol: "udp", Config: "{}"}).Error; err != nil {
		t.Fatalf("create strategy: %v", err)
	}
	sids, _ := json.Marshal([]string{sid})
	task := &storage.TaskModel{
		ID: "tk-both1", UserID: "u1", Name: "both",
		StrategyIDs: string(sids), Protocol: "udp",
		OutputType:   "both",
		OutputConfig: `{"port_group_id":"pg1"}`,
		Status:       "pending",
	}
	if err := db.Create(task).Error; err != nil {
		t.Fatalf("create task: %v", err)
	}

	e := core.NewEngine(core.EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 64, QueueSize: 16})
	if err := e.Start(); err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer e.Stop()

	h := NewTaskHandler(db, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)
	req := httptest.NewRequest("POST", "/tasks/tk-both1/start", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	var stored storage.TaskModel
	if err := db.Where("id = ?", "tk-both1").First(&stored).Error; err != nil {
		t.Fatalf("reload task: %v", err)
	}
	if !strings.Contains(stored.OutputConfig, "tk-both1_shadow.pcap") {
		t.Errorf("output_config = %s, want task-id derived shadow path persisted", stored.OutputConfig)
	}
	if !strings.HasPrefix(stored.OutputConfig, "{") {
		t.Errorf("output_config corrupted: %s", stored.OutputConfig)
	}
}

// Idempotency ruling: the default shadow path is filled at Start, NOT at
// Create — otherwise Create's full-output_config dedup would never hit and
// resubmission would double tasks.
func TestCreate_BothDedupBeforeShadowPathFilled(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newBothTestDB(t)
	setupPortGroupRow(t, db, "pg1", "ethX")
	sid := "st-9"
	if err := db.Create(&storage.StrategyModel{ID: sid, UserID: "u1", Name: "s", Mode: "synth", Protocol: "udp", Config: "{}"}).Error; err != nil {
		t.Fatalf("create strategy: %v", err)
	}
	h := NewTaskHandlerWithCallbacks(db, nil, nil, false)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/tasks", h.Create)

	body := `{"name":"t","strategy_ids":["` + sid + `"],"output_type":"both","output_config":{"port_group_id":"pg1"}}`
	var firstID string
	for i := 0; i < 2; i++ {
		req := httptest.NewRequest("POST", "/tasks", strings.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		r.ServeHTTP(w, req)
		wantCode := http.StatusCreated
		if i == 1 {
			wantCode = http.StatusOK // dedup hit returns Success (200)
		}
		if w.Code != wantCode {
			t.Fatalf("create %d: status = %d body=%s, want %d", i, w.Code, w.Body.String(), wantCode)
		}
		var resp struct {
			Data struct {
				ID      string `json:"id"`
				Message string `json:"message"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("decode: %v", err)
		}
		if i == 0 {
			firstID = resp.Data.ID
			continue
		}
		if resp.Data.Message != "task already exists" || resp.Data.ID != firstID {
			t.Fatalf("dedup broken: got id=%q msg=%q, want id=%q msg=%q",
				resp.Data.ID, resp.Data.Message, firstID, "task already exists")
		}
	}
	// And the stored output_config must NOT contain a generated path.
	var stored storage.TaskModel
	if err := db.Where("id = ?", firstID).First(&stored).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if strings.Contains(stored.OutputConfig, "_shadow.pcap") {
		t.Errorf("Create filled the shadow path (breaks dedup): %s", stored.OutputConfig)
	}
}

// Auto-register ruling: a both task's shadow registers like a pcap product.
func TestAutoRegisterTaskPcap_BothRegistersShadow(t *testing.T) {
	sdb := newRESTTestDB(t)
	pcapPath := filepath.Join(t.TempDir(), "shadow.pcap")
	writePcapForREST(t, pcapPath)
	task := &storage.TaskModel{
		ID: "bbbbbbbb-1111-1111-1111-111111111111", UserID: "u1", Name: "t",
		Protocol: "tcp", OutputType: "both", Status: "completed", Progress: 100,
		OutputConfig: `{"port_group_id":"pg","pcap_path":"` + pcapPath + `"}`,
	}
	p := NewPcapHandler(sdb, "")

	AutoRegisterTaskPcap(sdb, p, task)

	if task.PcapAssetID == "" {
		t.Fatalf("both shadow must auto-register (note=%q)", task.PcapAssetNote)
	}
}

// Guard row: a failed both task registers nothing.
func TestAutoRegisterTaskPcap_BothFailedNoOp(t *testing.T) {
	sdb := newRESTTestDB(t)
	pcapPath := filepath.Join(t.TempDir(), "shadow.pcap")
	writePcapForREST(t, pcapPath)
	task := &storage.TaskModel{
		ID: "bbbbbbbb-2222-2222-2222-222222222222", UserID: "u1", Name: "t",
		Protocol: "tcp", OutputType: "both", Status: "failed",
		OutputConfig: `{"port_group_id":"pg","pcap_path":"` + pcapPath + `"}`,
	}
	p := NewPcapHandler(sdb, "")

	AutoRegisterTaskPcap(sdb, p, task)

	if task.PcapAssetID != "" {
		t.Errorf("failed task must not register, got %q", task.PcapAssetID)
	}
}

// noteShadowIssue append semantics: two degradations must both survive.
func TestNoteShadowIssue_Appends(t *testing.T) {
	db := newBothTestDB(t)
	if err := db.Create(&storage.TaskModel{ID: "tk-note", UserID: "u1", Name: "n", OutputType: "both", Status: "running"}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	h := NewTaskHandlerWithCallbacks(db, nil, nil, false)
	h.noteShadowIssue("tk-note", "first issue")
	h.noteShadowIssue("tk-note", "second issue")

	var stored storage.TaskModel
	if err := db.Where("id = ?", "tk-note").First(&stored).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !strings.Contains(stored.ShadowNote, "first issue") || !strings.Contains(stored.ShadowNote, "second issue") {
		t.Errorf("shadow_note = %q, want both issues", stored.ShadowNote)
	}
}

// ---- 复审补测轮:失败路径 + 组合面(见 rev-test 清单 HIGH1-3/MEDIUM4-9) ----

func stubInterfaceWriter(t *testing.T, primary *stubWriter) {
	t.Helper()
	old := newInterfaceWriterFn
	newInterfaceWriterFn = func(string) (core.PacketWriter, error) { return primary, nil }
	t.Cleanup(func() { newInterfaceWriterFn = old })
}

// HIGH-1:CreateBatch both happy path——批路径在 Create 期即落缺省影子路径
// (batch 无幂等去重,与 Create 的 Start 期生成是两套时序,此差异需钉住);
// 引擎真实跑包,主路吃进桩,影子写出合法 pcap,任务完成,响应面带 download_url。
func TestCreateBatch_Both_HappyPath(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newBothTestDB(t)
	setupPortGroupRow(t, db, "pgB", "stubif0")

	primary := &stubWriter{}
	stubInterfaceWriter(t, primary)

	e := core.NewEngine(core.EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 256, QueueSize: 64})
	e.RegisterPlanner(udp.NewPlanner())
	e.SetBuildFunc(core.NewBuilder().Build)
	if err := e.Start(); err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer e.Stop()

	h := NewTaskHandler(db, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/tasks/batch", h.CreateBatch)

	shadowDir := t.TempDir()
	body := `{"name":"both-batch","batch":{"classes":[{"id":"u","type":"udp","flow_count":1,"config":{},` +
		`"tuples":{"src_ip":{"strategy":"fixed","value":"10.0.0.1"},"dst_ip":{"strategy":"fixed","value":"10.0.0.2"},` +
		`"src_port":{"strategy":"fixed","value":2000},"dst_port":{"strategy":"fixed","value":53}}}]},` +
		`"output_type":"both","output_config":{"port_group_id":"pgB","pcap_path":"` + shadowDir + `/shadow.pcap"}}`
	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusCreated {
		t.Fatalf("status = %d body=%s", w.Code, w.Body.String())
	}
	var resp struct {
		Data struct {
			ID string `json:"id"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	taskID := resp.Data.ID

	// Create 期(非 Start 期)即持久化影子路径——batch 专属时序。
	var stored storage.TaskModel
	if err := db.Where("id = ?", taskID).First(&stored).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if !strings.Contains(stored.OutputConfig, shadowDir+"/shadow.pcap") {
		t.Errorf("batch output_config = %s, want resolved shadow path at create time", stored.OutputConfig)
	}
	if stored.OutputType != "both" {
		t.Errorf("OutputType = %q, want both", stored.OutputType)
	}

	// 等完成:主路吃到包 + 影子文件非平凡。
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		db.First(&stored, "id = ?", taskID)
		if stored.Status == "completed" || stored.Status == "error" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if stored.Status != "completed" {
		t.Fatalf("status = %s err=%q, want completed", stored.Status, stored.ErrorMessage)
	}
	if primary.frames == 0 {
		t.Errorf("primary (NIC stub) received 0 frames")
	}
	info, err := os.Stat(shadowDir + "/shadow.pcap")
	if err != nil {
		t.Fatalf("shadow pcap missing: %v", err)
	}
	if info.Size() <= 24 {
		t.Errorf("shadow pcap size = %d, want records beyond the header", info.Size())
	}

	// 响应面 both:download_url 必须在(pcap_handler.go 直链守卫的呼应面)。
	tmResp := convertTaskToResponse(&stored)
	if tmResp.DownloadURL == "" {
		t.Errorf("both task response missing download_url")
	}
	if tmResp.ShadowNote != "" {
		t.Errorf("healthy run must not carry shadow_note, got %q", tmResp.ShadowNote)
	}
}

// HIGH-1b:CreateBatch both + interface2 → 400 errBothDual(batch 侧 dual
// 检测还覆盖 replay class direction=dual,这里显式 interface2 即可)。
func TestCreateBatch_Both_WithInterface2_Rejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newBothTestDB(t)
	setupPortGroupRow(t, db, "pgB2", "stubif0")
	h := NewTaskHandlerWithCallbacks(db, nil, nil, false)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/tasks/batch", h.CreateBatch)

	body := `{"name":"b","batch":{"classes":[{"id":"u","type":"udp","flow_count":1,"config":{},` +
		`"tuples":{"src_ip":{"strategy":"fixed","value":"10.0.0.1"},"dst_ip":{"strategy":"fixed","value":"10.0.0.2"},` +
		`"src_port":{"strategy":"fixed","value":2000},"dst_port":{"strategy":"fixed","value":53}}}]},` +
		`"output_type":"both","output_config":{"port_group_id":"pgB2","interface2":"eth9"}}`
	req := httptest.NewRequest("POST", "/tasks/batch", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), errBothDual) {
		t.Fatalf("status = %d body=%s, want 400 errBothDual", w.Code, w.Body.String())
	}
}

// HIGH-2:Start 的 both×dual 兜底——interface2 不在 output_config,而来自
// replay 策略 direction=dual;Create 不拦(那时不加载策略),必须 Start 拦。
func TestStart_BothReplayDual_Rejected(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newBothTestDB(t)
	setupPortGroupRow(t, db, "pgB3", "stubif0")
	sid := "st-dual-both"
	cfg := `{"pcap_asset_id":"ast-x","direction":"dual","speed":{"mode":""}}`
	if err := db.Create(&storage.StrategyModel{ID: sid, UserID: "u1", Name: "d", Mode: "replay", Protocol: "batch", Config: cfg}).Error; err != nil {
		t.Fatalf("seed strategy: %v", err)
	}
	sids, _ := json.Marshal([]string{sid})
	task := &storage.TaskModel{
		ID: "tk-dual-both", UserID: "u1", Name: "dual-both",
		StrategyIDs: string(sids), Protocol: "batch",
		OutputType:   "both",
		OutputConfig: `{"port_group_id":"pgB3"}`,
		Status:       "pending",
	}
	if err := db.Create(task).Error; err != nil {
		t.Fatalf("seed task: %v", err)
	}

	e := core.NewEngine(core.EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 64, QueueSize: 16})
	if err := e.Start(); err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer e.Stop()

	h := NewTaskHandler(db, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)
	req := httptest.NewRequest("POST", "/tasks/tk-dual-both/start", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), errBothDual) {
		t.Fatalf("status = %d body=%s, want 400 errBothDual", w.Code, w.Body.String())
	}
	var stored storage.TaskModel
	if err := db.Where("id = ?", "tk-dual-both").First(&stored).Error; err != nil {
		t.Fatalf("reload: %v", err)
	}
	if stored.Status != "error" {
		t.Errorf("task status = %q, want error (rejection must be persisted)", stored.Status)
	}
}

// HIGH-3:interface 模式拿到空 iface 必须显式报错,不许静默零输出。
// 端口组存在但没有任何 interface → resolvePortGroupIface 静默留空 → 守卫接住。
func TestStart_BothEmptyIface_FailsLoudly(t *testing.T) {
	gin.SetMode(gin.TestMode)
	db := newBothTestDB(t)
	// 端口组存在但 ports_config 为空数组 → iface 解析留空。
	ports, _ := json.Marshal([]map[string]interface{}{})
	if err := db.Create(&storage.PortGroupModel{ID: "pgE", Name: "pgE", PortsConfig: string(ports)}).Error; err != nil {
		t.Fatalf("seed pg: %v", err)
	}
	sid := "st-empty-iface"
	if err := db.Create(&storage.StrategyModel{ID: sid, UserID: "u1", Name: "s", Mode: "synth", Protocol: "udp", Config: "{}"}).Error; err != nil {
		t.Fatalf("seed strategy: %v", err)
	}
	sids, _ := json.Marshal([]string{sid})
	task := &storage.TaskModel{
		ID: "tk-empty-iface", UserID: "u1", Name: "e",
		StrategyIDs: string(sids), Protocol: "udp",
		OutputType:   "both",
		OutputConfig: `{"port_group_id":"pgE"}`,
		Status:       "pending",
	}
	if err := db.Create(task).Error; err != nil {
		t.Fatalf("seed task: %v", err)
	}

	e := core.NewEngine(core.EngineConfig{ConfigWorkers: 1, PacketWorkers: 1, OutputWorkers: 1, BufferSize: 64, QueueSize: 16})
	if err := e.Start(); err != nil {
		t.Fatalf("engine: %v", err)
	}
	defer e.Stop()

	h := NewTaskHandler(db, e, nil)
	r := gin.New()
	r.Use(func(c *gin.Context) { c.Set("userID", "u1"); c.Next() })
	r.POST("/tasks/:id/start", h.Start)
	req := httptest.NewRequest("POST", "/tasks/tk-empty-iface/start", strings.NewReader(""))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusBadRequest || !strings.Contains(w.Body.String(), "no interface resolved") {
		t.Fatalf("status = %d body=%s, want 400 no-interface-resolved", w.Code, w.Body.String())
	}
	var stored storage.TaskModel
	db.Where("id = ?", "tk-empty-iface").First(&stored)
	if stored.Status != "error" {
		t.Errorf("status = %q, want error", stored.Status)
	}
}

// MEDIUM-4/5/6:shadowWriter × 真 PCAPWriter 组合——§12 计划时间戳必须
// 真正写进 pcap 字节;上限截断在 WriteTimed 生产路径同样生效且文件完好。
func TestShadowWriter_RealPcapSink_TimestampsAndCap(t *testing.T) {
	path := filepath.Join(t.TempDir(), "combo.pcap")
	pw, err := output.NewPCAPWriterWithCap(path, 24+4*24) // 全局头 + 4 条 8B 记录
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	primary := &stubWriter{}
	sw := &shadowWriter{primary: primary, shadow: &pcapPacketWriter{w: pw}}

	outs := make([]core.PacketOutput, 10)
	for i := range outs {
		outs[i] = core.PacketOutput{Data: make([]byte, 8), Timestamp: time.Unix(int64(1700000000+i), 0)}
	}
	if err := sw.WriteTimedPackets(outs); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := sw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if !pw.Truncated() {
		t.Errorf("shadow cap must truncate at 4 records")
	}
	if primary.frames != 10 {
		t.Errorf("NIC frames = %d, want 10 (cap never touches the wire)", primary.frames)
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(raw) != 24+4*24 {
		t.Fatalf("file size = %d, want %d (4 complete records)", len(raw), 24+4*24)
	}
	for off, i := 24, 0; off < len(raw); off, i = off+24, i+1 {
		tsSec := binary.LittleEndian.Uint32(raw[off : off+4])
		recLen := binary.LittleEndian.Uint32(raw[off+8 : off+12])
		if tsSec != uint32(1700000000+i) {
			t.Errorf("record %d: ts = %d, want scheduled %d (§12)", i, tsSec, 1700000000+i)
		}
		if recLen != 8 {
			t.Errorf("record %d: caplen = %d, want 8", i, recLen)
		}
	}
}

// MEDIUM-9:Close 三分支——primary 错误传播;健康路径影子 Close 出错降级
// 为 note(恰好一次);broken 后影子仍被关闭但错误忽略、不重复 note。
func TestShadowWriter_CloseBranches(t *testing.T) {
	t.Run("primary_close_error_propagates", func(t *testing.T) {
		primary := &stubWriter{closeErr: fmt.Errorf("nic close fail")}
		shadow := &stubWriter{}
		sw := &shadowWriter{primary: primary, shadow: shadow}
		if err := sw.Close(); err == nil || !strings.Contains(err.Error(), "nic close fail") {
			t.Fatalf("Close = %v, want primary error", err)
		}
		if !shadow.closed {
			t.Errorf("shadow must still be closed")
		}
	})
	t.Run("healthy_shadow_close_error_degrades", func(t *testing.T) {
		primary := &stubWriter{}
		shadow := &stubWriter{closeErr: fmt.Errorf("fsync fail")}
		notes := 0
		sw := &shadowWriter{primary: primary, shadow: shadow, onShadowNote: func(string) { notes++ }}
		if err := sw.Close(); err != nil {
			t.Fatalf("healthy run Close = %v, want nil (shadow degraded)", err)
		}
		if notes != 1 {
			t.Errorf("notes = %d, want exactly 1", notes)
		}
	})
	t.Run("broken_shadow_close_silent", func(t *testing.T) {
		primary := &stubWriter{}
		shadow := &stubWriter{}
		shadow.onWrite = func([][]byte) error { return fmt.Errorf("disk full") }
		notes := 0
		sw := &shadowWriter{primary: primary, shadow: shadow, onShadowNote: func(string) { notes++ }}
		_ = sw.WriteTimedPackets(testOuts(1, true)) // breaks shadow, note #1
		shadow.closeErr = fmt.Errorf("late close fail")
		if err := sw.Close(); err != nil {
			t.Fatalf("Close = %v, want nil", err)
		}
		if notes != 1 {
			t.Errorf("notes = %d, want 1 (no duplicate after broken)", notes)
		}
		if !shadow.closed {
			t.Errorf("broken shadow must still be closed (flush what reached the buffer)")
		}
	})
}

// MEDIUM-7:下载直链对 both 放行(评审指出的 404 死角)。
func TestServeTaskPcapPublic_Both(t *testing.T) {
	db := newBothTestDB(t)
	pcapPath := filepath.Join(t.TempDir(), "shadow.pcap")
	writePcapForREST(t, pcapPath)
	if err := db.Create(&storage.TaskModel{
		ID: "cccccccc-1111-1111-1111-111111111111", UserID: "u1", Name: "t",
		Protocol: "tcp", OutputType: "both", Status: "completed", Progress: 100,
		OutputConfig: `{"port_group_id":"pg","pcap_path":"` + pcapPath + `"}`,
	}).Error; err != nil {
		t.Fatalf("seed: %v", err)
	}
	req := httptest.NewRequest("GET", "/downloads/tasks/cccccccc-1111-1111-1111-111111111111/pcap", nil)
	w := httptest.NewRecorder()
	ServeTaskPcapPublic(db, w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (both shadow must be downloadable)", w.Code)
	}
	if w.Body.Len() == 0 {
		t.Errorf("empty body")
	}
}

// F1 复审项:cap 触顶是计划性天花板(写路径全 nil),若 Close 不探测
// Truncated,任务会 completed 且 shadow_note 全空——触顶无痕。钉死:
// 触顶必须恰好留一条 note,且文案带 cap 数值。
func TestShadowWriter_CapTruncationSurfacesNote(t *testing.T) {
	primary := &stubWriter{}
	shadow := &stubWriter{}
	notes := []string{}
	sw := &shadowWriter{primary: primary, shadow: shadow,
		onShadowNote: func(msg string) { notes = append(notes, msg) }}

	// Healthy writes (cap stop is not an error — no note at write time).
	if err := sw.WriteTimedPackets(testOuts(3, true)); err != nil {
		t.Fatalf("write: %v", err)
	}
	if len(notes) != 0 {
		t.Fatalf("cap stop must be silent at write time, got %v", notes)
	}
	shadow.truncated = true // probe flips when the cap stopped the writer
	if err := sw.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("notes = %d, want exactly 1 truncation note", len(notes))
	}
	if !strings.Contains(notes[0], "truncated") || !strings.Contains(notes[0], "1024") {
		t.Errorf("note %q missing truncation + cap size", notes[0])
	}
}

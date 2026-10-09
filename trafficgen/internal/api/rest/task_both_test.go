package rest

// Spec-driven tests for output_type=both (NIC primary + best-effort shadow
// pcap). Spec sources: schemas/v1/task.json both arms, the v1 design rulings
// (shadow degrade-not-fail, Start-side default path, both×dual rejected),
// and the review findings each test pins (branch coverage, idempotency,
// truncation validity).

import (
	"encoding/json"
	"encoding/binary"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	sqlite "github.com/glebarez/sqlite"
	"github.com/gin-gonic/gin"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/output"
	"github.com/trafficgen/trafficgen/internal/storage"
	"gorm.io/gorm"
)

// ---- stubs ----

type stubWriter struct {
	mu      sync.Mutex
	frames  int
	writes  [][]byte
	err     error // sticky write error
	closed  bool
	timedN  int // >0 means the TimedWriter path was used
	onWrite func([][]byte) error
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
	s.timedN++
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
	return nil
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

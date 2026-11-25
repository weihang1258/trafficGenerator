package rest

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/api/websocket"
	"github.com/trafficgen/trafficgen/internal/core"
	"github.com/trafficgen/trafficgen/internal/core/layers"
	"github.com/trafficgen/trafficgen/internal/core/schema"
	"github.com/trafficgen/trafficgen/internal/output"
	"github.com/trafficgen/trafficgen/internal/storage"
	"github.com/trafficgen/trafficgen/pkg/auth"
	"github.com/trafficgen/trafficgen/pkg/netif"
	"gorm.io/gorm"
)

// errBothDual is the single message for the v1 both×dual rejection. All
// faces (REST create/batch/start, MCP) route through these handlers, so one
// constant keeps the negative-parity messages identical.
const errBothDual = "output_type=both does not support dual-port replay (interface2)"

// taskSchemaGate runs the unified task validation entry (shape + flow-control
// envelope + replay+bps conflict + batch semantics) and writes the 400 on
// failure. strategyViews carries the loaded strategies for the conflict
// check. DB lookups (existence/ownership, port groups) stay in the handler.
func taskSchemaGate(c *gin.Context, doc map[string]interface{}, strategyViews []schema.StrategyView) bool {
	if errs := schema.ValidateTaskCreate(doc, strategyViews); len(errs) > 0 {
		BadRequest(c, errs.Error())
		return false
	}
	return true
}

// toAny round-trips a typed request value through JSON into a plain map,
// so the schema entry validates exactly what the client sent (field names
// and types), not Go zero values. Nil input yields nil (absent envelope).
// Empty strings inside the map are dropped: gin binding fills absent string
// fields (e.g. OutputConfigRequest.PortGroupID on a pcap task) with "",
// which the client never sent. Dropping them restores the client-sent shape
// so "absent" validates as absent. Non-empty values pass through untouched.
func toAny(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	for k, val := range m {
		if s, ok := val.(string); ok && s == "" {
			delete(m, k)
		}
	}
	if len(m) == 0 {
		return nil
	}
	return m
}

// toStrategyViews projects storage models to the minimal view the schema
// entry needs for the replay+bps conflict check.
func toStrategyViews(models []storage.StrategyModel) []schema.StrategyView {
	out := make([]schema.StrategyView, 0, len(models))
	for _, m := range models {
		v := schema.StrategyView{Name: m.Name, Mode: m.Mode}
		var rs struct {
			Speed struct {
				Mode string `json:"mode"`
			} `json:"speed"`
		}
		if json.Unmarshal([]byte(m.Config), &rs) == nil {
			v.SpeedMode = rs.Speed.Mode
		}
		out = append(out, v)
	}
	return out
}

func containsStr(s, sub string) bool {
	return strings.Contains(s, sub)
}

// pruneZero drops zero-valued leaves from a decoded JSON map so the schema
// entry sees the client-sent shape: gin-bound structs marshal absent strings
// as "", absent numbers as 0, and absent sub-objects as {"strategy":""} or
// {}. Every dropped form means "not set" in handler semantics (optional
// fields, zero = default). Non-empty values pass through untouched. WARNING:
// only use for batch docs — flow_control value 0 is a REAL user error
// ("must be positive"), never prune it; taskCreateDoc keeps that path.
func pruneZero(m map[string]interface{}) map[string]interface{} {
	for k, v := range m {
		switch t := v.(type) {
		case string:
			if t == "" {
				delete(m, k)
			}
		case float64:
			if t == 0 {
				delete(m, k)
			}
		case map[string]interface{}:
			pruneZero(t)
			if len(t) == 0 {
				delete(m, k)
			}
		case []interface{}:
			for _, item := range t {
				if sm, ok := item.(map[string]interface{}); ok {
					pruneZero(sm)
				}
			}
		}
	}
	return m
}

// toAnyBatch converts a bound BatchSpec to the client-sent shape: same as
// toAny plus recursive zero pruning (BatchSpec/TrafficClass/GlobalConfig
// lack omitempty, so absent sub-fields arrive zero-valued).
// D-ROBUST-1：class.config 缺省（TrafficClass.Config 无 omitempty → JSON
// null → untyped nil 绕过 pruneZero 类型开关）归一为 {}——batch.json 中
// config 非必填、空对象=全默认合法形（层链 {"udp":{}} 同语义），合法输入
// 不得产出 "<invalid reflect.Value>" 垃圾报错（客户端压测 BUG-07①）。
func toAnyBatch(v interface{}) map[string]interface{} {
	if v == nil {
		return nil
	}
	raw, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil
	}
	if classes, ok := m["classes"].([]interface{}); ok {
		for _, ci := range classes {
			cm, ok := ci.(map[string]interface{})
			if !ok {
				continue
			}
			if cm["config"] == nil {
				cm["config"] = map[string]interface{}{}
			}
		}
	}
	return pruneZero(m)
}

// toAnyJSON decodes a stored JSON blob into a plain map for the schema entry.
func toAnyJSON(raw string) map[string]interface{} {
	if raw == "" {
		return nil
	}
	var m map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &m); err != nil {
		return nil
	}
	return m
}

// taskCreateDoc builds the schema-entry document, omitting absent envelopes
// (nil flow_control/output) so "absent" validates as absent. Explicit values
// pass through untouched.
func taskCreateDoc(name string, ids []interface{}, outputType string, output, fc map[string]interface{}) map[string]interface{} {
	doc := map[string]interface{}{
		"name": name, "strategy_ids": ids,
		"output_type": outputType, "output_config": output,
	}
	if fc != nil {
		doc["flow_control"] = fc
	}
	return doc
}

func toAnySlice(ss []string) []interface{} {
	out := make([]interface{}, 0, len(ss))
	for _, s := range ss {
		out = append(out, s)
	}
	return out
}

// TaskHandler handles task requests.
type TaskHandler struct {
	db                 *storage.DB
	engine             *core.Engine
	wsHub              *websocket.Hub
	pcap               *PcapHandler      // optional; enables task pcap auto-registration
	failedTasks        map[string]string // engineTaskID -> errorMessage
	failMu             sync.Mutex
	lastProgressUpdate map[string]time.Time // parentTaskID -> last DB update time
	progressMu         sync.Mutex
	// R7 缺陷 A：多策略聚合槽位制。已完成子任务从引擎 store 摘除后，旧实现
	// （RangeTaskStore 只见存活者）把已完成策略的统计从父任务合计里丢掉
	// （3×50 流 → pcap 150 包而 packets_sent=55；进度 83%/87% 跳变）。
	// 每个引擎子任务一个槽位，进度/统计以最后一次上报为准，完成后保留；
	// 父合计 = 全槽位求和（进度取均值）。父任务终态后整组删除。
	aggSlots map[string]map[string]*engineAggSlot // parentTaskID -> engineTaskID -> slot
	aggMu    sync.Mutex
}

// engineAggSlot is one engine sub-task's latest reported progress/stats.
type engineAggSlot struct {
	progress float64
	packets  int64
	bytes    int64
	flows    int64
}

// aggregateParent sums all slots of a parent (caller must hold aggMu).
func (h *TaskHandler) aggregateParent(parentTaskID string) (avg float64, packets, bytes, flows int64, count int) {
	slots := h.aggSlots[parentTaskID]
	var total float64
	for _, sl := range slots {
		total += sl.progress
		packets += sl.packets
		bytes += sl.bytes
		flows += sl.flows
	}
	count = len(slots)
	if count > 0 {
		avg = total / float64(count)
	}
	return
}

// releaseProgressBookkeeping drops the per-task entries the callbacks keep:
// the aggregation slots and progress throttle (keyed by parent task ID) plus
// the recorded output failures (keyed by engine task ID, i.e. "{parent}-{strategy}"
// for strategy tasks and the bare parent ID for batch tasks).
//
// The completion callback used to be the only place that deleted any of these,
// and its delete branch requires the row to still be running — so a stopped or
// deleted task left every entry behind forever. Every terminal path calls this.
func (h *TaskHandler) releaseProgressBookkeeping(taskID string) {
	h.aggMu.Lock()
	h.releaseProgressBookkeepingLocked(taskID)
	h.aggMu.Unlock()
}

// releaseTaskFailures drops the recorded output errors of one task. Failures
// are recorded under the engine task ID, so a parent with N strategies owns N
// prefixed entries plus (for batch tasks) the bare one.
func (h *TaskHandler) releaseTaskFailures(taskID string) {
	h.failMu.Lock()
	delete(h.failedTasks, taskID)
	prefix := taskID + "-"
	for k := range h.failedTasks {
		if strings.HasPrefix(k, prefix) {
			delete(h.failedTasks, k)
		}
	}
	h.failMu.Unlock()
}

// releaseProgressBookkeepingLocked 是 aggMu 已持有的版本。onEngineProgress
// 的"落库被拒"分支在同一个临界区里撤掉自己刚写的槽位，避免与 Stop/Delete
// 的释放形成"释放—复活"的交错。
func (h *TaskHandler) releaseProgressBookkeepingLocked(taskID string) {
	delete(h.aggSlots, taskID)
	h.progressMu.Lock()
	delete(h.lastProgressUpdate, taskID)
	h.progressMu.Unlock()
}

// SetPcapHandler enables task pcap auto-registration: on every completed
// pcap task the product is registered into the asset library (size-capped).
// The REST server wires its own pair; MCP-created TaskHandlers (callbacks
// disabled) never complete tasks and leave this unset.
func (h *TaskHandler) SetPcapHandler(p *PcapHandler) { h.pcap = p }

// maybeAutoRegisterPcap runs after a task outcome save; AutoRegisterTaskPcap
// applies its own guards (pcap output, completed, not yet registered).
func (h *TaskHandler) maybeAutoRegisterPcap(task *storage.TaskModel) {
	if h.pcap == nil {
		return
	}
	AutoRegisterTaskPcap(h.db, h.pcap, task)
}

// maybeAutoRegisterPcapAsync 在独立 goroutine 里跑入库（R8-D2）：完成回调
// 内联解析万包 pcap 需秒级，占用与后续任务共用的回调路径——连跑被上一产物
// 入库拖住（run 4s+）、create 排队 2.2~19.9s、time 截止尾部放大 5.8~13.2s，
// 三症状同根。异步后：任务终态照常落库，资产稍后 ready（pcap_asset_id 出现
// 时机由同步转"入库中"，轮询 get_task_progress 的调用方不受影响）。
// 解析本身与 MCP import 路径同为并发可达（sqlite 写锁自然串行化落库）。
func (h *TaskHandler) maybeAutoRegisterPcapAsync(task *storage.TaskModel) {
	if h.pcap == nil {
		return
	}
	go AutoRegisterTaskPcap(h.db, h.pcap, task)
}

// startSubmitHook is a test-only hook. When non-nil it is invoked after
// every engine task is submitted, letting tests deterministically simulate
// the engine completing/failing a task in the pre-fix "starting"-status
// window. Always nil in production.
var startSubmitHook func()

// runningWriteHook is a test-only hook invoked after the "running" DB write
// and before the engine SubmitTask loop — the ghost-task window: a Stop that
// lands here reads "running", stops an engine task that does not exist yet,
// and the subsequent submit resurrects it. Always nil in production.
var runningWriteHook func()

// parentAggregateWriteHook is a test-only hook invoked inside aggMu just
// before the parent aggregate row write (R8-D1 red test interleaves here to
// reproduce the out-of-order partial-sum overwrite). Always nil in production.
var parentAggregateWriteHook func()

// NewTaskHandler creates a new task handler and registers engine callbacks.
func NewTaskHandler(db *storage.DB, engine *core.Engine, wsHandler *websocket.Handler) *TaskHandler {
	return NewTaskHandlerWithCallbacks(db, engine, wsHandler, true)
}

// NewTaskHandlerWithCallbacks creates a TaskHandler. If registerCallbacks is
// false, engine callback fields (OnTaskComplete/OnTaskFailed/OnOutputError/
// OnProgress) are NOT overwritten -- used by MCP server to avoid clobbering
// the REST server's callbacks when it creates its own TaskHandler instance
// for direct method invocation.
func NewTaskHandlerWithCallbacks(db *storage.DB, engine *core.Engine, wsHandler *websocket.Handler, registerCallbacks bool) *TaskHandler {
	var hub *websocket.Hub
	if wsHandler != nil {
		hub = wsHandler.Hub()
	}
	h := &TaskHandler{
		db:                 db,
		engine:             engine,
		wsHub:              hub,
		failedTasks:        make(map[string]string),
		lastProgressUpdate: make(map[string]time.Time),
		aggSlots:           make(map[string]map[string]*engineAggSlot),
	}

	if registerCallbacks {
		// Register engine completion callback to update DB status
		engine.OnTaskComplete = h.onEngineTaskComplete

		// Register task failed callback to record error messages
		engine.OnTaskFailed = h.onEngineTaskFailed

		// Register output error callback to fail tasks on write errors
		engine.OnOutputError = h.onEngineOutputError

		// Register progress callback for continuous progress tracking
		engine.OnProgress = h.onEngineProgress
	}

	return h
}

// onEngineTaskFailed is called when an engine task fails (planning error, etc.).
// 它只登记失败原因；真正的终态落库在 onEngineTaskComplete。
func (h *TaskHandler) onEngineTaskFailed(engineTaskID string, errMsg string) {
	h.failMu.Lock()
	h.failedTasks[engineTaskID] = errMsg
	h.failMu.Unlock()
}

// stopSnapshotHook runs in Stop after the task row has been read and before the
// status write. A test interleaves a concurrent stats update here to prove the
// write does not clobber columns another writer just set. Always nil in
// production.
var stopSnapshotHook func()

// completeSnapshotHook is a test-only hook between the completion callback's
// status read and its terminal write, so a test can land a Stop in that window.
var completeSnapshotHook func()

// terminalStatuses lists the statuses that end a task's life. Used both by
// isTerminalStatus (read-side guard) and as the UPDATE-side WHERE clause in
// onEngineProgress, so the two cannot drift.
var terminalStatuses = []string{"completed", "failed", "stopped", "error"}

// startMu serializes the task-lifecycle HTTP handlers (Start/Stop/Delete).
//
// 作用域：进程内。部署形态是单实例（引擎输出独占本机 NIC 与本地文件系统，
// 多实例本身不可行）；若未来存储迁到 postgres 且部署转多实例，这里必须换
// 分布式锁，不能沿用包级 mutex。
//
// 锁序：startMu → {failMu, aggMu, progressMu, engine.taskMu, hub.mu}，
// 全部单向无环。引擎回调（OnProgress/OnTaskComplete）在 engine.taskMu 之外
// 触发且不回调本包的 Start/Stop/Delete，无重入。
//
// 调用者清单（任何改任务生命周期的 handler 必须持此锁）：
// Start (task_handler.go)、Stop、Delete。CreateBatch 不进锁族——
// 它建新行，与既有行的操作者无竞态对象；其失败出口由谓词保护。
//
// 持锁时间：整个 handler（含 DB 读写、writer 打开、MTU syscall、引擎提交）。
// 管理面操作，最坏几百 ms；WriteTimeout=65s、busy_timeout=60s 覆盖等待。
// 锁内不做任何会无限阻塞的等待（无用户交互、无网络对端等待）。
var startMu sync.Mutex

// isTerminalStatus reports whether a task status is a final state — the task
// has ended and nothing but an explicit restart may change it.
func isTerminalStatus(status string) bool {
	for _, s := range terminalStatuses {
		if status == s {
			return true
		}
	}
	return false
}

// markTaskError persists "this task failed" without rewriting the rest of the
// row. Every caller holds a snapshot read earlier in the request; a full-row
// Save from that snapshot silently rolls back anything another writer changed
// in between (progress callbacks write stats continuously).
//
// progress 固定写 0：走这条路径的都是"任务没跑起来"，沿用上一轮的 100 会
// 让记录读起来像"error at 100%"（与客户端报告问题 1 同形的矛盾态）。
//
// completed_at 固定写当前时刻：error 是终态，任务在此时结束。不能沿用
// task.CompletedAt——那是从 DB 读出来的旧值（往往是一小时前上一轮的完成
// 时间），而该字段会通过 TaskResponse 直接回给客户端。
// markTaskError persists "this task failed" without rewriting the rest of the
// row. The WHERE clause is supplied by the caller: Start's error exits claim
// "starting", CreateBatch's failure exits claim "running" (the row was created
// as running) — a terminal row (stopped/completed/failed) is never rewritten.
//
// 返回 (written, err)：
//
//	written=true,  err=nil   —— 正常落库
//	written=false, err=nil   —— 行已被接管/删除（谓词没匹配上）。调用方按
//	  无空响应规则给客户端响应，但**不得**再动这行的其它列。
//	err!=nil                 —— DB 故障。调用方必须回 500。
//
// 调用点清单（新增调用点必须处理返回值，漏一处就是静默行为）：
//
//	Start 校验出口 ×8（corrupt JSON / 策略不存在 / config 解析 / 无有效策略 /
//	  路径解析 / dual 校验 ×2 / MTU）—— 谓词 starting
//	Start 资源出口 ×3（全部 writer 失败 / running 写失败 / 全部提交失败）
//	  —— 谓词 starting
//	（CreateBatch 不走本函数，见其两处内联 Updates。）
func (h *TaskHandler) markTaskError(task *storage.TaskModel, where string, args ...interface{}) (bool, error) {
	now := currentTime()
	updates := map[string]interface{}{
		"status":        "error",
		"error_message": task.ErrorMessage,
		"progress":      0,
		"completed_at":  now,
	}
	res := h.db.Model(&storage.TaskModel{}).
		Where("id = ? AND "+where, append([]interface{}{task.ID}, args...)...).Updates(updates)
	if res.Error != nil {
		log.Printf("markTaskError: failed to persist error state for task %s: %v", task.ID, res.Error)
		return false, res.Error
	}
	if res.RowsAffected == 0 {
		log.Printf("markTaskError: task %s is no longer in the claimed state — "+
			"another path owns the row, error state not written", task.ID)
		return false, nil
	}
	task.CompletedAt = &now
	return true, nil
}

// applyTaskCompletion writes a task's terminal columns and reports whether
// this callback still owned the row when it wrote.
//
// 与 onEngineProgress 同一个道理（见 f2f9ba40）：完成回调开头读到的 running
// 只是**读到那一刻**的状态。Stop 可能在 SELECT 之后、这次写入之前把行写成
// stopped，无条件的 UPDATE 就把 stopped 又改回 completed/100。状态条件挂到
// WHERE 上才能原子判定"还是不是 running"。
//
// 返回 false 时调用方必须停手：不能广播完成、不能释放运行资源、不能入库
// pcap——那是另一轮运行（或一次停止）的行，本回调不再拥有它。
func (h *TaskHandler) applyTaskCompletion(taskID string, task *storage.TaskModel) bool {
	return h.applyTaskCompletionWhere(taskID, task, "status = ?", "running")
}

// applyTaskCompletionWhere 同上，WHERE 由调用方给——完成回调只接管 running
// 的行，而 Start 的对账入口接受 running/starting 两种未终态。
func (h *TaskHandler) applyTaskCompletionWhere(taskID string, task *storage.TaskModel, where string, args ...interface{}) bool {
	updates := map[string]interface{}{
		"status":   task.Status,
		"progress": task.Progress,
	}
	if task.CompletedAt != nil {
		updates["completed_at"] = *task.CompletedAt
	}
	if task.ErrorMessage != "" {
		updates["error_message"] = task.ErrorMessage
	}
	if completeSnapshotHook != nil {
		completeSnapshotHook()
	}
	res := h.db.Model(&storage.TaskModel{}).
		Where("id = ? AND "+where, append([]interface{}{taskID}, args...)...).Updates(updates)
	if res.Error != nil {
		// 终态写库失败不得静默：行会停在 running，只能等下一次 stale 对账
		// 修复。至少留下日志（Stop 在同类失败上是直接回 500 的）。
		log.Printf("applyTaskCompletion: failed to persist terminal state %q for task %s: %v",
			task.Status, taskID, res.Error)
		return false
	}
	return res.RowsAffected > 0
}

// onEngineOutputError is called when an output writer fails.
func (h *TaskHandler) onEngineOutputError(engineTaskID string, writeErr error) {
	taskID := engineTaskID
	if len(engineTaskID) > 37 {
		taskID = engineTaskID[:36]
	}

	log.Printf("output error for engine task %s: %v, failing task %s", engineTaskID, writeErr, taskID)

	// Record the failure before failing the engine task (FailTask triggers onEngineTaskComplete)
	h.failMu.Lock()
	h.failedTasks[engineTaskID] = writeErr.Error()
	h.failMu.Unlock()

	// Fail the engine task
	h.engine.FailTask(engineTaskID, writeErr.Error())

	// Unregister the broken writer
	h.engine.UnregisterOutputWriter(engineTaskID)
}

// onEngineProgress is called by the engine when task progress changes (>1% delta).
// It debounces DB updates to at most once per 2 seconds per parent task.
func (h *TaskHandler) onEngineProgress(engineTaskID string, progress float64, stats core.TaskStats) {
	// Extract parent task ID from composite engine task ID "{taskID}-{strategyID}".
	// 注意必须取前 36 字符：UUID 本身含连字符，SplitN("-") 会把父任务 ID
	// 截成第一段（如 "e65bf6fb"），WHERE 永不匹配——progress/stats 的
	// 落库曾因此整体失效（rows:0，实机日志抓出）。
	parentTaskID := engineTaskID
	if len(engineTaskID) > 36 {
		parentTaskID = engineTaskID[:36]
	}

	// Terminal tasks are read-only for progress: Stop sets "stopped" and the
	// final completion callback sets completed/failed. A progress callback
	// still in flight when the task ends must not rewrite progress/stats, or a
	// stopped task flips back to "50% running" with the stats of another
	// moment. 终态判定散在三处（Stop、完成回调、本函数）时，唯一安全的约定
	// 是：终态只由终态路径写，进度回调只写 running 的任务。
	var cur storage.TaskModel
	if err := h.db.Select("status").Where("id = ?", parentTaskID).First(&cur).Error; err == nil && isTerminalStatus(cur.Status) {
		return
	}

	// Throttle DB updates: at most once per 2 seconds per parent task.
	// progress>=100 bypasses the throttle: the final OnProgress (engine
	// forces a notify at 100) must land, otherwise completed tasks lose
	// their last stats delta and the client can never close the loop on
	// "how much was actually sent".
	//
	// 这里只读不写：时间戳必须在**落库成功**后才推进（见下方 aggMu 临界区
	// 内），否则"节流"会变成给每一个迟到回调开绿灯，而且 Stop 释放掉的
	// 条目会被重新建出来。
	h.progressMu.Lock()
	lastUpdate, exists := h.lastProgressUpdate[parentTaskID]
	h.progressMu.Unlock()
	if exists && time.Since(lastUpdate) < 2*time.Second && progress < 100 {
		return
	}

	// R7 缺陷 A：槽位制聚合（见 aggSlots 注释）——RangeTaskStore 只见存活
	// 子任务，已完成者的统计会在父合计里丢失；槽位以最后一次上报为准。
	h.aggMu.Lock()
	slots, ok := h.aggSlots[parentTaskID]
	if !ok {
		slots = make(map[string]*engineAggSlot)
		h.aggSlots[parentTaskID] = slots
	}
	slots[engineTaskID] = &engineAggSlot{
		progress: progress,
		packets:  stats.PacketsSent,
		bytes:    stats.BytesSent,
		flows:    int64(stats.FlowsCount),
	}
	// R8-D1：求和与父行落库必须同一把锁串行——旧实现求和在 upsert 时算、
	// DB 写在校锁外，先完成策略的写（旧的部分和）会乱序晚到覆盖最后的
	// 全和（客户端 6 轮中 3 轮：pcap 101,524 / 库 67,778=两策略和）。锁内
	// 写后写序=upsert 序，最后一次写必为最新全和。
	// R8-D1：求和与父行落库同一把锁串行——写序=upsert 序，最后一次写必
	// 为最新全和（旧序的迟到部分和覆盖在此结构下不可能）。
	avgProgress, aggPackets, aggBytes, aggFlows, _ := h.aggregateParent(parentTaskID)
	if parentAggregateWriteHook != nil {
		parentAggregateWriteHook()
	}
	// 终态约束必须挂在 UPDATE 的 WHERE 上，不能只靠上面的 SELECT：两次语句
	// 之间任务可能被 Stop / 完成回调写成终态，那时 SELECT 看到 running、
	// 这次 UPDATE 落地却是覆盖终态行（进度又跳回"跑到一半"）。WHERE 里的
	// 状态条件是原子的——终态行的 progress 只能由终态路径写。
	// RowsAffected == 0 即"这条已被终态化"，本次进度作废，无需广播。
	res := h.db.Model(&storage.TaskModel{}).
		Where("id = ? AND status NOT IN ?", parentTaskID, terminalStatuses).
		Updates(map[string]interface{}{
			"progress":     avgProgress,
			"packets_sent": aggPackets,
			"bytes_sent":   aggBytes,
			"flows_count":  aggFlows,
		})
	// 行已终态或已删（RowsAffected=0）——这一轮回音不属于 running 的任务了。
	// 必须在同一临界区里把刚写进去的记账撤掉：Stop/Delete 的释放已经完成，
	// 留着就等于刚释放的条目又被迟到回调复活。
	if res.Error != nil {
		// 只记日志，**不要**清记账：任务可能还在跑（SQLite 被 pcap_packets
		// 的批量插入挤住就会写超时），清掉槽位会让已完成子策略的统计从
		// 父合计里消失——正是 R7 缺陷 A 要防的事。
		log.Printf("onEngineProgress: failed to persist progress for task %s: %v",
			parentTaskID, res.Error)
		h.aggMu.Unlock()
		return
	}
	if res.RowsAffected == 0 {
		// 行已终态或已删（WHERE 里的状态条件没匹配上）：这一轮回音不属于
		// running 的任务了。必须在同一临界区里撤掉刚写进去的记账，否则
		// Stop/Delete 刚释放的条目会被迟到回调复活。
		h.releaseProgressBookkeepingLocked(parentTaskID)
		h.aggMu.Unlock()
		return
	}
	// 落库成功才记节流时间戳——与槽位在同一个临界区里推进，保证"释放之后
	// 不会再被迟到回调重建"。
	h.progressMu.Lock()
	h.lastProgressUpdate[parentTaskID] = time.Now()
	h.progressMu.Unlock()
	h.aggMu.Unlock()

	// Broadcast progress update via WebSocket
	if h.wsHub != nil {
		h.wsHub.BroadcastToTask(parentTaskID, websocket.Message{
			Type: websocket.TypeProgressUpdate,
			Data: map[string]interface{}{
				"task_id":  parentTaskID,
				"progress": avgProgress,
				"stats":    stats,
			},
		})
	}
}

// onEngineTaskComplete is called by the engine when a task finishes (completed or failed).
// The engine task ID format is "{taskID}-{strategyID}", so we extract the parent task ID.
// Batch tasks are a special case: their engine task ID == task ID (no suffix), and
// they use BatchConfig instead of StrategyIDs — so the strategyIDs loop below would
// no-op and we'd miss the failure-message collection path.
func (h *TaskHandler) onEngineTaskComplete(engineTaskID string) {
	// Extract parent task ID (format: {taskID}-{strategyID}, where taskID is a UUID)
	// UUID format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx (36 chars)
	// Engine task ID: {36-char-uuid}-{strategy-uuid}
	taskID := engineTaskID
	if len(engineTaskID) > 37 {
		taskID = engineTaskID[:36]
	}

	var task storage.TaskModel
	if err := h.db.Where("id = ?", taskID).First(&task).Error; err != nil {
		log.Printf("onEngineTaskComplete: task %s not found in DB: %v", taskID, err)
		return
	}

	// Batch tasks: single engine task, ID == taskID. Skip the strategyIDs
	// loop (empty by design) and check this engine task directly.
	if task.BatchConfig != "" {
		// Engine task still running -> not done yet.
		if _, err := h.engine.GetTaskStatus(taskID); err == nil {
			return
		}
		if task.Status != "running" {
			return
		}
		now := currentTime()
		task.CompletedAt = &now

		h.failMu.Lock()
		var failMsgs []string
		if errMsg, ok := h.failedTasks[taskID]; ok {
			failMsgs = append(failMsgs, fmt.Sprintf("%s: %s", taskID, errMsg))
			delete(h.failedTasks, taskID)
		}
		h.failMu.Unlock()

		if len(failMsgs) > 0 {
			task.Status = "failed"
			task.ErrorMessage = fmt.Sprintf("output error: %v", failMsgs)
			log.Printf("batch task %s marked as failed in DB: %s", taskID, task.ErrorMessage)
		} else {
			task.Status = "completed"
			task.Progress = 100
			log.Printf("batch task %s marked as completed in DB", taskID)
		}
		// P2-⑤：Updates 指定列而非 Save 全列——task 是回调开始时的旧快照，
		// 全列 Save 会把 onEngineProgress 刚落库的实发统计打回 0。
		if !h.applyTaskCompletion(taskID, &task) {
			// 行已不是 running：Stop 抢先写了 stopped（或这轮运行已被重启）。
			// 不能再广播完成、释放运行资源或入库 pcap。
			return
		}

		if h.wsHub != nil {
			msgType := websocket.TypeTaskCompleted
			if task.Status == "failed" {
				msgType = websocket.TypeTaskFailed
			}
			h.wsHub.BroadcastToTask(taskID, websocket.Message{
				Type: msgType,
				Data: map[string]interface{}{
					"task_id":  taskID,
					"status":   task.Status,
					"progress": task.Progress,
				},
			})
		}

		h.releasePortGroupPorts(&task)
		// Unregister closes the output writers (pcap fsync) — the file is
		// only final after this, so auto-registration must come later.
		h.engine.UnregisterOutputWriter(taskID)
		h.engine.UnregisterDualWriter(taskID)
		h.engine.CleanupTaskFlowControl(taskID)
		h.maybeAutoRegisterPcapAsync(&task)
		// R7 缺陷 A：父任务终态后整组删除聚合槽位（防 handler 生命周期泄漏）。
		h.releaseProgressBookkeeping(taskID)
		// 消费路径之外的残余失败条目（例如eid登记后策略消失）也一并清——
		// 幂等，不影响上面已消费的键。
		h.releaseTaskFailures(taskID)
		return
	}

	// Check if all engine tasks for this task are done
	var strategyIDs []string
	json.Unmarshal([]byte(task.StrategyIDs), &strategyIDs)

	allDone := true
	for _, sid := range strategyIDs {
		eid := fmt.Sprintf("%s-%s", taskID, sid)
		if _, err := h.engine.GetTaskStatus(eid); err == nil {
			// Still in taskStore = still running
			allDone = false
			break
		}
	}

	if allDone && task.Status == "running" {
		now := currentTime()
		task.CompletedAt = &now

		// Check if any engine task failed
		h.failMu.Lock()
		var failMsgs []string
		for _, sid := range strategyIDs {
			eid := fmt.Sprintf("%s-%s", taskID, sid)
			if errMsg, ok := h.failedTasks[eid]; ok {
				failMsgs = append(failMsgs, fmt.Sprintf("%s: %s", eid, errMsg))
				delete(h.failedTasks, eid)
			}
		}
		h.failMu.Unlock()

		if len(failMsgs) > 0 {
			task.Status = "failed"
			task.ErrorMessage = fmt.Sprintf("output error: %v", failMsgs)
			log.Printf("task %s marked as failed in DB: %s", taskID, task.ErrorMessage)
		} else {
			task.Status = "completed"
			task.Progress = 100
			log.Printf("task %s marked as completed in DB", taskID)
		}
		// 同 batch 分支：指定列更新，不覆盖实发统计（P2-⑤）。
		if !h.applyTaskCompletion(taskID, &task) {
			// 行已不是 running（Stop 抢先写了 stopped，或任务被重启）：
			// 本回调不再拥有这行，不得再广播完成或释放新运行的资源。
			return
		}

		// Broadcast task completion via WebSocket
		if h.wsHub != nil {
			msgType := websocket.TypeTaskCompleted
			if task.Status == "failed" {
				msgType = websocket.TypeTaskFailed
			}
			h.wsHub.BroadcastToTask(taskID, websocket.Message{
				Type: msgType,
				Data: map[string]interface{}{
					"task_id":  taskID,
					"status":   task.Status,
					"progress": task.Progress,
				},
			})
		}

		// Release port group ports
		h.releasePortGroupPorts(&task)

		// Unregister output writers (and dual-writers, if any) for all engine tasks
		for _, sid := range strategyIDs {
			eid := fmt.Sprintf("%s-%s", taskID, sid)
			h.engine.UnregisterOutputWriter(eid)
			h.engine.UnregisterDualWriter(eid)
		}
		// Batch tasks register a single writer under the plain taskID
		// (no strategy suffix); unregister it too. No-op for strategy tasks.
		h.engine.UnregisterOutputWriter(taskID)
		h.engine.UnregisterDualWriter(taskID)

		// Clean up task-level flow control state (parent rate bucket +
		// shared flow counter). Safe no-op when no ceiling was set.
		h.engine.CleanupTaskFlowControl(taskID)

		// Unregister closes the output writers (pcap fsync) — the file is
		// only final after this, so auto-registration must come later.
		h.maybeAutoRegisterPcapAsync(&task)

		// R7 缺陷 A：父任务终态后整组删除聚合槽位。
		h.releaseProgressBookkeeping(taskID)
		h.releaseTaskFailures(taskID)
	}
}

// resolvePortGroupIface returns the first interface of a port group — the
// primary NIC a task writes to (output_type=port_group and both).
func (h *TaskHandler) resolvePortGroupIface(groupID string) (string, error) {
	var portGroup storage.PortGroupModel
	if err := h.db.Where("id = ?", groupID).First(&portGroup).Error; err != nil {
		return "", fmt.Errorf("port group not found: %s", groupID)
	}
	var portsConfig []map[string]interface{}
	json.Unmarshal([]byte(portGroup.PortsConfig), &portsConfig)
	if len(portsConfig) > 0 {
		if i, ok := portsConfig[0]["interface"].(string); ok && i != "" {
			return i, nil
		}
	}
	return "", fmt.Errorf("port group has no interface configured")
}

// releasePortGroupPorts releases ports allocated for a task's port group.
func (h *TaskHandler) releasePortGroupPorts(task *storage.TaskModel) {
	if task.OutputType != "port_group" && task.OutputType != "both" {
		return
	}
	var outputConfig OutputConfigRequest
	json.Unmarshal([]byte(task.OutputConfig), &outputConfig)

	var portGroup storage.PortGroupModel
	if err := h.db.Where("id = ?", outputConfig.PortGroupID).First(&portGroup).Error; err != nil {
		return
	}

	var portsConfig []map[string]interface{}
	json.Unmarshal([]byte(portGroup.PortsConfig), &portsConfig)

	for _, portConfig := range portsConfig {
		if iface, ok := portConfig["interface"].(string); ok {
			h.db.Model(&storage.PortModel{}).
				Where("name = ? AND current_task_id = ?", iface, task.ID).
				Updates(map[string]interface{}{
					"status":          "idle",
					"current_task_id": "",
				})
		}
	}
}

// ensureTaskMTU ensures every NIC the task will write to has MTU >=
// engine.min_mtu. Returns the list of interfaces it was asked to check
// (for error reporting) and an error if any raise failed. For port_group
// output this walks every interface in the group; for dual-port replay it
// also checks interface2. pcap output is skipped (no NIC involved). On
// raise failure the caller must mark the task failed -- the operator
// needs to either run as root or lower engine.min_mtu.
func (h *TaskHandler) ensureTaskMTU(task *storage.TaskModel, interface2 string) ([]string, error) {
	minMTU := h.engine.MinMTU()
	if minMTU <= 0 {
		return nil, nil
	}
	if task.OutputType != "port_group" && task.OutputType != "both" {
		// pcap output doesn't touch a NIC.
		return nil, nil
	}
	var outputConfig OutputConfigRequest
	if err := json.Unmarshal([]byte(task.OutputConfig), &outputConfig); err != nil {
		return nil, fmt.Errorf("corrupt output_config: %w", err)
	}
	var portGroup storage.PortGroupModel
	if err := h.db.Where("id = ?", outputConfig.PortGroupID).First(&portGroup).Error; err != nil {
		return nil, fmt.Errorf("port group %s not found: %w", outputConfig.PortGroupID, err)
	}
	var portsConfig []map[string]interface{}
	if err := json.Unmarshal([]byte(portGroup.PortsConfig), &portsConfig); err != nil {
		return nil, fmt.Errorf("corrupt ports_config in port group %s: %w", portGroup.ID, err)
	}
	var ifaces []string
	seen := make(map[string]bool)
	for _, portConfig := range portsConfig {
		if iface, ok := portConfig["interface"].(string); ok && iface != "" && !seen[iface] {
			seen[iface] = true
			ifaces = append(ifaces, iface)
		}
	}
	if interface2 != "" && !seen[interface2] {
		ifaces = append(ifaces, interface2)
	}
	for _, iface := range ifaces {
		// Existence first: EnsureMTU's "interface %s: no such network
		// interface" (Go net.InterfaceByName) would otherwise surface
		// wrapped in "MTU raise failed", which reads as an MTU problem
		// when the real cause is a typo'd interface name.
		if _, err := net.InterfaceByName(iface); err != nil {
			return ifaces, fmt.Errorf("network interface %s does not exist: %w (check flowb_query_system action=interfaces for valid names)", iface, err)
		}
		if err := netif.EnsureMTU(iface, minMTU); err != nil {
			return ifaces, fmt.Errorf("MTU raise failed for %s: %w", iface, err)
		}
	}
	return ifaces, nil
}

// CreateTaskRequest represents a create task request.
type CreateTaskRequest struct {
	Name         string               `json:"name" binding:"required"`
	StrategyIDs  []string             `json:"strategy_ids" binding:"required,min=1"`
	OutputType   string               `json:"output_type" binding:"required"` // "port_group" or "pcap"
	OutputConfig *OutputConfigRequest `json:"output_config" binding:"required"`
	FlowControl  *FlowControlRequest  `json:"flow_control"` // Optional, task-level flow control
}

// CreateBatchTaskRequest represents a mixed-traffic batch task request. The
// caller supplies a full BatchSpec (multiple protocol classes) inline rather
// than referencing saved strategies.
type CreateBatchTaskRequest struct {
	Name         string               `json:"name" binding:"required"`
	Batch        *core.BatchSpec      `json:"batch" binding:"required"`
	OutputType   string               `json:"output_type" binding:"required"` // "port_group" or "pcap"
	OutputConfig *OutputConfigRequest `json:"output_config" binding:"required"`
}

// OutputConfigRequest represents output configuration.
type OutputConfigRequest struct {
	PortGroupID string `json:"port_group_id"`        // For port_group output
	PcapPath    string `json:"pcap_path"`            // For pcap output
	Interface2  string `json:"interface2,omitempty"` // Second interface for dual-port replay (§16.11)
}

// TaskStatsResponse represents task statistics in the response.
type TaskStatsResponse struct {
	PacketsSent int64   `json:"packets_sent"`
	BytesSent   int64   `json:"bytes_sent"`
	FlowsCount  int64   `json:"flows_count"`
	CurrentPPS  float64 `json:"current_pps"`
	CurrentBPS  float64 `json:"current_bps"`
}

// StrategyBrief represents a strategy summary in the task response.
type StrategyBrief struct {
	ID          string              `json:"id"`
	Name        string              `json:"name"`
	Mode        string              `json:"mode,omitempty"`
	Protocol    string              `json:"protocol"`
	FlowControl *FlowControlRequest `json:"flow_control,omitempty"`
}

// TaskResponse represents a task response.
type TaskResponse struct {
	ID           string               `json:"id"`
	UserID       string               `json:"user_id"`
	Name         string               `json:"name"`
	Protocol     string               `json:"protocol,omitempty"`
	StrategyIDs  []string             `json:"strategy_ids"`
	Strategies   []StrategyBrief      `json:"strategies,omitempty"`
	OutputType   string               `json:"output_type"`
	OutputConfig *OutputConfigRequest `json:"output_config"`
	FlowControl  *FlowControlRequest  `json:"flow_control"`
	Status       string               `json:"status"`
	ErrorMessage string               `json:"error_message,omitempty"`
	Progress     float64              `json:"progress"`
	Stats        *TaskStatsResponse   `json:"stats,omitempty"`
	// DownloadURL 对 pcap 任务返回公开下载直链（相对路径，无鉴权——任务
	// UUID 即能力凭证）；port_group 任务为空。
	DownloadURL string `json:"download_url,omitempty"`
	// PcapAssetID：pcap 产物自动注册进资产库后的资产 id（超阈值/失败时为
	// 空）。PcapAssetNote：已注册时为 flowb_manage_pcaps 使用提示；未注册
	// 时为原因 + 主动注册指引。ShadowNote：both 模式影子降级/截断记录。
	PcapAssetID   string `json:"pcap_asset_id,omitempty"`
	PcapAssetNote string `json:"pcap_asset_note,omitempty"`
	ShadowNote    string `json:"shadow_note,omitempty"`
	CreatedAt     int64  `json:"created_at"`
	UpdatedAt     int64  `json:"updated_at"`
	StartedAt     *int64 `json:"started_at,omitempty"`
	CompletedAt   *int64 `json:"completed_at,omitempty"`
}

// Create creates a new task (idempotent).
func (h *TaskHandler) Create(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	var req CreateTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// Unified schema gate: shape (task.json) + flow-control envelope text.
	// Strategy existence/ownership and the replay+bps conflict run below
	// with the loaded models (gate re-runs including the conflict once
	// strategies are known).
	// 第14轮 B10：组合合法性先于缺参——both×interface2 的真约束
	// （errBothDual）优先于 schema 缺参报错，否则报错把用户引向补
	// port_group_id（误导）。
	if req.OutputType == "both" && req.OutputConfig != nil && req.OutputConfig.Interface2 != "" {
		BadRequest(c, errBothDual)
		return
	}
	if !taskSchemaGate(c, taskCreateDoc(req.Name, toAnySlice(req.StrategyIDs), req.OutputType, toAny(req.OutputConfig), toAny(req.FlowControl)), nil) {
		return
	}

	// Validate strategy IDs and capture primary protocol
	var primaryProtocol string
	for _, strategyID := range req.StrategyIDs {
		var strategy storage.StrategyModel
		if err := h.db.Where("id = ? AND user_id = ?", strategyID, userID).First(&strategy).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				BadRequest(c, fmt.Sprintf("strategy %s not found", strategyID))
				return
			}
			InternalError(c, "failed to validate strategy: "+err.Error())
			return
		}
		if primaryProtocol == "" {
			primaryProtocol = strategy.Protocol
		}
	}

	// Collect strategies for replay+bps conflict check (needed below).
	// The check runs through the unified schema entry so REST, MCP and
	// tests share one message; the legacy helper stays as the single
	// implementation behind it.
	strategiesForFC := make([]storage.StrategyModel, 0, len(req.StrategyIDs))
	for _, strategyID := range req.StrategyIDs {
		var strategy storage.StrategyModel
		if err := h.db.Where("id = ? AND user_id = ?", strategyID, userID).First(&strategy).Error; err != nil {
			// already validated above, skip on error
			continue
		}
		strategiesForFC = append(strategiesForFC, strategy)
	}
	if !taskSchemaGate(c, taskCreateDoc(req.Name, toAnySlice(req.StrategyIDs), req.OutputType, toAny(req.OutputConfig), toAny(req.FlowControl)), toStrategyViews(strategiesForFC)) {
		return
	}

	// Serialize for storage
	outputConfigJSON, _ := json.Marshal(req.OutputConfig)
	// D-FILE-2 第14轮 B1/B2 收口：flow_control 随策略存储（MCP 层
	// embeddedFlowControl 提取入策略），任务创建必须继承——否则
	// StrategyModelToTask 读 task.FlowControl 恒空，TaskFCType 恒空，
	// task 级 time/bps 流控对主流程完全失效（B1/B2 实测根因）。显式
	// req.FlowControl 优先；未给时继承首个携带 flow_control 的策略。
	var flowControlJSON []byte
	switch {
	case req.FlowControl != nil:
		flowControlJSON, _ = json.Marshal(req.FlowControl)
	default:
		for _, sf := range strategiesForFC {
			if sf.FlowControl != "" {
				flowControlJSON = []byte(sf.FlowControl)
				break
			}
		}
	}
	// Sort strategy IDs for consistent idempotency checks AND canonical storage,
	// so a duplicate submission with reversed order still hits the same record.
	sortedStrategyIDs := make([]string, len(req.StrategyIDs))
	copy(sortedStrategyIDs, req.StrategyIDs)
	sort.Strings(sortedStrategyIDs)
	sortedStrategyIDsJSON, _ := json.Marshal(sortedStrategyIDs)

	// Check if an ACTIVE task already exists with same config for this user.
	// FlowControl is part of the identity: different ceilings = different task.
	var existingTask storage.TaskModel
	if err := h.db.Where("user_id = ? AND strategy_ids = ? AND output_config = ? AND flow_control = ? AND status IN ?",
		userID, string(sortedStrategyIDsJSON), string(outputConfigJSON), string(flowControlJSON),
		[]string{"pending", "running"}).First(&existingTask).Error; err == nil {
		Success(c, map[string]string{
			"id":      existingTask.ID,
			"message": "task already exists",
		})
		return
	}

	// Create new task. Store the SORTED strategy_ids so idempotency lookups
	// (which query by sorted form) match regardless of insertion order.
	task := &storage.TaskModel{
		ID:           uuid.New().String(),
		UserID:       userID,
		Name:         req.Name,
		StrategyIDs:  string(sortedStrategyIDsJSON),
		Protocol:     primaryProtocol,
		OutputType:   req.OutputType,
		OutputConfig: string(outputConfigJSON),
		FlowControl:  string(flowControlJSON),
		Status:       "pending",
		Progress:     0,
	}

	if err := h.db.Create(task).Error; err != nil {
		InternalError(c, "failed to create task: "+err.Error())
		return
	}

	Created(c, map[string]string{"id": task.ID})
}

// CreateBatch creates and immediately starts a mixed-traffic batch task. The
// BatchSpec runs multiple protocol classes concurrently in one engine task.
// POST /api/v1/tasks/batch
func (h *TaskHandler) CreateBatch(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	var req CreateBatchTaskRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		BadRequest(c, "invalid request: "+err.Error())
		return
	}

	// D-ROBUST-2（复测 N1/N2）：batch 每类建单期字段闸——与单任务入口对齐
	// （V9 范围/未知字段/声明形状），消除"同一非法配置单任务拒、批量放行"
	// 的校验分叉。flow_count 缺省 1（与单任务省略=1 流同语义；显式 0 同归
	// 缺省，§6.4 0=默认惯例同源）。静态四元组守卫不适用：batch 的 flows=N
	// 是 §2.5 明批的复制入口（见 schema.ValidateBatchClassLayerFields）。
	for i := range req.Batch.Classes {
		class := &req.Batch.Classes[i]
		if class.Type == "replay" {
			continue
		}
		if class.FlowCount == 0 {
			class.FlowCount = 1
		}
		if msg := schema.ValidateBatchClassLayerFields(class.Config); msg != "" {
			BadRequest(c, fmt.Sprintf("class[%d] %s: %s", i, class.ID, msg))
			return
		}
		// D-REQ-1 批 4（BUG-09 剩余面）：每类建单期全量语义 dry-run——
		// 复用 BuildLayersPlanner + ChainPlanner.ValidateSpec 流水线（131
		// 协议语义校验器），使"建单通过、开跑才报 validation failed"的
		// 延迟拒绝与单任务入口行为一致。纯函数无运行态依赖。
		if layersRaw, lok := class.Config["layers"]; lok {
			layersJSON, lerr := json.Marshal(layersRaw)
			if lerr != nil {
				BadRequest(c, fmt.Sprintf("class[%d] %s: layers marshal: %s", i, class.ID, lerr.Error()))
				return
			}
			planner, perr := layers.BuildLayersPlanner(class.Type, layersJSON)
			if perr != nil {
				// 同 strategy_handler：测试环境未导入的协议跳过 dry-run。
				if strings.Contains(perr.Error(), "generator not implemented") ||
					strings.Contains(perr.Error(), "not registered") {
					continue
				}
				BadRequest(c, fmt.Sprintf("class[%d] %s: %s", i, class.ID, perr.Error()))
				return
			}
			spec := core.MapToFlowSpec(class.Config, class.Type)
			if verr := planner.Validate(spec); verr != nil {
				BadRequest(c, fmt.Sprintf("class[%d] %s: %s", i, class.ID, verr.Error()))
				return
			}
		}
	}

	// Unified schema gate: task shape (batch form) + batch class semantics
	// via core.ValidateBatchSpec. Output presence and historic messages
	// preserved; engine SubmitTask re-validates as before.
	if !taskSchemaGate(c, map[string]interface{}{
		"name": req.Name, "batch": toAnyBatch(req.Batch),
		"output_type": req.OutputType, "output_config": toAny(req.OutputConfig),
	}, nil) {
		return
	}

	taskID := uuid.New().String()

	// Resolve output: interface name for port_group, resolved path for pcap.
	// both = interface (primary) + shadow pcap path (defaulted from the task
	// id and persisted into output_config so the auto-register hook and the
	// response surface can find the file).
	outputMode := "pcap"
	iface := ""
	pcapFile := ""
	shadowPcap := ""
	var err error
	if req.OutputType == "port_group" {
		outputMode = "interface"
		iface, err = h.resolvePortGroupIface(req.OutputConfig.PortGroupID)
		if err != nil {
			BadRequest(c, err.Error())
			return
		}
	} else if req.OutputType == "both" {
		outputMode = "interface"
		iface, err = h.resolvePortGroupIface(req.OutputConfig.PortGroupID)
		if err != nil {
			BadRequest(c, err.Error())
			return
		}
		if req.OutputConfig.PcapPath == "" {
			req.OutputConfig.PcapPath = "pcap/" + taskID + "_shadow.pcap"
		}
		resolved, err := resolvePcapPath(req.OutputConfig.PcapPath)
		if err != nil {
			BadRequest(c, err.Error())
			return
		}
		shadowPcap = resolved
		req.OutputConfig.PcapPath = resolved
	} else {
		resolved, err := resolvePcapPath(req.OutputConfig.PcapPath)
		if err != nil {
			BadRequest(c, err.Error())
			return
		}
		pcapFile = resolved
	}

	// Detect dual-port replay: a replay class with direction="dual" OR an
	// explicit interface2 in the output config (§16.11). Dual-port routes c2s
	// packets to the primary interface and s2c to the second.
	dualPort := req.OutputConfig != nil && req.OutputConfig.Interface2 != ""
	if !dualPort {
		for _, class := range req.Batch.Classes {
			if class.Type == "replay" && len(class.Replay) > 0 {
				var rs struct {
					Direction string `json:"direction"`
				}
				if json.Unmarshal(class.Replay, &rs) == nil && rs.Direction == "dual" {
					dualPort = true
					break
				}
			}
		}
	}
	// both×dual rejection comes before the dual-port validation below so the
	// message names the real constraint, not the missing interface2.
	if req.OutputType == "both" && dualPort {
		BadRequest(c, errBothDual)
		return
	}
	if dualPort && outputMode == "interface" && req.OutputType != "both" && (req.OutputConfig == nil || req.OutputConfig.Interface2 == "") {
		BadRequest(c, "dual-port replay requires a second interface (interface2 in output_config)")
		return
	}

	// Create + register the output writer BEFORE submitting (avoids race).
	var writer core.PacketWriter
	if outputMode == "interface" {
		if req.OutputType == "both" {
			// both: NIC primary + best-effort shadow pcap. Shadow issues
			// degrade to the task's shadow_note; NIC issues fail the task.
			// batch 是单 engine task 单消费者——不经共享注册表,直接开。
			sink, serr := output.NewPCAPWriterWithCap(shadowPcap, defaultShadowPcapMaxBytes)
			if serr != nil {
				InternalError(c, "failed to create shadow pcap writer: "+serr.Error())
				return
			}
			writer, err = newShadowPacketWriterWithSink(iface, &pcapPacketWriter{w: sink}, func(msg string) {
				h.noteShadowIssue(taskID, msg)
			})
			if err != nil {
				sink.Close()
			}
		} else {
			writer, err = newInterfacePacketWriter(iface)
		}
	} else {
		writer, err = newPcapPacketWriter(pcapFile)
	}
	if err != nil {
		InternalError(c, "failed to create output writer: "+err.Error())
		return
	}
	if dualPort {
		// Register a dual-port writer pair: c2s -> primary, s2c -> secondary.
		var writer2 core.PacketWriter
		if outputMode == "interface" {
			writer2, err = newInterfacePacketWriter(req.OutputConfig.Interface2)
		} else {
			// Dual-file pcap output: append ".s2c" to the pcap path.
			writer2, err = newPcapPacketWriter(pcapFile + ".s2c")
		}
		if err != nil {
			writer.Close()
			InternalError(c, "failed to create second output writer: "+err.Error())
			return
		}
		h.engine.RegisterDualWriter(taskID, writer, writer2)
	} else {
		h.engine.RegisterOutputWriter(taskID, writer)
	}

	// Persist a task record (StrategyIDs empty; BatchConfig holds the spec).
	batchJSON, _ := json.Marshal(req.Batch)
	outputConfigJSON, _ := json.Marshal(req.OutputConfig)
	now := currentTime()
	taskModel := &storage.TaskModel{
		ID:           taskID,
		UserID:       userID,
		Name:         req.Name,
		Protocol:     "batch",
		BatchConfig:  string(batchJSON),
		OutputType:   req.OutputType,
		OutputConfig: string(outputConfigJSON),
		Status:       "running",
		StartedAt:    &now,
	}
	if err := h.db.Create(taskModel).Error; err != nil {
		h.releaseBatchWriters(taskID, dualPort)
		InternalError(c, "failed to create task record: "+err.Error())
		return
	}

	// Raise NIC MTU if engine.min_mtu is configured. Done AFTER the task
	// record is persisted (so a failure leaves a clear audit trail) but
	// BEFORE SubmitTask (so the engine never sees a task whose NIC can't
	// fit the packets). On failure the task is marked failed.
	interface2ForDual := ""
	if dualPort && req.OutputConfig != nil {
		interface2ForDual = req.OutputConfig.Interface2
	}
	if _, err := h.ensureTaskMTU(taskModel, interface2ForDual); err != nil {
		// 终态先落库、writer 后释放：终态落库是原子的（谓词 running），
		// 之后迟到的进度写入会被终态谓词挡住；release 放 defer，写库失败
		// 的路径也能收回句柄。
		taskModel.Status = "error"
		taskModel.ErrorMessage = err.Error()
		// 按列更新而非 Save 全行：taskModel 是建单时的快照，整行写回会把
		// 期间落库的统计/进度列打回旧值。终态先落库、writer 后释放——
		// 终态谓词挡住迟到的进度写入后，再收回句柄。无论落库成败都要释放
		// （写库失败的路径同样不能漏），所以先 release 再检查结果。
		mtuRes := h.db.Model(&storage.TaskModel{}).Where("id = ? AND status = ?", taskID, "running").
			Updates(map[string]interface{}{
				"status":        "error",
				"error_message": taskModel.ErrorMessage,
				"progress":      0,
				"completed_at":  currentTime(),
			})
		h.releaseBatchWriters(taskID, dualPort)
		if mtuRes.Error != nil {
			InternalError(c, "MTU check failed ("+err.Error()+") and the error state could not be persisted: "+mtuRes.Error.Error())
			return
		}
		if mtuRes.RowsAffected == 0 {
			// 行已不在 running（防御纵深）：不能宣称错误细节。
			InternalError(c, "MTU check failed ("+err.Error()+"), and the task row was concurrently updated")
			return
		}
		BadRequest(c, taskModel.ErrorMessage)
		return
	}

	// Submit the batch engine task (engine task ID == taskModel ID, so the
	// existing completion callback marks this task done when it finishes).
	coreTask := core.Task{
		ID:         taskID,
		Name:       req.Name,
		UserID:     userID,
		Protocol:   "batch",
		Batch:      req.Batch,
		OutputMode: outputMode,
		Interface:  iface,
		PcapFile:   pcapFile,
	}
	if dualPort && req.OutputConfig != nil {
		coreTask.Interface2 = req.OutputConfig.Interface2
	}
	if err := h.engine.SubmitTask(coreTask); err != nil {
		taskModel.Status = "error"
		taskModel.ErrorMessage = err.Error()
		// 同 MTU 分支：终态先落库（谓词 running 原子），writer 后释放——
		// 两条失败分支顺序一致。落库失败不得静默。
		subRes := h.db.Model(&storage.TaskModel{}).Where("id = ? AND status = ?", taskID, "running").
			Updates(map[string]interface{}{
				"status":        "error",
				"error_message": taskModel.ErrorMessage,
				"progress":      0,
				"completed_at":  currentTime(),
			})
		h.releaseBatchWriters(taskID, dualPort)
		if subRes.Error != nil {
			InternalError(c, "task submission failed ("+err.Error()+") and the error state could not be persisted: "+subRes.Error.Error())
			return
		}
		if subRes.RowsAffected == 0 {
			InternalError(c, "task submission failed ("+err.Error()+"), and the task row was concurrently updated")
			return
		}
		BadRequest(c, err.Error())
		return
	}

	Created(c, map[string]string{"id": taskID})
}

// releaseBatchWriters closes whatever CreateBatch registered for a task before
// it failed. Dual-port tasks register through RegisterDualWriter, so calling
// only UnregisterOutputWriter leaves both writers (and their file/NIC handles)
// in the engine forever — the single-writer map never held them.
func (h *TaskHandler) releaseBatchWriters(taskID string, dualPort bool) {
	if dualPort {
		h.engine.UnregisterDualWriter(taskID)
		// A dual task registers the pair, not the primary alone; but
		// UnregisterOutputWriter is a harmless no-op if nothing is there.
		return
	}
	h.engine.UnregisterOutputWriter(taskID)
}

// List lists all tasks for the current user with server-side pagination.
func (h *TaskHandler) List(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	// Parse query parameters
	p := parsePageParams(c, 20, 100)
	size := p.Size

	// Build query
	query := h.db.Model(&storage.TaskModel{}).Where("user_id = ?", userID)

	// Status filter
	if statusFilter := c.Query("status"); statusFilter != "" {
		query = query.Where("status = ?", statusFilter)
	}

	// Name prefix filter (OBS-3 2026-10-06)：大库下 LLM 按前缀检索自己的任务。
	// LIKE 元字符转义，用户输入按字面前缀匹配。
	if np := c.Query("name_prefix"); np != "" {
		esc := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`).Replace(np)
		query = query.Where("name LIKE ? ESCAPE '\\'", esc+"%")
	}

	// Count total
	var total int64
	// D-SCHEMA-1（BUG-11）：Count 错误不得静默——吞掉后 total=0 造成"任务
	// 全部消失"假象（SQLite busy 排队期间客户端误判数据丢失）。
	if err := query.Count(&total).Error; err != nil {
		InternalError(c, "count tasks failed: "+err.Error())
		return
	}

	// Sorting
	sortBy := c.DefaultQuery("sort_by", "created_at")
	sortOrder := c.DefaultQuery("sort_order", "descending")
	allowedSortColumns := map[string]bool{"created_at": true, "updated_at": true, "name": true, "status": true, "progress": true}
	if !allowedSortColumns[sortBy] {
		sortBy = "created_at"
	}
	orderDir := "DESC"
	if sortOrder == "ascending" {
		orderDir = "ASC"
	}
	query = query.Order(sortBy + " " + orderDir)

	// Pagination
	// size == 0 = 全量拉取（用户裁定 2026-10-04）。
	if size > 0 {
		query = query.Offset(pageOffset(p)).Limit(size)
	}

	var tasks []storage.TaskModel
	if err := query.Find(&tasks).Error; err != nil {
		InternalError(c, "failed to list tasks: "+err.Error())
		return
	}

	result := make([]TaskResponse, len(tasks))
	for i, t := range tasks {
		result[i] = convertTaskToResponse(&t)
	}

	Success(c, pageBody(result, total, p, len(result)))
}

// Get gets a task by ID.
func (h *TaskHandler) Get(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing task id")
		return
	}

	var task storage.TaskModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "task not found")
			return
		}
		InternalError(c, "failed to get task: "+err.Error())
		return
	}

	// Include strategies in the single-task detail response
	Success(c, convertTaskToResponseWithDB(&task, h.db))
}

// Start starts a task.
func (h *TaskHandler) Start(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing task id")
		return
	}

	// 锁必须在**读行之前**拿到：读行在锁外的话，读到的状态与拿锁时的行
	// 状态可能不一致（另一个 Start/Stop/Delete 在中间动了它）。
	startMu.Lock()
	defer startMu.Unlock()

	var task storage.TaskModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "task not found")
			return
		}
		InternalError(c, "failed to get task: "+err.Error())
		return
	}

	// Check if task is already running. A DB status of "running"/"starting"
	// normally means the engine owns the task — but if the engine taskStore
	// no longer has it (the task finished or failed while the client was
	// disconnected / polling timed out, or the server restarted), the DB
	// record is stale. Instead of rejecting the start forever, reconcile the
	// DB status and fall through to the restart path below. Batch tasks are
	// always treated as already-running: they are auto-started on creation
	// and cannot be restarted (rejected below).
	if task.Status == "running" || task.Status == "starting" {
		if task.BatchConfig != "" || engineTaskStillRunning(h, &task) {
			BadRequest(c, "task is already running")
			return
		}
		// Stale DB status: no engine task exists. Repair the record so the
		// run appears in history: a recorded engine failure becomes
		// "failed", otherwise the task finished — mark "completed".
		h.failMu.Lock()
		var failMsgs []string
		for _, sid := range taskStrategyIDs(&task) {
			eid := fmt.Sprintf("%s-%s", task.ID, sid)
			if errMsg, ok := h.failedTasks[eid]; ok {
				failMsgs = append(failMsgs, fmt.Sprintf("%s: %s", eid, errMsg))
				delete(h.failedTasks, eid)
			}
		}
		if errMsg, ok := h.failedTasks[task.ID]; ok {
			failMsgs = append(failMsgs, fmt.Sprintf("%s: %s", task.ID, errMsg))
			delete(h.failedTasks, task.ID)
		}
		h.failMu.Unlock()

		if len(failMsgs) > 0 {
			task.Status = "failed"
			task.ErrorMessage = fmt.Sprintf("output error: %v", failMsgs)
		} else {
			task.Status = "completed"
		}
		now := currentTime()
		task.CompletedAt = &now
		// 指定列更新：task 是读出来的旧快照，整行 Save 会把这期间落库的
		// 实发统计一起写回旧值（与 Stop 同一个坑）。
		// 这里的入口状态是 running/starting 两种，故谓词用"未终态"。
		if !h.applyTaskCompletionWhere(task.ID, &task, "status NOT IN ?", terminalStatuses) {
			InternalError(c, "failed to reconcile task status before restart")
			return
		}
		log.Printf("task %s reconciled stale status -> %s before restart", task.ID, task.Status)
		h.maybeAutoRegisterPcapAsync(&task)
	}

	// Batch tasks are auto-started on creation and use BatchConfig instead of
	// StrategyIDs. Re-starting them is not supported — the engine task ID format
	// differs (plain taskID vs {taskID}-{strategyID}) and the batch spec is not
	// re-runnable. Return a clear error instead of failing later with the
	// misleading "corrupt strategy_ids" message.
	//
	// 位置在状态改写之前、且不写库：拒绝路径必须只读。此前这段在
	// Update("status","starting") / Progress=0 / ErrorMessage="" 之后，于是
	// 对一条**已经跑完**的 batch 任务调 start，会把 completed+progress=100
	// 改成 error+progress=0——流量明明发出去了，记录却判失败（客户端
	// 2026-11-23 报告问题 1）。
	if task.StrategyIDs == "" && task.BatchConfig != "" {
		BadRequest(c, "batch tasks are auto-started on creation and cannot be restarted")
		return
	}

	// Optimistic lock: atomically set status to prevent concurrent starts
	result := h.db.Model(&storage.TaskModel{}).
		Where("id = ? AND status = ?", id, task.Status).
		Update("status", "starting")
	if result.Error != nil {
		// 此前只看 RowsAffected：写库失败（比如磁盘满）也会被报成
		// "状态变了请重试"，把基础设施故障伪装成并发冲突。
		InternalError(c, "failed to mark task starting: "+result.Error.Error())
		return
	}
	if result.RowsAffected == 0 {
		BadRequest(c, "task status changed, please retry")
		return
	}
	task.Status = "starting"

	// Reset state for re-start
	task.Progress = 0
	task.ErrorMessage = ""
	task.CompletedAt = nil

	// Validate all strategies exist and convert to engine tasks
	var strategyIDs []string
	if err := json.Unmarshal([]byte(task.StrategyIDs), &strategyIDs); err != nil {
		task.Status = "error"
		task.ErrorMessage = "corrupt strategy_ids in task record"
		if _, merr := h.markTaskError(&task, "status = ?", "starting"); merr != nil {
			InternalError(c, task.ErrorMessage+" (and the error state could not be persisted: "+merr.Error()+")")
			return
		}
		InternalError(c, task.ErrorMessage)
		return
	}

	// Resolve port interface name if needed
	var portGroupIface string
	if task.OutputType == "port_group" || task.OutputType == "both" {
		var outputConfig OutputConfigRequest
		json.Unmarshal([]byte(task.OutputConfig), &outputConfig)
		if outputConfig.PortGroupID != "" {
			iface, err := h.resolvePortGroupIface(outputConfig.PortGroupID)
			if err == nil {
				portGroupIface = iface
			}
		}
	}

	// Load all strategies first for conflict validation
	var loadedStrategies []storage.StrategyModel
	for _, strategyID := range strategyIDs {
		var strategy storage.StrategyModel
		if err := h.db.Where("id = ? AND user_id = ?", strategyID, userID).First(&strategy).Error; err != nil {
			if err == gorm.ErrRecordNotFound {
				task.Status = "error"
				task.ErrorMessage = fmt.Sprintf("strategy %s not found", strategyID)
				if _, merr := h.markTaskError(&task, "status = ?", "starting"); merr != nil {
					InternalError(c, task.ErrorMessage+" (and the error state could not be persisted: "+merr.Error()+")")
					return
				}
				BadRequest(c, task.ErrorMessage)
				return
			}
			InternalError(c, "failed to validate strategy: "+err.Error())
			return
		}
		loadedStrategies = append(loadedStrategies, strategy)
	}
	// Replay+bps conflict via the unified schema entry (same message as
	// Create). Task shape was validated at creation; only the conflict is
	// re-checked here against the loaded strategies. toAnyJSON decodes the
	// stored output blob verbatim (no empty-string dropping: stored JSON has
	// no gin zero-fill), and the flow_control blob is passed through raw so
	// an absent ceiling stays absent.
	var taskFC map[string]interface{}
	if task.FlowControl != "" {
		var fc FlowControlRequest
		json.Unmarshal([]byte(task.FlowControl), &fc)
		taskFC = map[string]interface{}{"type": fc.Type, "value": fc.Value}
	}
	conflictDoc := map[string]interface{}{
		"name": task.Name, "strategy_ids": toAnySlice(strategyIDs),
		"output_type": task.OutputType, "output_config": toAnyJSON(task.OutputConfig),
	}
	if taskFC != nil {
		conflictDoc["flow_control"] = taskFC
	}
	if errs := schema.ValidateTaskCreate(conflictDoc, toStrategyViews(loadedStrategies)); len(errs) > 0 {
		for _, e := range errs {
			if containsStr(e.Message, "cannot combine with bps") {
				task.Status = "error"
				task.ErrorMessage = e.Message
				if _, merr := h.markTaskError(&task, "status = ?", "starting"); merr != nil {
					InternalError(c, task.ErrorMessage+" (and the error state could not be persisted: "+merr.Error()+")")
					return
				}
				BadRequest(c, task.ErrorMessage)
				return
			}
		}
	}

	var coreTasks []*core.Task
	var failedIDs []string
	for _, strategy := range loadedStrategies {
		coreTask, err := core.StrategyModelToTask(&task, &strategy, portGroupIface)
		if err != nil {
			log.Printf("error converting strategy %s: %v", strategy.ID, err)
			failedIDs = append(failedIDs, strategy.ID)
			continue
		}
		// P2c 层链驱动生成: strategy config with a "layers" key carries the raw
		// layers JSON on the task; the engine builds a per-task ChainPlanner
		// from it at SubmitTask (layers.BuildLayersPlanner, wired in main.go).
		// Parse failures surface here as a strategy failure — the strategy was
		// already validated at creation time, so this only fires for a config
		// edited out-of-band, but it must fail the task loudly, never generate
		// an empty flow. Replay strategies are skipped: their Config is a
		// ReplaySpec, not a layer chain, and their tasks carry no protocol.
		if strategy.Mode != "replay" {
			var configMap map[string]json.RawMessage
			if err := json.Unmarshal([]byte(strategy.Config), &configMap); err != nil {
				log.Printf("error parsing config for strategy %s: %v", strategy.ID, err)
				failedIDs = append(failedIDs, strategy.ID)
				continue
			}
			if rawLayers, ok := configMap["layers"]; ok {
				coreTask.Layers = rawLayers
			}
		}
		coreTasks = append(coreTasks, coreTask)
	}

	if len(coreTasks) == 0 {
		task.Status = "error"
		task.ErrorMessage = "no valid strategies to execute"
		if _, merr := h.markTaskError(&task, "status = ?", "starting"); merr != nil {
			InternalError(c, task.ErrorMessage+" (and the error state could not be persisted: "+merr.Error()+")")
			return
		}
		BadRequest(c, task.ErrorMessage)
		return
	}

	// Validate and resolve output paths before proceeding. pcap resolves the
	// requested path; both resolves (or generates — task-id derived, so a
	// re-created task never collides) the shadow path and persists it into
	// output_config: the auto-register hook and the response surface read it
	// from there. Generated here (Start), NOT at Create — Create dedups by
	// the full output_config string, so filling a path there would break
	// idempotent resubmission.
	if task.OutputType == "pcap" || task.OutputType == "both" {
		var outputConfig OutputConfigRequest
		json.Unmarshal([]byte(task.OutputConfig), &outputConfig)
		if task.OutputType == "both" && outputConfig.PcapPath == "" {
			outputConfig.PcapPath = "pcap/" + task.ID + "_shadow.pcap"
		}
		resolved, err := resolvePcapPath(outputConfig.PcapPath)
		if err != nil {
			task.Status = "error"
			task.ErrorMessage = err.Error()
			if _, merr := h.markTaskError(&task, "status = ?", "starting"); merr != nil {
				InternalError(c, task.ErrorMessage+" (and the error state could not be persisted: "+merr.Error()+")")
				return
			}
			BadRequest(c, task.ErrorMessage)
			return
		}
		// Update task with resolved path
		outputConfig.PcapPath = resolved
		resolvedJSON, _ := json.Marshal(&outputConfig)
		task.OutputConfig = string(resolvedJSON)
		// 此前 Error 被丢弃：落库失败时任务照常跑，但完成后的 auto-register
		// 读 DB 里的 output_config（旧值）→ 注册错路径的文件或 404。必须失败。
		ocRes := h.db.Model(&storage.TaskModel{}).Where("id = ?", task.ID).
			Update("output_config", task.OutputConfig)
		if ocRes.Error != nil || ocRes.RowsAffected == 0 {
			// Error：DB 故障；RowsAffected=0：行不在了（防御纵深）——
			// 两种情况都意味着 auto-register 会读到旧路径，任务必须失败。
			reason := "DB error: " + ocRes.Error.Error()
			if ocRes.Error == nil {
				reason = "task row no longer exists"
			}
			task.Status = "error"
			task.ErrorMessage = "failed to persist resolved output path (" + reason + ")"
			if _, merr := h.markTaskError(&task, "status = ?", "starting"); merr != nil {
				InternalError(c, task.ErrorMessage+" (and the error state could not be persisted: "+merr.Error()+")")
				return
			}
			InternalError(c, task.ErrorMessage)
			return
		}

		// Update coreTasks with resolved path
		for i := range coreTasks {
			coreTasks[i].PcapFile = resolved
		}
	}

	// Detect dual-port replay: an explicit interface2 in the output config,
	// OR any loaded replay strategy whose Config has direction="dual".
	// Mirrors CreateBatch's dual-port detection (§16.11). When set, each
	// engine task gets a DualWriter pair: c2s -> primary, s2c -> secondary.
	var outputConfigForDual OutputConfigRequest
	json.Unmarshal([]byte(task.OutputConfig), &outputConfigForDual)
	dualPort := outputConfigForDual.Interface2 != ""
	if !dualPort {
		for _, s := range loadedStrategies {
			if s.Mode != "replay" {
				continue
			}
			var rs struct {
				Direction string `json:"direction"`
			}
			if json.Unmarshal([]byte(s.Config), &rs) == nil && rs.Direction == "dual" {
				dualPort = true
				break
			}
		}
	}
	if dualPort && task.OutputType == "both" {
		task.Status = "error"
		task.ErrorMessage = errBothDual
		if _, merr := h.markTaskError(&task, "status = ?", "starting"); merr != nil {
			InternalError(c, task.ErrorMessage+" (and the error state could not be persisted: "+merr.Error()+")")
			return
		}
		BadRequest(c, task.ErrorMessage)
		return
	}
	if dualPort && task.OutputType == "port_group" && outputConfigForDual.Interface2 == "" {
		task.Status = "error"
		task.ErrorMessage = "dual-port replay requires a second interface (interface2 in output_config)"
		if _, merr := h.markTaskError(&task, "status = ?", "starting"); merr != nil {
			InternalError(c, task.ErrorMessage+" (and the error state could not be persisted: "+merr.Error()+")")
			return
		}
		BadRequest(c, task.ErrorMessage)
		return
	}

	// Raise NIC MTU if engine.min_mtu is configured. Done after dual-port
	// validation (so we know interface2 is valid) but BEFORE creating output
	// writers / SubmitTask. On failure the task is marked failed -- the
	// operator must either run as root or lower engine.min_mtu.
	if _, err := h.ensureTaskMTU(&task, outputConfigForDual.Interface2); err != nil {
		task.Status = "error"
		task.ErrorMessage = err.Error()
		if _, merr := h.markTaskError(&task, "status = ?", "starting"); merr != nil {
			InternalError(c, task.ErrorMessage+" (and the error state could not be persisted: "+merr.Error()+")")
			return
		}
		BadRequest(c, task.ErrorMessage)
		return
	}

	// Set up output writers BEFORE submitting engine tasks to avoid race.
	// D-ENG-1: 多策略任务会为同一 resolved 路径建多个 writer——各自 os.Create
	// 会截断前者并交错覆盖(产物损坏)。路径键控注册表让同路径只开一个
	// SharedPCAPWriter,每 ct 持一个引用计数适配器,末次 Release 才真关。
	// 覆盖全部 pcap 落盘点:主路径、dual 的 .s2c、both 的影子。NIC 侧不共享
	// (每 fd 独立注入无损坏面)。
	var writerErrors []string
	sharedPCAPs := map[string]*output.SharedPCAPWriter{}
	openShared := func(path string, maxBytes int64) (*output.SharedPCAPWriter, error) {
		if s, ok := sharedPCAPs[path]; ok {
			return s, nil
		}
		s, err := newSharedPCAPWriterFn(path, maxBytes)
		if err != nil {
			return nil, err
		}
		sharedPCAPs[path] = s
		return s, nil
	}
	for _, ct := range coreTasks {
		var writer core.PacketWriter
		var err error

		if ct.OutputMode == "interface" && ct.Interface != "" {
			if task.OutputType == "both" && ct.PcapFile != "" {
				// both: NIC primary + best-effort shadow pcap. Shadow path is
				// the task-level resolved path, shared across strategies via
				// the registry (D-ENG-1). L1: sink 引用成功后才组装 adapter,
				// 半失败 Release 抵消,不留注册表残项。
				sink, serr := openShared(ct.PcapFile, defaultShadowPcapMaxBytes)
				if serr != nil {
					err = serr
				} else {
					sink.AddRef()
					adapter := &sharedPcapAdapter{s: sink}
					var w2 core.PacketWriter
					w2, err = newShadowPacketWriterWithSink(ct.Interface, adapter, func(msg string) {
						h.noteShadowIssue(task.ID, msg)
					})
					if err != nil {
						adapter.Close() // 抵消 AddRef
						if adapter.final {
							delete(sharedPCAPs, ct.PcapFile) // 真关后的缓存句柄不得被后续 ct 复用
						}
					} else {
						writer = w2
					}
				}
			} else {
				writer, err = newInterfacePacketWriter(ct.Interface)
			}
		} else if ct.OutputMode == "interface" {
			// Interface mode with no resolved iface would previously fall
			// through to the pcap branch (empty → nil writer → silent
			// zero-output). Fail loudly instead.
			err = fmt.Errorf("interface output but no interface resolved (port group missing?)")
		} else if ct.PcapFile != "" {
			sink, serr := openShared(ct.PcapFile, 0)
			if serr != nil {
				err = serr
			} else {
				sink.AddRef()
				writer = &sharedPcapAdapter{s: sink}
			}
		}

		if err != nil {
			log.Printf("failed to create output writer for task %s: %v", ct.ID, err)
			writerErrors = append(writerErrors, fmt.Sprintf("%s: %v", ct.ID, err))
			continue
		}

		if dualPort {
			// Create the secondary writer for s2c traffic. Interface mode uses
			// interface2; pcap mode appends ".s2c" to the path. On failure we
			// close the primary writer and record the error so the task fails
			// rather than silently degrading to single-port. D-ENG-1: .s2c 同
			// 样走共享注册表(多策略 dual 的同损坏面)。
			var writer2 core.PacketWriter
			if ct.OutputMode == "interface" {
				writer2, err = newInterfacePacketWriter(outputConfigForDual.Interface2)
			} else if ct.PcapFile != "" {
				sink2, serr := openShared(ct.PcapFile+".s2c", 0)
				if serr != nil {
					err = serr
				} else {
					sink2.AddRef()
					writer2 = &sharedPcapAdapter{s: sink2}
				}
			}
			if err != nil {
				if writer != nil {
					writer.Close()
					// R1 (rev-d1): if this Close was the final Release, the
					// registry now holds a closed writer under the main path —
					// a later ct with the same path would cache-hit it and
					// fail every write ("pcap writer closed"). Evict on
					// final, symmetric with the shadow branch above.
					if a, ok := writer.(*sharedPcapAdapter); ok && a.final && ct.PcapFile != "" {
						delete(sharedPCAPs, ct.PcapFile)
					}
				}
				log.Printf("failed to create second output writer for task %s: %v", ct.ID, err)
				writerErrors = append(writerErrors, fmt.Sprintf("%s: %v", ct.ID, err))
				continue
			}
			ct.Interface2 = outputConfigForDual.Interface2
			h.engine.RegisterDualWriter(ct.ID, writer, writer2)
		} else if writer != nil {
			h.engine.RegisterOutputWriter(ct.ID, writer)
		}
	}

	// If all output writers failed, mark task as error before submitting
	if len(writerErrors) > 0 && len(writerErrors) == len(coreTasks) {
		task.Status = "error"
		task.ErrorMessage = fmt.Sprintf("failed to create output writers: %v", writerErrors)
		task.Progress = 0
		if written, merr := h.markTaskError(&task, "status = ?", "starting"); merr != nil {
			InternalError(c, task.ErrorMessage+" (and the error state could not be persisted: "+merr.Error()+")")
			return
		} else if !written {
			// 行已被接管/删除：不再宣称错误细节，给状态族统一文案。
			BadRequest(c, "task status changed, please retry")
			return
		}
		BadRequest(c, task.ErrorMessage)
		return
	} else if len(writerErrors) > 0 {
		log.Printf("warning: %d/%d output writers failed: %v", len(writerErrors), len(coreTasks), writerErrors)
	}

	// Mark the task running BEFORE submitting engine tasks. A config worker
	// can consume the task and fail it (planning/validation error) the moment
	// SubmitTask returns -- onEngineTaskComplete then reads the DB record and
	// must see "running" (not "starting") or it bails and the failure is
	// clobbered by the late "running" save below, wedging the task in
	// "running" forever.
	task.Status = "running"
	now := currentTime()
	task.StartedAt = &now
	// 指定列更新，不整行 Save：task 是请求开始时读的快照，整行写回会把这
	// 期间落库的统计列打回旧值。但 "Reset state for re-start" 设的三项
	// （progress / error_message / completed_at）必须显式写进去——只写
	// status+started_at 会留下上一轮的 100% 和 completed_at，客户端立刻
	// 轮询就看见"状态 running、进度 100、已完成时间还在"。
	// 谓词 starting + RowsAffected 检查：行在此窗口被删/接管（理论上锁族
	// 已挡，防御纵深）时 RowsAffected=0，放弃提交——否则引擎会跑起一个
	// DB 里已不存在的幽灵任务。
	res := h.db.Model(&storage.TaskModel{}).Where("id = ? AND status = ?", task.ID, "starting").
		Updates(map[string]interface{}{
			"status":        "running",
			"started_at":    now,
			"progress":      0,
			"error_message": "",
			"completed_at":  nil,
		})
	if res.Error != nil || res.RowsAffected == 0 {
		// 必须拦住：此前这里失败也照样提交引擎任务并回 200，库里却停在
		// 上一轮的 completed/100——引擎在跑，界面显示"已完成"。
		// writer 已经全部注册进引擎了，这条出口必须把它们连同 flow-control
		// 一起收回，否则任务没起来、句柄却永久留在引擎里。
		for _, ct := range coreTasks {
			h.engine.UnregisterOutputWriter(ct.ID)
			h.engine.UnregisterDualWriter(ct.ID)
		}
		h.engine.CleanupTaskFlowControl(id)
		if res.Error != nil {
			task.Status = "error"
			task.ErrorMessage = "failed to mark task running: " + res.Error.Error()
			if _, merr := h.markTaskError(&task, "status = ?", "starting"); merr != nil {
				InternalError(c, task.ErrorMessage+" (and the error state could not be persisted: "+merr.Error()+")")
				return
			}
			InternalError(c, task.ErrorMessage)
			return
		}
		// RowsAffected=0：行已不在 starting——被接管或删除。
		BadRequest(c, "task status changed, please retry")
		return
	}

	if runningWriteHook != nil {
		runningWriteHook()
	}

	// Submit all engine tasks
	var submittedIDs []string
	var lastFailureReason string
	for _, ct := range coreTasks {
		// Skip tasks whose output writer failed
		skip := false
		for _, we := range writerErrors {
			if len(we) >= len(ct.ID) && we[:len(ct.ID)] == ct.ID {
				skip = true
				break
			}
		}
		if skip {
			// 这条策略的 writer 没开成：它从未注册进引擎，这里无需注销
			// （writer 创建失败的 ct 在上一循环就 continue 了）。
			continue
		}

		if err := h.engine.SubmitTask(*ct); err != nil {
			log.Printf("error submitting engine task %s: %v", ct.ID, err)
			h.engine.UnregisterOutputWriter(ct.ID)
			h.engine.UnregisterDualWriter(ct.ID)
			failedIDs = append(failedIDs, ct.ID)
			lastFailureReason = err.Error()
			continue
		}
		submittedIDs = append(submittedIDs, ct.ID)
	}

	if startSubmitHook != nil {
		startSubmitHook()
	}

	if len(submittedIDs) == 0 {
		task.Status = "error"
		task.ErrorMessage = "failed to start any strategy"
		if len(failedIDs) > 0 {
			// Include the underlying per-strategy failure reason (e.g.
			// "invalid spec: mss 100 too small") so the caller can see why
			// the start failed instead of a generic message.
			task.ErrorMessage += fmt.Sprintf(" (last failure: %s)", lastFailureReason)
		}
		// 谓词 running：此出口在 running 写之后、SubmitTask 之后——行已不是
		// starting。写成 starting 是本修复第一版犯的错（layer 测试抓出）。
		if written, merr := h.markTaskError(&task, "status = ?", "running"); merr != nil {
			InternalError(c, task.ErrorMessage+" (and the error state could not be persisted: "+merr.Error()+")")
		} else if !written {
			BadRequest(c, "task status changed, please retry")
		} else {
			InternalError(c, task.ErrorMessage)
		}
		// Clean up flow-control state created during the failed SubmitTask attempts
		// (parent rate bucket + shared flow counter). Without this, a task that
		// never successfully starts leaks entries in the engine's maps.
		h.engine.CleanupTaskFlowControl(id)
		h.releaseProgressBookkeeping(id)
		h.releaseTaskFailures(id)
		return
	}

	// Reserve ports for port_group output
	if task.OutputType == "port_group" || task.OutputType == "both" {
		var outputConfig OutputConfigRequest
		json.Unmarshal([]byte(task.OutputConfig), &outputConfig)

		var portGroup storage.PortGroupModel
		if err := h.db.Where("id = ?", outputConfig.PortGroupID).First(&portGroup).Error; err == nil {
			var portsConfig []map[string]interface{}
			json.Unmarshal([]byte(portGroup.PortsConfig), &portsConfig)

			for _, portConfig := range portsConfig {
				if iface, ok := portConfig["interface"].(string); ok {
					h.db.Model(&storage.PortModel{}).
						Where("name = ? AND (status = ? OR current_task_id = ?)", iface, "idle", "").
						Updates(map[string]interface{}{
							"status":          "using",
							"current_task_id": id,
						})
				}
			}
		}
	}

	SuccessWithMessage(c, "task started", map[string]interface{}{
		"engine_task_ids": submittedIDs,
	})
}

// taskStrategyIDs parses the StrategyIDs JSON column. A corrupt value returns
// an empty slice; callers treat that as "no engine tasks" for stale checks.
func taskStrategyIDs(task *storage.TaskModel) []string {
	var ids []string
	json.Unmarshal([]byte(task.StrategyIDs), &ids)
	return ids
}

// engineTaskStillRunning reports whether any engine task for the task still
// exists in the engine taskStore. Engine task IDs are "{taskID}-{strategyID}"
// (batch tasks use plain taskID but are handled separately). If the engine
// has no record for any of them, the DB status is stale.
func engineTaskStillRunning(h *TaskHandler, task *storage.TaskModel) bool {
	for _, sid := range taskStrategyIDs(task) {
		if _, err := h.engine.GetTaskStatus(fmt.Sprintf("%s-%s", task.ID, sid)); err == nil {
			return true
		}
	}
	return false
}

// Stop stops a task.
func (h *TaskHandler) Stop(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing task id")
		return
	}

	// 与 Start 互斥：Start 写完 running 到 SubmitTask 之间有缝隙，Stop 若
	// 在缝隙里进来，会对"引擎里还不存在"的任务调 StopTask 并写 stopped，
	// Start 随后照常提交——引擎在跑、DB 是 stopped 的幽灵任务。
	startMu.Lock()
	defer startMu.Unlock()

	var task storage.TaskModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "task not found")
			return
		}
		InternalError(c, "failed to get task: "+err.Error())
		return
	}

	// Check if task is running
	if task.Status != "running" {
		BadRequest(c, "task is not running")
		return
	}

	// Update DB status first for consistency. 指定列更新而非整行 Save：task
	// 是上面的旧快照，整行写回会把这期间 onEngineProgress 刚落库的实发统计
	// (packets_sent/bytes_sent/flows_count/progress) 打回旧值——用户点停止
	// 后界面从"已发 500 包"退回 0。
	now := currentTime()
	if stopSnapshotHook != nil {
		stopSnapshotHook()
	}
	stopRes := h.db.Model(&storage.TaskModel{}).Where("id = ? AND status = ?", id, "running").
		Updates(map[string]interface{}{"status": "stopped", "completed_at": now})
	if stopRes.Error != nil {
		InternalError(c, "failed to stop task: "+stopRes.Error.Error())
		return
	}
	if stopRes.RowsAffected == 0 {
		// 行已不在 running（防御纵深——锁族下不可达）：状态族统一文案。
		BadRequest(c, "task status changed, please retry")
		return
	}
	task.Status = "stopped"
	task.CompletedAt = &now

	// stopped 已落库，终态不可逆——此后**每条**出口都要释放记账。用 defer
	// 而不是在每条 return 前手写：下面"strategy_ids 损坏"那条提前返回曾
	// 跳过全部清理，让一个停止过的任务的记账条目永久留在 handler 里。
	defer h.releaseProgressBookkeeping(id)
	defer h.releaseTaskFailures(id)

	// Release port group ports
	h.releasePortGroupPorts(&task)

	// Batch tasks: engine task ID == task ID (no strategy suffix), and
	// StrategyIDs is empty by design. Stop the single engine task directly
	// and clean up both OutputWriter and DualWriter (whichever was registered).
	if task.BatchConfig != "" {
		h.engine.UnregisterOutputWriter(id)
		h.engine.UnregisterDualWriter(id)
		if err := h.engine.StopTask(id); err != nil {
			log.Printf("error stopping batch engine task %s: %v", id, err)
		}
		h.engine.CleanupTaskFlowControl(id)
		SuccessWithMessage(c, "task stopped", map[string]interface{}{
			"stopped_engine_tasks": []string{id},
		})
		return
	}

	// Stop engine tasks and unregister output writers (best-effort after DB update)
	var strategyIDs []string
	if err := json.Unmarshal([]byte(task.StrategyIDs), &strategyIDs); err != nil {
		log.Printf("corrupt strategy_ids for task %s: %v", id, err)
		SuccessWithMessage(c, "task stopped (engine cleanup may be incomplete)", nil)
		return
	}
	var stopped []string
	for _, strategyID := range strategyIDs {
		engineTaskID := fmt.Sprintf("%s-%s", id, strategyID)
		h.engine.UnregisterOutputWriter(engineTaskID)
		h.engine.UnregisterDualWriter(engineTaskID)
		if err := h.engine.StopTask(engineTaskID); err != nil {
			log.Printf("error stopping engine task %s: %v", engineTaskID, err)
			continue
		}
		stopped = append(stopped, engineTaskID)
	}

	// Clean up task-level flow control state (parent bucket + flow counter).
	h.engine.CleanupTaskFlowControl(id)

	SuccessWithMessage(c, "task stopped", map[string]interface{}{
		"stopped_engine_tasks": stopped,
	})
}

// Delete deletes a task.
func (h *TaskHandler) Delete(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	id := c.Param("id")
	if id == "" {
		BadRequest(c, "missing task id")
		return
	}

	startMu.Lock()
	defer startMu.Unlock()

	var task storage.TaskModel
	if err := h.db.Where("id = ? AND user_id = ?", id, userID).First(&task).Error; err != nil {
		if err == gorm.ErrRecordNotFound {
			NotFound(c, "task not found")
			return
		}
		InternalError(c, "failed to get task: "+err.Error())
		return
	}

	// running 与 starting 都不可删：删掉 starting 的行，Start 恢复后会照常
	// 提交引擎任务——引擎在跑、DB 无行的幽灵任务，永远停不掉。
	if task.Status == "running" {
		BadRequest(c, "cannot delete running task, stop it first")
		return
	}
	if task.Status == "starting" {
		// starting 的行删掉会造幽灵（Start 恢复后照常提交）——409 冲突。
		Conflict(c, "cannot delete a task while it is starting")
		return
	}

	// Delete task
	if err := h.db.Delete(&task).Error; err != nil {
		InternalError(c, "failed to delete task: "+err.Error())
		return
	}
	// 行已删：没有任何后续回调会来释放记账，必须在这里清掉。
	h.releaseProgressBookkeeping(id)
	h.releaseTaskFailures(id)

	SuccessWithMessage(c, "task deleted", map[string]interface{}{"id": id, "deleted": true})
}

// History returns completed task history.
func (h *TaskHandler) History(c *gin.Context) {
	userID := auth.GetUserID(c)
	if userID == "" {
		Unauthorized(c, "user not authenticated")
		return
	}

	// Parse query parameters
	p := parsePageParams(c, 20, 100)
	size := p.Size

	// Build query
	query := h.db.Model(&storage.TaskModel{}).Where("user_id = ? AND status IN ?", userID, []string{"completed", "failed", "stopped", "error"})

	// Time range filter
	if startTimeStr := c.Query("start_time"); startTimeStr != "" {
		if startTime, err := strconv.ParseInt(startTimeStr, 10, 64); err == nil {
			query = query.Where("created_at >= ?", time.Unix(startTime, 0))
		}
	}
	if endTimeStr := c.Query("end_time"); endTimeStr != "" {
		if endTime, err := strconv.ParseInt(endTimeStr, 10, 64); err == nil {
			query = query.Where("created_at <= ?", time.Unix(endTime, 0))
		}
	}

	// Status filter
	if statusFilter := c.Query("status"); statusFilter != "" {
		query = query.Where("status = ?", statusFilter)
	}

	// Count total
	var total int64
	// D-SCHEMA-1（BUG-11）：Count 错误不得静默——吞掉后 total=0 造成"任务
	// 全部消失"假象（SQLite busy 排队期间客户端误判数据丢失）。
	if err := query.Count(&total).Error; err != nil {
		InternalError(c, "count tasks failed: "+err.Error())
		return
	}

	// Sorting
	sortBy := c.DefaultQuery("sort_by", "created_at")
	sortOrder := c.DefaultQuery("sort_order", "descending")
	allowedSortColumns := map[string]bool{"created_at": true, "updated_at": true, "name": true, "status": true, "progress": true}
	if !allowedSortColumns[sortBy] {
		sortBy = "created_at"
	}
	orderDir := "DESC"
	if sortOrder == "ascending" {
		orderDir = "ASC"
	}
	query = query.Order(sortBy + " " + orderDir)

	// Pagination
	// size == 0 = 全量拉取（用户裁定 2026-10-04）。
	if size > 0 {
		query = query.Offset(pageOffset(p)).Limit(size)
	}

	var tasks []storage.TaskModel
	if err := query.Find(&tasks).Error; err != nil {
		InternalError(c, "failed to list history: "+err.Error())
		return
	}

	result := make([]TaskResponse, len(tasks))
	for i, t := range tasks {
		result[i] = convertTaskToResponse(&t)
	}

	Success(c, pageBody(result, total, p, len(result)))
}

// convertTaskToResponse converts a TaskModel to TaskResponse.
func convertTaskToResponse(t *storage.TaskModel) TaskResponse {
	var strategyIDs []string
	json.Unmarshal([]byte(t.StrategyIDs), &strategyIDs)

	var outputConfig OutputConfigRequest
	json.Unmarshal([]byte(t.OutputConfig), &outputConfig)

	var flowControl *FlowControlRequest
	if t.FlowControl != "" {
		flowControl = &FlowControlRequest{}
		json.Unmarshal([]byte(t.FlowControl), flowControl)
	}

	response := TaskResponse{
		ID:           t.ID,
		UserID:       t.UserID,
		Name:         t.Name,
		Protocol:     t.Protocol,
		StrategyIDs:  strategyIDs,
		OutputType:   t.OutputType,
		OutputConfig: &outputConfig,
		FlowControl:  flowControl,
		Status:       t.Status,
		ErrorMessage: t.ErrorMessage,
		Progress:     t.Progress,
		CreatedAt:    t.CreatedAt.Unix(),
		UpdatedAt:    t.UpdatedAt.Unix(),
	}
	// 实发统计：引擎 progress 回调回填（>=100 强制落库）。未运行的任务
	// 全零 → 保持 nil，不为没跑过的任务伪造 stats。
	if t.PacketsSent > 0 || t.BytesSent > 0 || t.FlowsCount > 0 {
		response.Stats = &TaskStatsResponse{
			PacketsSent: t.PacketsSent,
			BytesSent:   t.BytesSent,
			FlowsCount:  t.FlowsCount,
		}
	}
	if t.OutputType == "pcap" || t.OutputType == "both" {
		response.DownloadURL = "/downloads/tasks/" + t.ID + "/pcap"
		response.PcapAssetID = t.PcapAssetID
		if t.PcapAssetNote != "" {
			response.PcapAssetNote = t.PcapAssetNote
		} else if t.PcapAssetID != "" {
			// 已注册：响应层补默认提示语（DB 只存跳过/失败原因），提醒
			// LLM 该 pcap 可以直接做报文查看/分析/下载。
			response.PcapAssetNote = "pcap auto-registered into the asset library (id " + t.PcapAssetID +
				") — inspect and analyze it via flowb_manage_pcaps: list_flows / list_packets / get_packet / " +
				"extract / get_packet_payload; download via its download action"
		}
		response.ShadowNote = t.ShadowNote
	}

	if t.StartedAt != nil {
		startedAt := t.StartedAt.Unix()
		response.StartedAt = &startedAt
	}

	if t.CompletedAt != nil {
		completedAt := t.CompletedAt.Unix()
		response.CompletedAt = &completedAt
	}

	return response
}

// convertTaskToResponseWithDB converts a TaskModel to TaskResponse with DB access for strategies.
func convertTaskToResponseWithDB(t *storage.TaskModel, db *storage.DB) TaskResponse {
	resp := convertTaskToResponse(t)

	// Populate strategies
	var strategyIDs []string
	json.Unmarshal([]byte(t.StrategyIDs), &strategyIDs)

	if len(strategyIDs) > 0 {
		var strategies []storage.StrategyModel
		db.Where("id IN ?", strategyIDs).Find(&strategies)

		stratMap := make(map[string]storage.StrategyModel)
		for _, s := range strategies {
			stratMap[s.ID] = s
		}

		for _, sid := range strategyIDs {
			if s, ok := stratMap[sid]; ok {
				var fc *FlowControlRequest
				if s.FlowControl != "" {
					fc = &FlowControlRequest{}
					json.Unmarshal([]byte(s.FlowControl), fc)
				}
				resp.Strategies = append(resp.Strategies, StrategyBrief{
					ID:          s.ID,
					Name:        s.Name,
					Mode:        s.Mode,
					Protocol:    s.Protocol,
					FlowControl: fc,
				})
			}
		}
	}

	return resp
}

// calculateTaskHash calculates a hash for task configuration.
func calculateTaskHash(strategyIDs []string, outputConfig string) string {
	data := ""
	for _, id := range strategyIDs {
		data += id
	}
	data += outputConfig
	hash := sha256.Sum256([]byte(data))
	return hex.EncodeToString(hash[:])
}

// validateReplayBPSConflict is retired: the R-F2 invariant (no replay
// strategy with original/multiplier speed under a bps task ceiling) now
// lives in schema.ValidateTaskCreate, which both Create and Start call.
// Kept (unexported, no live callers) so the documented invariant has a
// stable anchor; delete once replay+bps coverage fully migrates to the
// schema package tests.
func validateReplayBPSConflict(strategies []storage.StrategyModel, taskFC *FlowControlRequest) error {
	if taskFC == nil || taskFC.Type != "bps" {
		return nil
	}
	for _, s := range strategies {
		if s.Mode == "replay" {
			var rs struct {
				Speed struct {
					Mode string `json:"mode"`
				} `json:"speed"`
			}
			if json.Unmarshal([]byte(s.Config), &rs) == nil && (rs.Speed.Mode == "original" || rs.Speed.Mode == "multiplier") {
				return fmt.Errorf("replay strategy %q has %s speed limit, cannot combine with bps task-level flow control", s.Name, rs.Speed.Mode)
			}
		}
	}
	return nil
}

// currentTime returns current time (helper for testing).
func currentTime() time.Time {
	return time.Now()
}

// resolvePcapPath validates and resolves a PCAP path.
// Relative paths are prepended with "pcap/" directory.
// Parent directories are auto-created if they don't exist.
func resolvePcapPath(path string) (string, error) {
	if path == "" {
		return "", fmt.Errorf("pcap_path is required")
	}
	// Reject Windows-style absolute paths
	if len(path) >= 2 && path[1] == ':' && (path[0] >= 'A' && path[0] <= 'Z' || path[0] >= 'a' && path[0] <= 'z') {
		return "", fmt.Errorf("invalid pcap_path: Windows-style path \"%s\" is not supported on this system", path)
	}
	// Reject UNC paths
	if len(path) >= 2 && path[0] == '\\' && path[1] == '\\' {
		return "", fmt.Errorf("invalid pcap_path: UNC path \"%s\" is not supported on this system", path)
	}
	// Relative paths go under pcap/ directory
	if !filepath.IsAbs(path) && !strings.HasPrefix(path, "pcap/") && !strings.HasPrefix(path, "pcap\\") {
		path = filepath.Join("pcap", path)
	}
	// Auto-create parent directory
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("failed to create directory \"%s\": %w", dir, err)
	}
	return path, nil
}

// pcapSink is the base a pcapPacketWriter delegates to: *output.PCAPWriter
// directly (single-consumer paths) or a shared adapter (D-ENG-1 multi-
// strategy paths). Method names match PCAPWriter so both are drop-in.
// Final reports whether THIS consumer's Close actually finalized the file
// (last Release) — the both-mode truncation note fires only then, so N
// strategies sharing one shadow produce exactly one note (M2).
type pcapSink interface {
	Write([][]byte) error
	WriteTimed([]output.TimedPacket) error
	Truncated() bool
	Close() error
	Final() bool
}

// pcapPacketWriter adapts a pcapSink to core.PacketWriter/TimedWriter.
type pcapPacketWriter struct {
	w pcapSink
}

func (pw *pcapPacketWriter) WritePackets(packets [][]byte) error {
	return pw.w.Write(packets)
}

// WriteTimedPackets implements core.TimedWriter so the pcap output uses the
// scheduled send timestamp (§12) instead of time.Now(). The OutputWorker
// prefers this path over WritePackets when present.
func (pw *pcapPacketWriter) WriteTimedPackets(packets []core.PacketOutput) error {
	tp := make([]output.TimedPacket, len(packets))
	for i, p := range packets {
		tp[i] = output.TimedPacket{Data: p.Data, Timestamp: p.Timestamp}
	}
	return pw.w.WriteTimed(tp)
}

func (pw *pcapPacketWriter) Close() error {
	return pw.w.Close()
}

// Truncated exposes the shadow writer's cap probe (shadowSink).
func (pw *pcapPacketWriter) Truncated() bool {
	return pw.w.Truncated()
}

// Final: a direct pcapPacketWriter owns its file as the sole consumer.
func (pw *pcapPacketWriter) Final() bool { return true }

// interfacePacketWriter adapts output.InterfaceWriter to core.PacketWriter.
type interfacePacketWriter struct {
	w *output.InterfaceWriter
}

func (iw *interfacePacketWriter) WritePackets(packets [][]byte) error {
	return iw.w.Write(packets)
}

func (iw *interfacePacketWriter) Close() error {
	return iw.w.Close()
}

func newPcapPacketWriter(path string) (core.PacketWriter, error) {
	w, err := output.NewPCAPWriter(path)
	if err != nil {
		return nil, err
	}
	return &pcapPacketWriter{w: w}, nil
}

// sharedPcapAdapter is one consumer's handle on a SharedPCAPWriter (D-ENG-1).
// Each strategy of a multi-strategy task holds its own adapter (engine
// unregisters close one adapter each); the underlying file closes when the
// last adapter releases. sync.Once pins the "exactly one Release per
// adapter" invariant.
type sharedPcapAdapter struct {
	s     *output.SharedPCAPWriter
	once  sync.Once
	err   error
	final bool
}

func (a *sharedPcapAdapter) WritePackets(packets [][]byte) error { return a.s.Write(packets) }

func (a *sharedPcapAdapter) WriteTimedPackets(packets []core.PacketOutput) error {
	tp := make([]output.TimedPacket, len(packets))
	for i, p := range packets {
		tp[i] = output.TimedPacket{Data: p.Data, Timestamp: p.Timestamp}
	}
	return a.s.WriteTimed(tp)
}

func (a *sharedPcapAdapter) Truncated() bool { return a.s.Truncated() }

// Final reports whether this adapter's Release was the last one (file
// actually closed).
func (a *sharedPcapAdapter) Final() bool { return a.final }

func (a *sharedPcapAdapter) Close() error {
	a.once.Do(func() { a.final, a.err = a.s.Release() })
	return a.err
}

// newInterfaceWriterFn is a test seam: unit tests swap in a stub so
// batch/both happy paths run without a real NIC. Always the real
// constructor in production.
var newInterfaceWriterFn = func(iface string) (core.PacketWriter, error) {
	w, err := output.NewInterfaceWriter(iface)
	if err != nil {
		return nil, err
	}
	return &interfacePacketWriter{w: w}, nil
}

func newInterfacePacketWriter(iface string) (core.PacketWriter, error) {
	return newInterfaceWriterFn(iface)
}

// newSharedPCAPWriterFn is a test seam, same idiom as newInterfaceWriterFn:
// the D-ENG-1 R1 regression test needs to fail exactly one ct's .s2c open
// deterministically (a real-filesystem failure can't hit ct1's .s2c without
// also hitting ct2's, since the path is shared). Always the real constructor
// in production.
var newSharedPCAPWriterFn = output.NewSharedPCAPWriter

// defaultShadowPcapMaxBytes caps the both-mode shadow pcap on disk (global
// header included). Hitting it truncates the shadow (valid pcap, complete
// records) and surfaces a note; the wire run is never affected.
// Var so the D-ENG-3 bench can shrink it to exercise the cap-trigger phase
// (production default unchanged).
// ponytail: fixed 1GB, no knob — make it a setting when someone hits it.
var defaultShadowPcapMaxBytes int64 = 1 << 30

// shadowSink is the shadow-side contract: the pcap writer plus its timed
// variant and the truncation probe (interface extracted so tests can stub
// the sink). Truncated lets shadowWriter surface a cap-hit note at Close —
// PCAPWriter treats the cap as a planned ceiling (Write returns nil), so
// without this probe a 1GB-truncated shadow would complete silently with no
// shadow_note, undercutting the pcap-path acceptance evidence (§6.3).
// Final gates the note to the LAST releasing consumer (M2: N strategies
// sharing one shadow must produce exactly one truncation note).
type shadowSink interface {
	core.PacketWriter
	core.TimedWriter
	Truncated() bool
	Final() bool
}

// shadowWriter fans each packet out to a primary sink (NIC) and a
// best-effort shadow pcap sink (output_type=both). Error tiers differ:
//   - primary failure returns the error → the normal output-error path fails
//     the task (wire problems must be loud);
//   - shadow failure is downgraded: logged once, recorded via onShadowIssue
//     (task shadow_note), and further shadow writes are skipped — a full
//     disk must not kill a healthy wire run. A cap-hit truncation ends on a
//     complete record (valid pcap); an ERROR-path tear may leave a torn
//     final record (parsers tolerate a torn tail).
//
// shadowWriter implements core.TimedWriter and dispatches per side: the
// shadow receives the scheduled §12 send timestamps; the NIC (no schedule)
// gets the plain byte path. v1 registers it only via RegisterOutputWriter —
// both×dual is rejected at the validation gates.
type shadowWriter struct {
	primary      core.PacketWriter
	shadow       shadowSink
	broken       atomic.Bool
	onShadowNote func(msg string)
}

func (s *shadowWriter) WriteTimedPackets(packets []core.PacketOutput) error {
	frames := make([][]byte, len(packets))
	for i, p := range packets {
		frames[i] = p.Data
	}
	if err := s.primary.WritePackets(frames); err != nil {
		return err
	}
	s.writeShadow(func() error { return s.shadow.WriteTimedPackets(packets) })
	return nil
}

func (s *shadowWriter) WritePackets(packets [][]byte) error {
	if err := s.primary.WritePackets(packets); err != nil {
		return err
	}
	s.writeShadow(func() error { return s.shadow.WritePackets(packets) })
	return nil
}

// writeShadow runs one shadow-side write under the degrade policy: first
// error flips broken (so later packets skip the shadow entirely — no
// per-packet error spam) and fires the note callback exactly once.
func (s *shadowWriter) writeShadow(write func() error) {
	if s.broken.Load() {
		return
	}
	if err := write(); err != nil {
		if s.broken.CompareAndSwap(false, true) {
			msg := "shadow pcap degraded, mirror stopped: " + err.Error()
			log.Printf("[shadow] %s", msg)
			if s.onShadowNote != nil {
				s.onShadowNote(msg)
			}
		}
	}
}

func (s *shadowWriter) Close() error {
	perr := s.primary.Close()
	if s.broken.Load() {
		// Already degraded: still close/flush whatever reached the buffer.
		// A close-time failure stays unrecorded (best-effort; the first
		// write error in the note is the headline, a torn tail is tolerated
		// by parsers).
		_ = s.shadow.Close()
		return perr
	}
	s.writeShadow(func() error { return s.shadow.Close() })
	// A cap hit is a planned ceiling — Write/Close all return nil, so it
	// would otherwise complete with NO shadow_note (F1). Surface it here,
	// once, after the final flush made the truncation fact on disk — and
	// only from the consumer whose Close finalized the file (M2: shared
	// shadow, N strategies → one note, not N).
	if !s.broken.Load() && s.shadow.Truncated() && s.shadow.Final() && s.onShadowNote != nil {
		s.onShadowNote(fmt.Sprintf(
			"shadow pcap hit the %dMB cap and was truncated (still a valid pcap, ends on a complete record)",
			defaultShadowPcapMaxBytes/(1<<20)))
	}
	return perr
}

// newShadowPacketWriterWithSink builds the both-mode composite around an
// already-referenced shadow sink (D-ENG-1: the caller owns the AddRef and
// releases on error). L1: primary 先开,失败时 sink 未入 writer,由调用方
// Release 抵消。
func newShadowPacketWriterWithSink(iface string, shadow shadowSink, onShadowNote func(msg string)) (core.PacketWriter, error) {
	primary, err := newInterfacePacketWriter(iface)
	if err != nil {
		return nil, err
	}
	return &shadowWriter{primary: primary, shadow: shadow, onShadowNote: onShadowNote}, nil
}

// noteShadowIssue persists a shadow degradation into the task's shadow_note
// column (best-effort: the wire run never depends on it). Append-safe via
// SQL concat — multi-strategy tasks run one shadowWriter per engine task,
// and two degraded shadows must not clobber each other's note.
func (h *TaskHandler) noteShadowIssue(taskID, msg string) {
	h.db.Model(&storage.TaskModel{}).Where("id = ?", taskID).
		Update("shadow_note", gorm.Expr(
			"CASE WHEN shadow_note IS NULL OR shadow_note = '' THEN ? ELSE shadow_note || ? END",
			msg, " | "+msg))
}

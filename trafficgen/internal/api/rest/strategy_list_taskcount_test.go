package rest

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/trafficgen/trafficgen/internal/storage"
)

// P1-5（2026-10-05 客户端复测）：list 的 TaskCount 与逐条 EXISTS 计数一致。
// N+1 → 单条 GROUP BY 聚合是纯性能修复（2875 策略实测 66s，线上部署后复测
// 耗时），行为契约由本测试钉定：引用计数语义不变。
func TestStrategyListTaskCounts(t *testing.T) {
	h, r, db := newStrategyTestServer(t)
	stratUser(r, "u1", "alice")
	r.GET("/strategies", h.List)

	id1 := createTestStrategy(t, db, "u1", "list-s1", "dns")
	id2 := createTestStrategy(t, db, "u1", "list-s2", "http")
	// task1 引用两策略；task2 只引用 s1 → s1 计 2、s2 计 1。
	for i, sids := range [][]string{{id1, id2}, {id1}} {
		sidsJSON, _ := json.Marshal(sids)
		if err := db.Create(&storage.TaskModel{
			ID: fmt.Sprintf("task-%d", i), UserID: "u1", Name: fmt.Sprintf("t%d", i),
			StrategyIDs: string(sidsJSON), Status: "completed",
		}).Error; err != nil {
			t.Fatalf("seed task: %v", err)
		}
	}
	// 他人策略不计数（user 隔离）。
	createTestStrategy(t, db, "someone-else", "other-s", "dns")

	req := httptest.NewRequest("GET", "/strategies", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("list: %d %s", w.Code, w.Body.String())
	}
	var resp struct {
		Data []struct {
			ID        string `json:"id"`
			TaskCount int    `json:"task_count"`
		} `json:"data"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := map[string]int{}
	for _, s := range resp.Data {
		got[s.ID] = s.TaskCount
	}
	if got[id1] != 2 || got[id2] != 1 {
		t.Errorf("task counts: s1=%d (want 2) s2=%d (want 1)", got[id1], got[id2])
	}
}

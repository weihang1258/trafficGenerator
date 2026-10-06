package rest

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/trafficgen/trafficgen/internal/storage"
)

// OBS-3（2026-10-06 客户端反馈）：manage_tasks action=list 无名称过滤——
// 全系统 2 万+ 任务全量返回（13.8MB 自动导出），LLM 无法按前缀检索自己的
// 任务。name_prefix 前缀过滤（LIKE 元字符转义）。

func TestTaskListNamePrefix(t *testing.T) {
	gin.SetMode(gin.TestMode)
	h, r, db, _ := newTaskTestServer(t)
	r.Use(func(c *gin.Context) { c.Set("userID", "test-user"); c.Next() })
	r.GET("/tasks", h.List)

	names := []string{"alpha-1", "alpha-2", "beta-1"}
	for _, n := range names {
		if err := db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: n, Status: "completed"}).Error; err != nil {
			t.Fatalf("seed %s: %v", n, err)
		}
	}

	fetch := func(q string) []string {
		w := httptest.NewRecorder()
		r.ServeHTTP(w, httptest.NewRequest("GET", "/tasks"+q, nil))
		if w.Code != 0 && w.Code >= 400 {
			t.Fatalf("list status=%d body=%s", w.Code, w.Body.String())
		}
		var resp struct {
			Code int `json:"code"`
			Data struct {
				Items []struct {
					Name string `json:"name"`
				} `json:"items"`
			} `json:"data"`
		}
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("unmarshal: %v body=%s", err, w.Body.String())
		}
		out := make([]string, 0, len(resp.Data.Items))
		for _, tk := range resp.Data.Items {
			out = append(out, tk.Name)
		}
		return out
	}

	got := fetch("?name_prefix=alpha")
	if len(got) != 2 {
		t.Errorf("name_prefix=alpha returned %d tasks %v, want 2", len(got), got)
	}
	got = fetch("?name_prefix=alpha-1")
	if len(got) != 1 || got[0] != "alpha-1" {
		t.Errorf("name_prefix=alpha-1 returned %v, want [alpha-1]", got)
	}
	// 无过滤 → 全量（既有行为不变）。
	if all := fetch(""); len(all) < 3 {
		t.Errorf("no filter returned %d, want >= 3", len(all))
	}
	// LIKE 元字符按字面前缀匹配：%/_/\ 必须被转义成字面量，不得当通配符。
	if err := db.Create(&storage.TaskModel{ID: uuid.New().String(), UserID: "test-user", Name: "a%b_c", Status: "completed"}).Error; err != nil {
		t.Fatalf("seed metachar task: %v", err)
	}
	got = fetch(`?name_prefix=a%25b_c`)
	if len(got) != 1 || got[0] != "a%b_c" {
		t.Errorf("metachar prefix must match literally, got %v", got)
	}
	got = fetch("?name_prefix=a")
	if len(got) != 3 {
		t.Errorf("prefix 'a' must NOT expand the metachar task's %% and _ as wildcards beyond literal prefix; got %v", got)
	}
}

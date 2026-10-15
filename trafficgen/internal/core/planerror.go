package core

import (
	"context"
	"sync"
)

// PlanErrorSink carries a planner's asynchronous (drive-goroutine) error back
// to the submitting worker. D-ROBUST-1（BUG-16）：ChainPlanner 的 drive 跑在
// goroutine 里，其错误此前只落日志——任务面只剩 "planner produced 0 packet
// configs"（0 包掩蔽，真实根因丢失）。sink 经 ctx 传递，零接口变更
// （ProtocolPlanner 不动），全部 planner 统一受益；未设置的路径（legacy
// planner 直连）Load 返回 nil，0 包报错维持原文。
type PlanErrorSink struct {
	mu  sync.Mutex
	err error
}

// Store records the drive error (first write wins).
func (s *PlanErrorSink) Store(err error) {
	if s == nil || err == nil {
		return
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
}

// Load returns the stored error, or nil when none was recorded.
func (s *PlanErrorSink) Load() error {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

type planErrorKey struct{}

// WithPlanErrorSink returns a ctx carrying sink.
func WithPlanErrorSink(ctx context.Context, sink *PlanErrorSink) context.Context {
	return context.WithValue(ctx, planErrorKey{}, sink)
}

// PlanErrorFrom returns the sink carried by ctx, or nil.
func PlanErrorFrom(ctx context.Context) *PlanErrorSink {
	sink, _ := ctx.Value(planErrorKey{}).(*PlanErrorSink)
	return sink
}

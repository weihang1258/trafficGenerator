# API设计 - gRPC API

**文档版本**: v1.0  
**更新日期**: 2026-04-01  
**模块**: internal/api/grpc

---

## 1. Proto定义

```protobuf
// api/proto/traffic.proto
syntax = "proto3";
package traffic.v1;

service TrafficService {
  rpc CreateTask(CreateTaskRequest) returns (CreateTaskResponse);
  rpc StartTask(StartTaskRequest) returns (StartTaskResponse);
  rpc GetTask(GetTaskRequest) returns (GetTaskResponse);
  rpc StreamTaskStatus(StreamTaskStatusRequest) returns (stream TaskStatus);
}

message Task {
  string task_id = 1;
  string name = 2;
  string status = 3;
  double progress = 4;
}

message CreateTaskRequest {
  string name = 1;
  TaskSpec spec = 2;
}

message CreateTaskResponse {
  string task_id = 1;
}
```

---

## 2. 服务实现

```go
// internal/api/grpc/service.go
type TrafficServiceServer struct {
    engine *core.Engine
}

func (s *TrafficServiceServer) CreateTask(
    ctx context.Context,
    req *pb.CreateTaskRequest,
) (*pb.CreateTaskResponse, error) {
    taskID := s.engine.CreateTask(req.Name, req.Spec)
    return &pb.CreateTaskResponse{TaskId: taskID}, nil
}

func (s *TrafficServiceServer) StreamTaskStatus(
    req *pb.StreamTaskStatusRequest,
    stream pb.TrafficService_StreamTaskStatusServer,
) error {
    ticker := time.NewTicker(time.Second)
    for range ticker.C {
        status := s.engine.GetTaskStatus(req.TaskId)
        stream.Send(&pb.TaskStatus{
            TaskId:   req.TaskId,
            Status:   status.Status,
            Progress: status.Progress,
        })
    }
    return nil
}
```


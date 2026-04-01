# API设计 - 完整Proto定义

**文档版本**: v1.0  
**更新日期**: 2026-04-01  
**文件**: api/proto/traffic.proto

---

## 1. 完整Proto文件

```protobuf
// api/proto/traffic.proto
syntax = "proto3";

package traffic.v1;
option go_package = "github.com/yourorg/traffic-generator/api/proto/trafficpb";

// ==================== 服务定义 ====================

service TrafficService {
  // 任务管理
  rpc CreateTask(CreateTaskRequest) returns (CreateTaskResponse);
  rpc StartTask(StartTaskRequest) returns (StartTaskResponse);
  rpc StopTask(StopTaskRequest) returns (StopTaskResponse);
  rpc GetTask(GetTaskRequest) returns (GetTaskResponse);
  rpc ListTasks(ListTasksRequest) returns (ListTasksResponse);
  rpc DeleteTask(DeleteTaskRequest) returns (DeleteTaskResponse);
  
  // 策略管理
  rpc CreateStrategy(CreateStrategyRequest) returns (CreateStrategyResponse);
  rpc GetStrategy(GetStrategyRequest) returns (GetStrategyResponse);
  rpc ListStrategies(ListStrategiesRequest) returns (ListStrategiesResponse);
  
  // 实时流
  rpc StreamTaskStatus(StreamTaskStatusRequest) returns (stream TaskStatusUpdate);
  rpc StreamMetrics(StreamMetricsRequest) returns (stream MetricsUpdate);
}

// ==================== 任务相关 ====================

message Task {
  string id = 1;
  string name = 2;
  string description = 3;
  TaskSpec spec = 4;
  string status = 5;  // created, running, paused, completed, failed
  double progress = 6;
  TaskStats stats = 7;
  int64 created_at = 8;
  int64 started_at = 9;
  int64 completed_at = 10;
}

message TaskSpec {
  repeated TrafficClass classes = 1;
  FlowConfig flows = 2;
  GlobalConfig global = 3;
}

message TrafficClass {
  string id = 1;
  string type = 2;  // tcp, udp, http, dns
  string bps = 3;
  map<string, string> config = 4;
}

message FlowConfig {
  int32 count = 1;
  int32 duration_seconds = 2;
}

message GlobalConfig {
  int32 total_flows = 1;
  int32 duration_seconds = 2;
}

message TaskStats {
  int64 packets_sent = 1;
  int64 bytes_sent = 2;
  int32 flows_generated = 3;
  double current_pps = 4;
  double current_bps = 5;
}

// ==================== 请求/响应 ====================

message CreateTaskRequest {
  string name = 1;
  string description = 2;
  TaskSpec spec = 3;
}

message CreateTaskResponse {
  string task_id = 1;
  string message = 2;
}

message StartTaskRequest {
  string task_id = 1;
}

message StartTaskResponse {
  bool success = 1;
  string message = 2;
}

message StopTaskRequest {
  string task_id = 1;
}

message StopTaskResponse {
  bool success = 1;
  string message = 2;
}

message GetTaskRequest {
  string task_id = 1;
}

message GetTaskResponse {
  Task task = 1;
}

message ListTasksRequest {
  int32 page = 1;
  int32 page_size = 2;
  string status = 3;  // filter by status
}

message ListTasksResponse {
  repeated Task tasks = 1;
  int32 total = 2;
}

message DeleteTaskRequest {
  string task_id = 1;
}

message DeleteTaskResponse {
  bool success = 1;
}

// ==================== 策略相关 ====================

message Strategy {
  string id = 1;
  string name = 2;
  string protocol = 3;
  string description = 4;
  map<string, string> config = 5;
  int32 usage_count = 6;
  int64 created_at = 7;
}

message CreateStrategyRequest {
  string name = 1;
  string protocol = 2;
  string description = 3;
  map<string, string> config = 4;
}

message CreateStrategyResponse {
  string strategy_id = 1;
}

message GetStrategyRequest {
  string strategy_id = 1;
}

message GetStrategyResponse {
  Strategy strategy = 1;
}

message ListStrategiesRequest {
  int32 page = 1;
  int32 page_size = 2;
  string protocol = 3;
}

message ListStrategiesResponse {
  repeated Strategy strategies = 1;
  int32 total = 2;
}

// ==================== 流式更新 ====================

message StreamTaskStatusRequest {
  string task_id = 1;
}

message TaskStatusUpdate {
  string task_id = 1;
  string status = 2;
  double progress = 3;
  TaskStats stats = 4;
  int64 timestamp = 5;
}

message StreamMetricsRequest {
  repeated string metric_names = 1;
}

message MetricsUpdate {
  map<string, double> metrics = 1;
  int64 timestamp = 2;
}
```

---

## 2. 编译脚本

### Makefile

```makefile
.PHONY: proto
proto:
	protoc --go_out=. --go_opt=paths=source_relative \
	       --go-grpc_out=. --go-grpc_opt=paths=source_relative \
	       api/proto/traffic.proto

.PHONY: proto-clean
proto-clean:
	rm -f api/proto/trafficpb/*.pb.go
```

### 生成命令

```bash
# 安装protoc编译器
# macOS: brew install protobuf
# Linux: apt-get install protobuf-compiler

# 安装Go插件
go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
go install google.golang.org/grpc/cmd/protoc-gen-go-grpc@latest

# 生成代码
make proto
```

---

## 3. 生成文件位置

```
api/
├── proto/
│   ├── traffic.proto          # Proto定义
│   └── trafficpb/             # 生成的Go代码
│       ├── traffic.pb.go      # 消息定义
│       └── traffic_grpc.pb.go # gRPC服务
```

---

## 4. 服务端使用

```go
import pb "github.com/yourorg/traffic-generator/api/proto/trafficpb"

type server struct {
    pb.UnimplementedTrafficServiceServer
    engine *core.Engine
}

func (s *server) CreateTask(ctx context.Context, req *pb.CreateTaskRequest) (*pb.CreateTaskResponse, error) {
    taskID, err := s.engine.CreateTask(req.Name, req.Spec)
    if err != nil {
        return nil, status.Errorf(codes.Internal, "create task failed: %v", err)
    }
    return &pb.CreateTaskResponse{TaskId: taskID}, nil
}
```

---

## 5. 客户端使用

```go
conn, _ := grpc.Dial("localhost:9090", grpc.WithInsecure())
defer conn.Close()

client := pb.NewTrafficServiceClient(conn)

resp, err := client.CreateTask(context.Background(), &pb.CreateTaskRequest{
    Name: "Test Task",
    Spec: &pb.TaskSpec{...},
})
```

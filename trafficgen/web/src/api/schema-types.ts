// Code generated from trafficgen/schemas/v1 by tools/webgen.py. DO NOT EDIT.
// Single truth: schemas/v1/*.json.

// Shared envelopes (defs.json).
export type FlowControlType = 'flows' | 'bps' | 'time'
export interface FlowControl { type: FlowControlType; value: number }
// output_config keys: interface2 pcap_path port_group_id
export interface OutputConfig { port_group_id?: string; pcap_path?: string; interface2?: string }

// Strategy (strategy.json).
export type StrategyMode = 'synth' | 'replay'
export interface Strategy {
  id: string
  name: string
  mode?: StrategyMode
  protocol: string
  config: Record<string, any>
  flow_control?: FlowControl
  task_count?: number
  created_at: number
  updated_at: number
}
export interface CreateStrategyRequest {
  name: string
  mode?: StrategyMode
  protocol?: string
  config: Record<string, any>
  flow_control?: FlowControl
}

// Task (task.json).
export type OutputType = 'port_group' | 'pcap'
export interface Task {
  id: string
  user_id: string
  name: string
  strategy_ids: string[]
  protocol?: string
  strategies?: Strategy[]
  output_type: OutputType
  output_config: OutputConfig
  flow_control?: FlowControl
  status: string
  error_message?: string
  progress: number
  created_at: number
  updated_at: number
  started_at?: number
  completed_at?: number
}
export interface CreateTaskRequest {
  name: string
  strategy_ids: string[]
  output_type: OutputType
  output_config: OutputConfig
  flow_control?: FlowControl
}
export interface CreateBatchRequest {
  name: string
  batch: BatchSpec
  output_type: OutputType
  output_config: OutputConfig
  flow_control?: FlowControl
}

// Batch (batch.json).
// class keys: bps config flow_count flows_per_second group_id id replay tuples type
export interface BatchClass {
  id: string
  type: string
  bps?: string
  flows_per_second?: number
  flow_count?: number
  tuples?: Record<string, any>
  config?: Record<string, any>
  replay?: Record<string, any>
  group_id?: Record<string, any>
}
export interface BatchSpec {
  classes: BatchClass[]
  global?: { total_flows?: number; duration_seconds?: number }
}

// Layers: 115 registered (Layer chain).

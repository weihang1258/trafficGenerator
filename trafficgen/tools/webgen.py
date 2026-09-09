"""Single truth: schemas/v1/*.json -> web/src/api/schema-types.ts + docs/config-schema.md tables.
Reads: schemas/v1/{defs,strategy,task,batch,layers}.json (+ generated/layers.generated.json for counts).
Writes: web/src/api/schema-types.ts, docs/config-schema.md (tables only; prose rules stay hand-written in CODE_DESIGN).
Regenerate: python3 tools/webgen.py (from trafficgen/). CI: regenerate + git diff --exit-code."""
import json, collections, os
BASE = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
def load(p):
    return json.loads(open(os.path.join(BASE, p)).read(), object_pairs_hook=collections.OrderedDict)
defs = load('schemas/v1/defs.json')['$defs']
strategy = load('schemas/v1/strategy.json')
task = load('schemas/v1/task.json')
batch = load('schemas/v1/batch.json')
layers = load('schemas/v1/layers.json')
gen = load('schemas/v1/generated/layers.generated.json')
def fc_union():
    return " | ".join("'%s'" % e for e in defs['flow_control']['properties']['type']['enum'])
lines = []
lines.append("// Code generated from trafficgen/schemas/v1 by tools/webgen.py. DO NOT EDIT.")
lines.append("// Single truth: schemas/v1/*.json.")
lines.append("")
lines.append("// Shared envelopes (defs.json).")
lines.append("export type FlowControlType = %s" % fc_union())
lines.append("export interface FlowControl { type: FlowControlType; value: number }")
oc = defs['output_config']['properties']
oc_fields = " ".join("<%s>" % k for k in oc.keys())
lines.append("// output_config keys: %s" % " ".join(sorted(oc.keys())))
lines.append("export interface OutputConfig { %s }" % "; ".join(
    "%s?: string" % k for k in oc.keys()))
lines.append("")
lines.append("// Strategy (strategy.json).")
mode_enum = " | ".join("'%s'" % e for e in strategy['properties']['mode']['enum'])
lines.append("export type StrategyMode = %s" % mode_enum)
lines.append("export interface Strategy {")
for f in ["  id: string","  name: string","  mode?: StrategyMode","  protocol: string",
          "  config: Record<string, any>","  flow_control?: FlowControl","  task_count?: number",
          "  created_at: number","  updated_at: number"]:
    lines.append(f)
lines.append("}")
lines.append("export interface CreateStrategyRequest {")
for f in ["  name: string","  mode?: StrategyMode","  protocol?: string",
          "  config: Record<string, any>","  flow_control?: FlowControl"]:
    lines.append(f)
lines.append("}")
lines.append("")
lines.append("// Task (task.json).")
lines.append("export type OutputType = %s" % " | ".join("'%s'" % e for e in task['properties']['output_type']['enum']))
for iface, fields in [
    ("Task", ["  id: string","  user_id: string","  name: string","  strategy_ids: string[]",
              "  protocol?: string","  strategies?: Strategy[]","  output_type: OutputType",
              "  output_config: OutputConfig","  flow_control?: FlowControl","  status: string",
              "  error_message?: string","  progress: number","  created_at: number","  updated_at: number",
              "  started_at?: number","  completed_at?: number"]),
    ("CreateTaskRequest", ["  name: string","  strategy_ids: string[]","  output_type: OutputType",
              "  output_config: OutputConfig","  flow_control?: FlowControl"]),
    ("CreateBatchRequest", ["  name: string","  batch: BatchSpec","  output_type: OutputType",
              "  output_config: OutputConfig","  flow_control?: FlowControl"]),
]:
    lines.append("export interface %s {" % iface)
    lines.extend(fields)
    lines.append("}")
lines.append("")
lines.append("// Batch (batch.json).")
cls = batch['properties']['classes']['items']['properties']
lines.append("// class keys: %s" % " ".join(sorted(cls.keys())))
lines.append("export interface BatchClass {")
for f in ["  id: string","  type: string","  bps?: string","  flows_per_second?: number",
          "  flow_count?: number","  tuples?: Record<string, any>","  config?: Record<string, any>",
          "  replay?: Record<string, any>","  group_id?: Record<string, any>"]:
    lines.append(f)
lines.append("}")
lines.append("export interface BatchSpec {")
lines.append("  classes: BatchClass[]")
lines.append("  global?: { total_flows?: number; duration_seconds?: number }")
lines.append("}")
lines.append("")
lines.append("// Layers: %d registered (%s)." % (len(gen['layers']), layers['title']))
open(os.path.join(BASE, 'web/src/api/schema-types.ts'), 'w').write("\n".join(lines) + "\n")
print("wrote web/src/api/schema-types.ts")

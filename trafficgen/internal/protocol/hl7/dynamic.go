// Package hl7 dynamic value resolution (契约 §6 动态值机制)：session-level
// control_id/timestamp/patient_id 策略对象（inc/rand）与 @ts/@pid/@cid/@name
// 字段占位符。唯一解析权威——planner（validator）与 generator 都经
// newDynState + resolve 取值，线上序列与校验判重集合同源（megaco U1/U2
// 教训：解析权威必须唯一，两侧各算必漂移）。
package hl7

import (
	"encoding/json"
	"fmt"
	"math/rand"

	"github.com/trafficgen/trafficgen/internal/core"
)

// dynSpec is one parsed session-level strategy object
// {"strategy":"inc"|"rand","range":[min,max],"step":n,"seed":n}.
type dynSpec struct {
	strategy string
	min, max int64
	step     int64
	seed     int64
	draws    int64      // number of prior draws (inc sequence index)
	rng      *rand.Rand // rand strategy: lazily seeded, deterministic
}

// parseDynSpec parses one raw session dynamic value. Only the object form is
// contract-legal at session level (§6 fixture 形状)；字符串通道是事件级钉值
// （ev.ControlID/ev.Timestamp），会话级字符串不在契约形状内——拒。
func parseDynSpec(raw json.RawMessage, key, where string) (*dynSpec, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var obj struct {
		Strategy string  `json:"strategy"`
		Range    []int64 `json:"range"`
		Step     int64   `json:"step"`
		Seed     int64   `json:"seed"`
	}
	if err := json.Unmarshal(raw, &obj); err != nil {
		return nil, fmt.Errorf("%s %s: strategy object invalid: %v", where, key, err)
	}
	d := &dynSpec{strategy: obj.Strategy, step: obj.Step, seed: obj.Seed}
	if len(obj.Range) != 2 || obj.Range[0] > obj.Range[1] {
		return nil, fmt.Errorf("%s %s: strategy %q needs range [min,max] with min<=max", where, key, obj.Strategy)
	}
	d.min, d.max = obj.Range[0], obj.Range[1]
	switch obj.Strategy {
	case "inc":
		if d.step <= 0 {
			d.step = 1
		}
	case "rand":
		// seed 缺省 0 也确定（rand.NewSource(0)）。
	default:
		return nil, fmt.Errorf("%s %s: unknown strategy %q (inc/rand)", where, key, obj.Strategy)
	}
	return d, nil
}

// draw returns the next value and advances the spec's own counter. inc wraps
// within the range (ValueCycler 约定)；rand 依固定种子的确定性序列逐次抽取
// ——validator 与 generator 每事件各恰调一次 resolve，两侧序列一致。
func (d *dynSpec) draw() string {
	i := d.draws
	d.draws++
	span := d.max - d.min + 1
	if d.strategy == "inc" {
		return fmt.Sprintf("%d", d.min+(i*d.step)%span)
	}
	if d.rng == nil {
		d.rng = rand.New(rand.NewSource(d.seed))
	}
	return fmt.Sprintf("%d", d.min+d.rng.Int63n(span))
}

// dynState is the per-session resolution authority: parsed specs plus the
// advancing counters shared by validator and generator.
type dynState struct {
	sess              *core.HL7Session
	ctrl, tsSpec, pid *dynSpec
	seq               int64 // MSG%04d counter (events without pin/strategy)
}

// newDynState parses the session's strategy objects. Errors are config-shape
// errors (unknown strategy / bad range) — plain text, not wire_fault anchors.
func newDynState(sess *core.HL7Session, where string) (*dynState, error) {
	st := &dynState{sess: sess}
	var err error
	if st.ctrl, err = parseDynSpec(sess.ControlID, "control_id", where); err != nil {
		return nil, err
	}
	if st.tsSpec, err = parseDynSpec(sess.Timestamp, "timestamp", where); err != nil {
		return nil, err
	}
	if st.pid, err = parseDynSpec(sess.PatientID, "patient_id", where); err != nil {
		return nil, err
	}
	return st, nil
}

// resolve returns (MSH-7 timestamp, MSH-10 control id, patient id) for one
// event and advances the strategy counters. Event pins win (契约：消息级
// 覆盖会话级)；strategy counters advance only when actually consumed.
// now is the runtime timestamp fallback (generator passes wall clock,
// validator passes "" — it never renders).
func (st *dynState) resolve(ev *core.HL7Event, now string) (ts, ctrlID, pid string) {
	if ev.Timestamp != "" {
		ts = ev.Timestamp
	} else if st.tsSpec != nil {
		ts = st.tsSpec.draw()
	} else {
		ts = now
	}
	if ev.ControlID != "" {
		ctrlID = ev.ControlID
	} else if st.ctrl != nil {
		ctrlID = st.ctrl.draw()
	} else {
		if st.seq == 0 {
			st.seq = 1
		}
		ctrlID = fmt.Sprintf("MSG%04d", st.seq)
		st.seq++
	}
	if st.pid != nil {
		pid = st.pid.draw()
	}
	return ts, ctrlID, pid
}

// placeholders returns the substitution table for one event's field values
// (契约 §6 占位符表：@ts/@cid/@pid 策略替换，@name 会话名替换).
func (st *dynState) placeholders(ts, ctrlID, pid string) map[string]string {
	return map[string]string{
		"@ts":   ts,
		"@cid":  ctrlID,
		"@pid":  pid,
		"@name": st.sess.Name,
	}
}

// scanPlaceholders validates placeholder tokens in one field value: unknown
// tokens and tokens without their backing resource are rejected — a silent
// literal on the wire is exactly the F11 failure face.
func (st *dynState) scanPlaceholders(where string, sgi, fi int, s string) error {
	for i := 0; i < len(s); i++ {
		if s[i] != '@' {
			continue
		}
		j := i + 1
		for j < len(s) && s[j] >= 'a' && s[j] <= 'z' {
			j++
		}
		if j == i+1 {
			continue // bare '@' is not a placeholder
		}
		switch s[i+1 : j] {
		case "ts", "cid": // always backed: MSH-7 / MSH-10 authority exists
		case "pid":
			if st.pid == nil {
				return fmt.Errorf("%s segment[%d].field[%d] placeholder @pid requires session-level patient_id strategy (pid)", where, sgi, fi)
			}
		case "name":
			if st.sess.Name == "" {
				return fmt.Errorf("%s segment[%d].field[%d] placeholder @name requires a session name (name)", where, sgi, fi)
			}
		default:
			return fmt.Errorf("%s segment[%d].field[%d] unknown placeholder @%s (known: ts/pid/cid/name) (placeholder)", where, sgi, fi, s[i+1:j])
		}
		i = j - 1
	}
	return nil
}

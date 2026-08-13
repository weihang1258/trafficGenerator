package layers

import (
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

// completeError is a validation/completion failure with a stable code prefix
// that tests can match (校验错误，§10.2 V1-V10)。
type completeError struct{ msg string }

func (e *completeError) Error() string { return e.msg }

func errf(format string, args ...interface{}) error {
	return &completeError{msg: fmt.Sprintf(format, args...)}
}

// numeric helpers: convert config values to an int64 range for bound checks.
// Supported value kinds: json.Number, float64, int/uint variants (from yaml),
// and numeric strings. 显式 0 与缺失的区分由调用方负责（§6.4）。
// 越界值返回 (0, false)：超 int64 的整数、超出 uint64 的整数、非整数值都算不可转换，
// 调用方对"存在值但不可转换"必须报错，不得静默跳过（防绕过 V9 范围检查）。
func asInt64(v interface{}) (int64, bool) {
	switch n := v.(type) {
	case json.Number:
		if i, err := n.Int64(); err == nil {
			return i, true
		}
		// 超 int64：若可解析为 float64 且数值本身超 int64 范围 → 不可转换。
		if f, err := n.Float64(); err == nil {
			if f >= float64(1<<63) || f < float64(-1<<63) {
				return 0, false
			}
		}
		return 0, false
	case float64:
		// 非整数值不可转换（1.5 是小数，不能截断成 1 通过范围检查）。
		if n != float64(int64(n)) {
			return 0, false
		}
		return int64(n), true
	case int:
		return int64(n), true
	case int8:
		return int64(n), true
	case int16:
		return int64(n), true
	case int32:
		return int64(n), true
	case int64:
		return n, true
	case uint:
		return int64(n), n <= 1<<63-1
	case uint8:
		return int64(n), true
	case uint16:
		return int64(n), true
	case uint32:
		return int64(n), true
	case uint64:
		return int64(n), n <= 1<<63-1
	case string:
		i, err := strconv.ParseInt(n, 10, 64)
		return i, err == nil
	case bool:
		if n {
			return 1, true
		}
		return 0, true
	}
	return 0, false
}

// IsValidationError reports whether err is a layer-chain validation error.
func IsValidationError(err error) bool {
	_, ok := err.(*completeError)
	return ok
}

// completeDeps runs one dependency-completion sweep over out: for every layer
// whose depends_on is missing outward of it, insert the missing dependency
// just outward of that layer (外层包内层). Returns whether anything was
// inserted. TransportOn substitution skips the default transport when the
// user wrote another usable transport explicitly.
//
// 第一趟/第三趟共用：迭代直到不再插入（外层循环负责迭代）。
func (r *Registry) completeDeps(out []Layer) ([]Layer, bool, error) {
	changed := false
	for i := 0; i < len(out); i++ {
		schema, ok := r.Get(out[i].Name)
		if !ok {
			return nil, false, errf("layers: unknown layer %q in chain %s", out[i].Name, chainString(out))
		}
		for _, dep := range schema.DependsOn {
			if outerHas(out, i, dep) {
				continue // 该层更外层已有此依赖
			}
			// TransportOn 替代：dep 是默认传输层，用户显式写了另一个可用传输层 → 不补默认。
			if len(schema.TransportOn) > 0 && contains(schema.TransportOn, dep) {
				if hasAnyOuter(out, i, schema.TransportOn) {
					continue
				}
			}
			// 插到该层外侧（位置 i），depends_on 顺序 = 从外到内。
			out = append(out[:i], append([]Layer{{Name: dep}}, out[i:]...)...)
			changed = true
			i++ // 跳过刚插入的层，继续检查更内层
		}
	}
	return out, changed, nil
}

// CompleteChain 自动补全层链（§7.3 两趟式，方向按 §12 示例修正）：
//
// 第一趟：硬依赖（depends_on）— 每层更外层方向缺的依赖自动插入到该层外侧，
//  迭代直到稳定（新插入层自己的依赖也会被补，如 http 补的 tcp 又缺 ip）。
//  依赖层在外侧：http 需要 tcp 包它 → tcp 在 http 外面 [ip → tcp → http]。
// 第二趟：内层起点（inner_required）— 隧道层的直接内层邻居不满足起点要求时补。
// 第三趟：补全回看 — inner_required 插入把内层整体推后一格，被推后层自身的
//   depends_on 需要再补一轮（HIGH-1 修复，否则含隧道层链可能 V8 拒绝）。
//
// 关键正确性保证（§7.5 等价性不变量）：
//   1. 每层的全部 depends_on 都在该层更外层方向出现
//   2. 隧道层的直接内层邻居 ∈ inner_required
//   3. 传输层全链唯一（tcp/udp 不重复）
//   4. 终结层全链唯一
//   5. 末层是终结层、传输层/隧道层不在末层
//   6. 二层层（eth/vlan/mpls）只能出现在链最外（开头连续段）
//
// 返回补全后的新链；原链不变。
func (r *Registry) CompleteChain(chain []Layer) ([]Layer, error) {
	if len(chain) == 0 {
		return nil, errf("layers: empty layer chain")
	}
	out := make([]Layer, len(chain))
	copy(out, chain)

	// 第一趟：硬依赖（depends_on）+ 传输层替代（TransportOn），迭代直到稳定。
	// 每层缺的依赖（该层更外层方向没有的）插到该层外侧（位置 i，更外层）。
	// 依赖层在外侧：http 需要 tcp 包它 → tcp 在 http 外面（§12.1 [ip → tcp → http]）。
	// 迭代式处理"新插入层自己的依赖"（如 http 补的 tcp 又缺 ip）。
	//
	// TransportOn 替代（§4.4 注记）：当层的 depends_on 是传输层（默认值），
	// 而用户已显式写了 TransportOn 中的另一个传输层 → 跳过默认，不重复补。
	// 例：{"dns":{}, "tcp":{}} → [ip → tcp → dns]（tcp 覆盖 dns 默认的 udp）。
	// 例：{"http":{}, "udp":{}} → http 的 TransportOn 不含 udp → 仍补 tcp，
	//     之后校验报"传输层重复"（http 不支持 udp）。
	for changed := true; changed; {
		var err error
		out, changed, err = r.completeDeps(out)
		if err != nil {
			return nil, err
		}
	}

	// 第二趟：内层起点（inner_required），隧道层专用。
	for i := 0; i < len(out); i++ {
		schema, ok := r.Get(out[i].Name)
		if !ok {
			return nil, errf("layers: unknown layer %q in chain %s", out[i].Name, chainString(out))
		}
		if len(schema.InnerRequired) == 0 {
			continue
		}
		// 内层直接邻居必须满足起点要求。
		innerIdx := i + 1
		if innerIdx >= len(out) {
			// 隧道层是末层：必须补内层起点。
			out = append(out, Layer{Name: schema.InnerRequired[0]})
			continue
		}
		inner := out[innerIdx].Name
		matches := false
		for _, req := range schema.InnerRequired {
			if inner == req {
				matches = true
				break
			}
		}
		if !matches {
			// 补第一个要求的起点层，插到隧道层内侧。
			out = append(out[:innerIdx], append([]Layer{{Name: schema.InnerRequired[0]}}, out[innerIdx:]...)...)
		}
	}

	// 第三趟：补全回看 — inner_required 插入把隧道层内层整体推后一格，
	// 被推后层自身的 depends_on 可能因此缺失（HIGH-1 修复）。
	// 迭代补依赖直到稳定，保证含隧道层链"新插入层的依赖也被补"（§7.3 声明）。
	for changed := true; changed; {
		var err error
		out, changed, err = r.completeDeps(out)
		if err != nil {
			return nil, err
		}
	}

	// 补全后统一校验（§7.5 等价性不变量）。
	if err := r.validateChain(out); err != nil {
		return nil, err
	}
	return out, nil
}

// outerHas reports whether the layer at index i has a layer named want
// anywhere more outward (smaller index) than it (该层更外层方向是否有某层)。
func outerHas(chain []Layer, i int, want string) bool {
	for k := 0; k < i; k++ {
		if chain[k].Name == want {
			return true
		}
	}
	return false
}

// contains reports whether want is in list.
func contains(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}

// hasAnyOuter reports whether any of wants appears outward of index i.
// Used by TransportOn substitution (是否已有任一可用传输层在外侧)。
func hasAnyOuter(chain []Layer, i int, wants []string) bool {
	for k := 0; k < i; k++ {
		for _, w := range wants {
			if chain[k].Name == w {
				return true
			}
		}
	}
	return false
}

// chainString renders the chain for error messages (层链文本表示)。
func chainString(chain []Layer) string {
	names := make([]string, len(chain))
	for i, l := range chain {
		names[i] = l.Name
	}
	return "[" + strings.Join(names, " → ") + "]"
}

// ValidateChain 校验一条（已补全的）层链，返回第一个违规错误（§10.2 V1-V10）。
func (r *Registry) ValidateChain(chain []Layer) error {
	return r.validateChain(chain)
}

// ValidateLayerConfig checks one layer's config values against its schema
// field ranges（§10.2 V9 字段范围）。Unknown fields are reported too（防拼写错误）。
// 返回值不区分"显式 0"与"缺失"：只对存在且可转换的值做范围检查（§6.4）。
// 转换口径与生成器一致（configUint64，MEDIUM 修复）：bool 不是数值，放进
// 数值字段（window_size/mss/ttl…）必须拒绝——旧实现 asInt64 把 true 当 1
// 放行，生成器 configUint64 拒绝，错误被驱动 goroutine 吞掉 → 静默空流
// （与 CRITICAL-1 同类后果）。bool 字段（handshake 等）无数值边界，跳过
// 数值转换，由生成器 configBool 兜底。
func (r *Registry) ValidateLayerConfig(l Layer) error {
	s, ok := r.Get(l.Name)
	if !ok {
		return errf("layers: unknown layer %q", l.Name)
	}
	names := make([]string, 0, len(l.Config))
	for k := range l.Config {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		v := l.Config[k]
		f, known := s.Fields[k]
		if !known {
			return errf("layers: layer %q: unknown field %q", l.Name, k)
		}
		if f.Min == 0 && f.Max == 0 {
			continue // no numeric bounds declared（bool/字符串字段由生成器转换兜底）
		}
		u, ok := configUint64(v)
		if !ok {
			// 存在值但不可转换（bool、负值、超 uint64 的整数、非整数值）：
			// 必须拒绝，不得静默跳过（防绕过 V9 范围检查，MEDIUM-2 修复；
			// bool 拒绝为 MEDIUM 修复，与生成器 configUint64 口径一致）。
			return errf("layers: layer %q field %q = %v invalid: not a numeric value in [%d,%d]",
				l.Name, k, v, f.Min, f.Max)
		}
		if u == 0 {
			// 显式 0 = "用 schema 默认值"（§6.4 显式 0 ≠ 缺失；与 flat 配置
			// 校验同款：mss 0 合法 → 生成时用默认 1460）。默认值本身在范围
			// 内（registry 保证），0 直接放行。
			continue
		}
		if u < uint64(f.Min) || u > uint64(f.Max) {
			return errf("layers: layer %q field %q = %v invalid: out of range [%d,%d]",
				l.Name, k, v, f.Min, f.Max)
		}
	}
	return nil
}

func (r *Registry) validateChain(chain []Layer) error {
	if len(chain) == 0 {
		return errf("layers: empty layer chain")
	}

	// ---- 第一遍：逐层静态检查（V1 层名、V4 末层、V7 二层层位置）----
	for i, l := range chain {
		schema, ok := r.Get(l.Name)
		if !ok {
			return errf("layers: unknown layer %q (position %d)", l.Name, i)
		}
		// V7: 二层层只能出现在链最外的"开头连续段"（链首起连续的二层层）。
		// 例：[eth, vlan, vlan, ip, tcp, http] 合法；[ip, vlan, http] 非法。
		if schema.Category == CategoryL2 {
			for k := 0; k < i; k++ {
				if ks, _ := r.Get(chain[k].Name); ks.Category != CategoryL2 {
					return errf("layers: layer %q (l2) must be in the outermost run (position %d)", l.Name, i)
				}
			}
		}
		// V4/V5/V6: 末层必须是终结层，传输层/隧道层/二层层/网络层不能当末层。
		// 含 CategoryNetwork：零终结层链（如 [gre] 补全自产的 [ip, gre, ip]）必须拒绝，
		// 不能只拦 transport/tunnel/l2 而放行 ip 结尾。
		if i == len(chain)-1 {
			switch schema.Category {
			case CategoryTransport:
				return errf("layers: layer chain must end with a terminal layer, got %q (transport)", l.Name)
			case CategoryTunnel:
				return errf("layers: layer chain must end with a terminal layer, got %q (tunnel)", l.Name)
			case CategoryL2:
				return errf("layers: layer chain must end with a terminal layer, got %q (l2)", l.Name)
			case CategoryNetwork:
				return errf("layers: layer chain must end with a terminal layer, got %q (network)", l.Name)
			}
		}
	}

	// ---- 第二遍：唯一性（V2 终结层、V3 传输层）----
	terminalCount := 0
	terminalSeen := ""
	transportCount := 0
	for _, l := range chain {
		schema, ok := r.Get(l.Name)
		if !ok {
			continue // V1 already reported
		}
		switch schema.Category {
		case CategoryTerminal:
			terminalCount++
			terminalSeen = l.Name
		case CategoryTransport:
			transportCount++
		}
	}
	if terminalCount > 1 {
		return errf("layers: terminal layer %q duplicated (%d terminal layers)", terminalSeen, terminalCount)
	}
	// V3: 传输层全链唯一——计数而非按层名去重（两个同名 tcp 也是重复）。
	if transportCount > 1 {
		return errf("layers: transport layer duplicated (%d transport layers)", transportCount)
	}

	// ---- 第三遍：顺序必须符合依赖（V8 + 隧道层内层起点）----
	// 每层的 depends_on 必须在它更外层方向出现（例：http 依赖 tcp → tcp 在 http 外层）。
	// TransportOn 替代（§4.4 注记）：dep 是默认传输层，用户显式写了另一可用传输层 → 该默认依赖不算缺失。
	for i, l := range chain {
		schema, ok := r.Get(l.Name)
		if !ok {
			continue
		}
		for _, dep := range schema.DependsOn {
			if len(schema.TransportOn) > 0 && contains(schema.TransportOn, dep) && hasAnyOuter(chain, i, schema.TransportOn) {
				continue // 默认传输层已被用户显式写的另一可用传输层替代
			}
			if !outerHas(chain, i, dep) {
				return errf("layers: layer %q depends on %q which is not outward of it", l.Name, dep)
			}
		}
		// 隧道层：直接内层邻居 ∈ inner_required（补全趟已处理，这里复查）。
		if len(schema.InnerRequired) > 0 && i < len(chain)-1 {
			inner := chain[i+1].Name
			okInner := false
			for _, req := range schema.InnerRequired {
				if inner == req {
					okInner = true
					break
				}
			}
			if !okInner {
				return errf("layers: tunnel layer %q inner layer %q not in inner_required %v", l.Name, inner, schema.InnerRequired)
			}
		}
	}
	return nil
}

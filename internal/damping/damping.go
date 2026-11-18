// Package damping 实现 BGP 路由翻动抑制（route flap damping, RFC 2439 简化模型）。
package damping

import "math"

// Config 是一组阻尼参数，缺省值采用 RFC 2439 附录的行业惯例。
type Config struct {
	Reuse          float64 `json:"reuse"`            // 重用阈值：惩罚值衰减到该值以下时解除抑制
	Suppress       float64 `json:"suppress"`         // 抑制阈值：惩罚值超过该值时抑制
	HalfLifeSec    float64 `json:"half_life_sec"`    // 半衰期（秒）
	FlapPenalty    float64 `json:"flap_penalty"`     // 每次翻动（撤回/重新通告）累加的惩罚
	MaxSuppressSec float64 `json:"max_suppress_sec"` // 最大抑制时长（秒）
}

// DefaultConfig 返回 Cisco/RFC 惯例参数。
func DefaultConfig() Config {
	return Config{
		Reuse:          750,
		Suppress:       2000,
		HalfLifeSec:    15 * 60,
		FlapPenalty:    1000,
		MaxSuppressSec: 60 * 60,
	}
}

// state 是单条（前缀 + 学到的对端）路由的阻尼状态。
type state struct {
	penalty      float64
	suppressed   bool
	lastUpdate   float64 // 上次衰减基准时间（秒）
	suppressedAt float64
}

// Tracker 按 routeKey（通常为 prefix|receivedFrom）维护全部阻尼状态。
type Tracker struct {
	cfg   Config
	items map[string]*state
}

// NewTracker 构造阻尼跟踪器。
func NewTracker(cfg Config) *Tracker {
	return &Tracker{cfg: cfg, items: map[string]*state{}}
}

// decayFactor 计算给定时间间隔后的惩罚衰减系数 2^(-delta/halfLife)。
func (t *Tracker) decayFactor(delta float64) float64 {
	if delta <= 0 {
		return 1
	}
	return math.Pow(2, -delta/t.cfg.HalfLifeSec)
}

// advance 把某条状态推进到 now，返回衰减后的惩罚值与是否仍抑制。
func (t *Tracker) advance(s *state, now float64) {
	if s.penalty == 0 {
		s.lastUpdate = now
		return
	}
	delta := now - s.lastUpdate
	if delta > 0 {
		s.penalty *= t.decayFactor(delta)
		s.lastUpdate = now
	}
	// 惩罚值低到可忽略时归零，避免长期残留。
	if s.penalty < 1 {
		s.penalty = 0
	}
	if s.suppressed && s.penalty < t.cfg.Reuse {
		// 超过最大抑制时长也必须放出。
		if now-s.suppressedAt >= t.cfg.MaxSuppressSec || s.penalty < t.cfg.Reuse {
			s.suppressed = false
		}
	}
}

// Flap 记录一次翻动并返回该路由当前是否应被抑制。
// 语义：路由被撤回或在不稳定状态下重新通告时调用。
func (t *Tracker) Flap(key string, now float64) (penalty float64, suppressed bool) {
	s := t.items[key]
	if s == nil {
		s = &state{}
		t.items[key] = s
	}
	t.advance(s, now)
	s.penalty += t.cfg.FlapPenalty
	if s.penalty >= t.cfg.Suppress && !s.suppressed {
		s.suppressed = true
		s.suppressedAt = now
	}
	return s.penalty, s.suppressed
}

// ReAnnounce 处理路由重新通告：若此前完全稳定（无惩罚）则不罚，
// 否则按一次翻动处理（RFC 2439 中 down→up 同样计罚）。
func (t *Tracker) ReAnnounce(key string, now float64) (penalty float64, suppressed bool) {
	s := t.items[key]
	if s == nil || s.penalty == 0 {
		if s == nil {
			t.items[key] = &state{lastUpdate: now}
		} else {
			s.lastUpdate = now
		}
		return 0, false
	}
	return t.Flap(key, now)
}

// Tick 把全部状态推进到 now，返回本次新解除抑制的 routeKey 列表，
// 供引擎把压住的路由重新纳入选路。
func (t *Tracker) Tick(now float64) []string {
	var released []string
	for key, s := range t.items {
		wasSuppressed := s.suppressed
		t.advance(s, now)
		if wasSuppressed && !s.suppressed {
			released = append(released, key)
		}
	}
	return released
}

// Penalty 查询某条路由当前惩罚值（先按 now 衰减）。
func (t *Tracker) Penalty(key string, now float64) (float64, bool) {
	s := t.items[key]
	if s == nil {
		return 0, false
	}
	t.advance(s, now)
	return s.penalty, s.suppressed
}

// Snapshot 返回全部阻尼状态，供页面展示。
type Snapshot struct {
	Key        string  `json:"key"`
	Penalty    float64 `json:"penalty"`
	Suppressed bool    `json:"suppressed"`
}

// SnapshotAt 生成 now 时刻的全量快照。
func (t *Tracker) SnapshotAt(now float64) []Snapshot {
	out := make([]Snapshot, 0, len(t.items))
	for key, s := range t.items {
		t.advance(s, now)
		if s.penalty == 0 {
			continue
		}
		out = append(out, Snapshot{Key: key, Penalty: s.penalty, Suppressed: s.suppressed})
	}
	return out
}

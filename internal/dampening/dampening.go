// Package dampening implements RFC 2439-style route flap dampening.
//
// Each (router, prefix) pair has a penalty counter.  Every withdrawal (a path
// becoming unusable) adds a fixed penalty.  When the accumulated penalty
// crosses the suppress threshold the prefix is suppressed: it is withdrawn
// from the RIB and not advertised until the penalty decays below the reuse
// threshold.  Penalties decay exponentially with a configurable half-life.
package dampening

import (
	"math"
)

// State is the per-(router,prefix) dampening record.
type State struct {
	Penalty      float64 `json:"penalty"`
	Suppressed   bool    `json:"suppressed"`
	Flaps        int     `json:"flaps"`
	SuppressedAt int64   `json:"suppressedAt"` // unix seconds, 0 if never
	lastSeen     int64
	ReusedAt     int64 `json:"reusedAt"` // unix seconds of last reuse
}

// Tracker holds all dampening states for one simulation run.
type Tracker struct {
	cfg   Config
	state map[uint64]*State
}

// Config mirrors model.DampeningConfig but with the values pre-converted.
type Config struct {
	Enabled        bool
	PenaltyPerFlap float64
	Suppress       float64
	Reuse          float64
	HalfLifeSec    float64
	MaxPenalty     float64
}

func New(cfg Config) *Tracker {
	if cfg.MaxPenalty <= 0 {
		cfg.MaxPenalty = 12000
	}
	return &Tracker{cfg: cfg, state: map[uint64]*State{}}
}

func key(router, prefix int) uint64 {
	return uint64(uint32(router))<<32 | uint64(uint32(prefix))
}

// Get returns the state for a pair, creating it if needed.
func (t *Tracker) Get(router, prefix int) *State {
	k := key(router, prefix)
	s, ok := t.state[k]
	if !ok {
		s = &State{}
		t.state[k] = s
	}
	return s
}

// Enabled reports whether damping is on.
func (t *Tracker) Enabled() bool { return t != nil && t.cfg.Enabled }

// Decay advances the penalty by dt seconds at time now.  Returns the new
// penalty.  A suppressed prefix that decays below the reuse threshold is
// released here.
func (t *Tracker) Decay(s *State, dt float64, now int64) float64 {
	return t.decay(s, dt, now)
}

func (t *Tracker) decay(s *State, dt float64, now int64) float64 {
	s.lastSeen = now
	if dt <= 0 || s.Penalty <= 0 {
		return s.Penalty
	}
	factor := math.Pow(0.5, dt/t.cfg.HalfLifeSec)
	s.Penalty *= factor
	if s.Penalty < 1 {
		s.Penalty = 0
	}
	if s.Suppressed && s.Penalty < t.cfg.Reuse {
		s.Suppressed = false
		s.ReusedAt = now
	}
	return s.Penalty
}

// Flap records one withdrawal and returns whether the prefix is suppressed.
func (t *Tracker) Flap(s *State, now int64) bool {
	if !t.Enabled() {
		return false
	}
	s.Penalty += t.cfg.PenaltyPerFlap
	if s.Penalty > t.cfg.MaxPenalty {
		s.Penalty = t.cfg.MaxPenalty
	}
	s.Flaps++
	if !s.Suppressed && s.Penalty >= t.cfg.Suppress {
		s.Suppressed = true
		s.SuppressedAt = now
	}
	return s.Suppressed
}

// Suppressed reports whether the pair is currently suppressed.
func (t *Tracker) Suppressed(router, prefix int) bool {
	if !t.Enabled() {
		return false
	}
	s, ok := t.state[key(router, prefix)]
	return ok && s.Suppressed
}

// DecayAll advances every penalty by dt seconds and returns the keys of
// prefixes that were released from suppression, so the simulator can
// recompute them.
func (t *Tracker) DecayAll(dt float64, now int64) []int64 {
	if !t.Enabled() {
		return nil
	}
	var released []int64
	for k, s := range t.state {
		if s.Penalty <= 0 && !s.Suppressed {
			continue
		}
		was := s.Suppressed
		t.decay(s, dt, now)
		if was && !s.Suppressed {
			released = append(released, int64(k))
		}
	}
	return released
}

// Snapshot returns a copy of all states for the UI.
func (t *Tracker) Snapshot() map[string]State {
	out := make(map[string]State, len(t.state))
	for k, v := range t.state {
		out[itoa(uint32(k>>32))+"/"+itoa(uint32(k))] = *v
	}
	return out
}

func itoa(v uint32) string {
	if v == 0 {
		return "0"
	}
	var buf [10]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

// Package clock abstracts time so the simulator can accelerate and jump it.
package clock

import (
	"sync"
	"time"
)

type Clock interface {
	Now() time.Time
}

type Real struct{}

func (Real) Now() time.Time { return time.Now() }

// Sim is an accelerated, jumpable clock for the simulator.
type Sim struct {
	mu       sync.Mutex
	base     time.Time // sim time at lastReal
	lastReal time.Time
	scale    float64
}

func NewSim(start time.Time, scale float64) *Sim {
	return &Sim{base: start, lastReal: time.Now(), scale: scale}
}

func (s *Sim) nowLocked() time.Time {
	elapsed := time.Since(s.lastReal)
	if elapsed < 0 {
		elapsed = 0
	}
	return s.base.Add(time.Duration(float64(elapsed) * s.scale))
}

func (s *Sim) Now() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.nowLocked()
}

// Jump moves the sim clock by d (may be negative) to test clock-skew safety.
func (s *Sim) Jump(d time.Duration) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.base = s.nowLocked().Add(d)
	s.lastReal = time.Now()
}

func (s *Sim) Scale() float64 { return s.scale }

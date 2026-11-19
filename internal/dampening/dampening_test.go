package dampening_test

import (
	"math"
	"testing"

	"bgpsim/internal/dampening"
)

func cfg() dampening.Config {
	return dampening.Config{
		Enabled: true, PenaltyPerFlap: 1000, Suppress: 2000, Reuse: 750,
		HalfLifeSec: 900, MaxPenalty: 12000,
	}
}

func TestSuppressAndReuse(t *testing.T) {
	d := dampening.New(cfg())
	s := d.Get(0, 0)
	if d.Flap(s, 0) {
		t.Fatal("a single flap must not suppress")
	}
	if s.Penalty != 1000 {
		t.Fatalf("penalty %v, want 1000", s.Penalty)
	}
	if !d.Flap(s, 0) {
		t.Fatal("two flaps must reach the suppress threshold")
	}
	if !d.Suppressed(0, 0) {
		t.Fatal("prefix should be suppressed")
	}
}

func TestHalfLifeArithmetic(t *testing.T) {
	d := dampening.New(cfg())
	s := d.Get(0, 0)
	d.Flap(s, 0)
	d.Flap(s, 0) // 2000, suppressed
	// One half-life: 1000, still above reuse (750).
	d.DecayAll(900, 900)
	if math.Abs(s.Penalty-1000) > 1e-6 {
		t.Fatalf("after one half-life penalty is %v, want 1000", s.Penalty)
	}
	if !s.Suppressed {
		t.Fatal("1000 > 750 must stay suppressed")
	}
	// Second half-life: 500, below reuse.
	released := d.DecayAll(900, 1800)
	if s.Suppressed {
		t.Fatal("500 < 750 must be released")
	}
	if len(released) != 1 || released[0] != 0 {
		t.Fatalf("released set %v, want [0]", released)
	}
}

func TestMaxPenaltyClamp(t *testing.T) {
	d := dampening.New(cfg())
	s := d.Get(0, 0)
	for i := 0; i < 100; i++ {
		d.Flap(s, 0)
	}
	if s.Penalty != 12000 {
		t.Fatalf("penalty %v, want the 12000 clamp", s.Penalty)
	}
}

func TestDisabledNeverSuppresses(t *testing.T) {
	c := cfg()
	c.Enabled = false
	d := dampening.New(c)
	s := d.Get(0, 0)
	for i := 0; i < 10; i++ {
		if d.Flap(s, 0) {
			t.Fatal("disabled dampening suppressed a prefix")
		}
	}
	if d.Suppressed(0, 0) {
		t.Fatal("disabled dampening reports suppressed")
	}
}

func TestKeysAreIndependent(t *testing.T) {
	d := dampening.New(cfg())
	a, b := d.Get(0, 1), d.Get(1, 0)
	d.Flap(a, 0)
	d.Flap(a, 0)
	if !d.Suppressed(0, 1) {
		t.Fatal("(0,1) should be suppressed")
	}
	if d.Suppressed(1, 0) {
		t.Fatal("(1,0) was suppressed by the (0,1) flaps")
	}
	_ = b
}

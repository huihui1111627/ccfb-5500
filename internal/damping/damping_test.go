package damping

import (
	"math"
	"testing"
)

func testCfg() Config {
	return Config{Reuse: 750, Suppress: 2000, HalfLifeSec: 900, FlapPenalty: 1000, MaxSuppressSec: 3600}
}

func TestSuppressAndDecay(t *testing.T) {
	tr := NewTracker(testCfg())
	key := "p|peer"
	var suppressed bool
	for i := 1; i <= 3; i++ {
		_, suppressed = tr.Flap(key, float64(i))
	}
	if !suppressed {
		t.Fatal("should be suppressed after penalty crosses threshold")
	}
	// 半衰期衰减：从最后一次翻动时刻 t=3 起经过一个半衰期（到 t=903），
	// 惩罚应约为 3000 的一半。衰减基于浮点幂，给 1% 容差。
	penalty, _ := tr.Penalty(key, 3+900)
	want := 3000.0 * math.Pow(2, -1)
	if math.Abs(penalty-want) > want*0.01 {
		t.Fatalf("decay wrong: want %.1f got %.1f", want, penalty)
	}
	// 足够久后应自动解除抑制。
	released := tr.Tick(3 + 900*10)
	found := false
	for _, k := range released {
		if k == key {
			found = true
		}
	}
	if !found {
		t.Fatal("route not released after decaying below reuse threshold")
	}
}

func TestStableRouteNotPenalized(t *testing.T) {
	tr := NewTracker(testCfg())
	key := "p|peer"
	// 全新路由重新通告不应计罚。
	penalty, suppressed := tr.ReAnnounce(key, 1)
	if penalty != 0 || suppressed {
		t.Fatalf("stable re-announce should not be penalized, got %v/%v", penalty, suppressed)
	}
}

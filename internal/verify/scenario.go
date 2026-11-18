package verify

import (
	"github.com/edu-net/bgpsim/internal/engine"
	"github.com/edu-net/bgpsim/internal/gen"
)

// buildFromScenario 用生成场景的配置构造引擎。
func buildFromScenario(s *gen.Scenario) (*engine.Engine, error) {
	return engine.New(s.Config)
}

package linux

import (
	"errors"
	"testing"

	"github.com/w512/SysRail/internal/providers/providertest"
)

// Examples exercise every Linux capability; shared with the integration test.
var contractExamples = map[string]string{
	"system.status":       `{}`,
	"system.cpu":          `{"per_cpu":true}`,
	"system.memory":       `{}`,
	"system.gpu":          `{}`,
	"storage.status":      `{}`,
	"storage.mounts":      `{"include_pseudo":true}`,
	"network.connections": `{"state":"all"}`,
}

func TestContract(t *testing.T) {
	p := testProvider(t, Options{Statfs: func(string) (FSUsage, error) { return FSUsage{}, errors.New("n/a") }})
	providertest.Run(t, p, providertest.Options{Examples: contractExamples})
}

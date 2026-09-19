package fake_test

import (
	"testing"

	"github.com/w512/SysRail/internal/providers/fake"
	"github.com/w512/SysRail/internal/providers/providertest"
)

func TestContract(t *testing.T) {
	providertest.Run(t, fake.New(), providertest.Options{Examples: map[string]string{
		"fake.status":  `{"value":"x"}`,
		"fake.slow":    `{"millis":1}`,
		"fake.failure": `{"code":"CONFLICT"}`,
		"fake.restart": `{"name":"w"}`,
	}})
}

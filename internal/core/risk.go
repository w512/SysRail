// Package core holds the types shared by every layer of SysRail: capabilities,
// risk levels, structured errors and caller identity.
package core

// Risk classifies the potential impact of a capability (spec §5.4).
type Risk string

const (
	RiskRead     Risk = "read"
	RiskLow      Risk = "low"
	RiskMedium   Risk = "medium"
	RiskHigh     Risk = "high"
	RiskCritical Risk = "critical"
)

// Rank orders risk levels from read (0) to critical (4). Unknown levels return -1.
func (r Risk) Rank() int {
	switch r {
	case RiskRead:
		return 0
	case RiskLow:
		return 1
	case RiskMedium:
		return 2
	case RiskHigh:
		return 3
	case RiskCritical:
		return 4
	}
	return -1
}

// Valid reports whether r is a known risk level.
func (r Risk) Valid() bool { return r.Rank() >= 0 }

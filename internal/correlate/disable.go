package correlate

// DisabledRules is expressed as RuleID values so an invalid id can never
// silently match: config validation (string level) rejects unknown ids before
// they are converted, and a mistyped RuleID constant simply never equals any
// candidate id.
type disableSet map[RuleID]bool

func buildDisableSet(ids []RuleID) disableSet {
	if len(ids) == 0 {
		return nil
	}
	set := make(disableSet, len(ids))
	for _, id := range ids {
		set[id] = true
	}
	return set
}

// disabled reports whether the rule must never fire.
func (d disableSet) disabled(id RuleID) bool { return d != nil && d[id] }

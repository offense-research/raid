// Approval state machine (spec 8.1).
package approval

// Valid transitions from the spec:
//
//	pending -> approved
//	pending -> denied
//	pending -> expired
//	pending -> cancelled
//	pending -> superseded
//	approved -> consumed
//	approved -> expired
var allowed = map[State]map[State]bool{
	StatePending: {
		StateApproved: true, StateDenied: true, StateExpired: true,
		StateCancelled: true, StateSuperseded: true,
	},
	StateApproved: {
		StateConsumed: true, StateExpired: true,
	},
}

// CanTransit reports whether from -> to is a legal transition.
func CanTransit(from, to State) bool {
	if from == to {
		return false
	}
	m, ok := allowed[from]
	if !ok {
		return false
	}
	return m[to]
}

// AllowedTargets lists the legal destinations of a state.
func AllowedTargets(from State) []State {
	m, ok := allowed[from]
	if !ok {
		return nil
	}
	out := []State{}
	for s := range m {
		out = append(out, s)
	}
	return out
}
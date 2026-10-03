// Bounded approval event fanout (spec 15.3).
//
// The hub fans events out to connected SSE subscribers. Slow subscribers
// are dropped rather than allowed to block resolution; they must resume
// from their last sequence via Last-Event-ID.
package stream

import (
	"errors"
	"sync"
	"time"
)

// MaxSubscribers bounds the fanout set (slow TUI clients cannot exhaust the
// daemon).
const MaxSubscribers = 256

// Subscriber receives approval events.
type Subscriber interface {
	// Deliver delivers an event; returning an error disconnects the
	// subscriber (bounded fanout, spec 15.3).
	Deliver(e Event) error
}

// Event is one approval lifecycle notification.
type Event struct {
	Kind       string
	ApprovalID string
	At         time.Time
}

// Hub publishes events to all connected subscribers.
type Hub struct {
	mu   sync.Mutex
	subs []Subscriber
}

// NewHub returns an empty hub.
func NewHub() *Hub {
	return &Hub{}
}

// Subscribe registers a subscriber (bounded).
func (h *Hub) Subscribe(s Subscriber) error {
	h.mu.Lock()
	if len(h.subs) >= MaxSubscribers {
		h.mu.Unlock()
		return errors.New("raid: subscriber limit reached")
	}
	h.subs = append(h.subs, s)
	h.mu.Unlock()
	return nil
}

// Unsubscribe removes a subscriber.
func (h *Hub) Unsubscribe(s Subscriber) {
	h.mu.Lock()
	var out []Subscriber
	for _, x := range h.subs {
		if x == s {
			continue
		}
		out = append(out, x)
	}
	h.subs = out
	h.mu.Unlock()
}

// Publish fans the event to subscribers, dropping failures. Delivery to a
// subscriber must return promptly; the hub itself never blocks.
func (h *Hub) Publish(e Event) {
	h.mu.Lock()
	subs := h.subs
	h.mu.Unlock()
	live := []Subscriber{}
	for _, s := range subs {
		if err := s.Deliver(e); err != nil {
			continue
		}
		live = append(live, s)
	}
	h.mu.Lock()
	h.subs = live
	h.mu.Unlock()
}

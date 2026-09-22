// SSE approval stream (spec 9.6, 15.3).
//
// Each subscriber holds a bounded event queue. A stalled or slow subscriber
// is dropped (its queue fills); reconnect resumes from Last-Event-ID, and a
// full snapshot replaces local state when history is unavailable.
package stream

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"offense.dev/raid/core/canonical"
)

// QueueCap bounds buffered events per subscriber.
const QueueCap = 64

// SseSubscriber is a per-connection event sink.
type SseSubscriber struct {
	mu sync.Mutex
	cv sync.Cond
	q  []Event
}

// NewSseSubscriber creates an empty subscriber.
func NewSseSubscriber() *SseSubscriber {
	return &SseSubscriber{}
}

// Deliver implements Subscriber with a bounded queue.
func (s *SseSubscriber) Deliver(e Event) error {
	s.mu.Lock()
	if len(s.q) >= QueueCap {
		s.mu.Unlock()
		return errors.New("raid: subscriber queue full")
	}
	s.q = append(s.q, e)
	s.cv.Signal()
	s.mu.Unlock()
	return nil
}

// Poll drains queued events (non-blocking). Returns false when none.
func (s *SseSubscriber) Poll() ([]Event, bool) {
	s.mu.Lock()
	if len(s.q) == 0 {
		s.mu.Unlock()
		return nil, false
	}
	out := s.q
	s.q = nil
	s.mu.Unlock()
	return out, true
}

// WriteEvent renders one SSE frame.
func WriteEvent(sb *strings.Builder, e Event) () {
	sb.WriteString("event: ")
	sb.WriteString(e.Kind)
	sb.WriteString("\ndata: {\"id\":")
	canonical.WriteEscaped(sb, e.ApprovalID)
	sb.WriteString(`,"kind":`)
	canonical.WriteEscaped(sb, e.Kind)
	sb.WriteString("}\n\n")
}

// StartStream keeps the SSE response open, emitting events and heartbeats,
// until the client disconnects. seq starts at the client's last seen id.
func StartStream(w http.ResponseWriter, sub *SseSubscriber, seq uint64) () {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Accel-Buffering", "no")
	w.WriteHeader(http.StatusOK)
	last := seq
	lastBeat := time.Now()
	var sb strings.Builder
	for {
		var wrote bool = false
		for ; ; {
			events, ok := sub.Poll()
			if !ok {
				break
			}
			for _, e := range events {
				last++
				sb.WriteString("id: " + fmt.Sprintf("%d", last) + "\n")
				WriteEvent(&sb, e)
				wrote = true
			}
		}
		now := time.Now()
		if !wrote && time.Since(lastBeat) >= 15 * time.Second {
			sb.WriteString(": ping\n\n")
			lastBeat = now
			wrote = true
		}
		if wrote {
			if _, err := w.Write([]byte(sb.String())); err != nil {
				return
			}
			if fl, ok := w.(http.Flusher); ok {
				fl.Flush()
			}
			sb.Reset()
		}
		time.Sleep(1 * time.Second)
	}
}
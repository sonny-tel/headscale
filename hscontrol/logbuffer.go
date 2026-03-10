package hscontrol

import (
	"sync"
	"time"
)

// ConsoleLogBuffer is a global ring buffer that captures zerolog output
// for the web UI console tab.
var ConsoleLogBuffer = NewLogBuffer(2000)

// LogEntry represents a single captured log line.
type LogEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Message   string    `json:"message"`
}

// LogBuffer is a thread-safe ring buffer that captures log output.
type LogBuffer struct {
	mu      sync.Mutex
	entries []LogEntry
	cap     int
	pos     int
	full    bool
}

// NewLogBuffer creates a ring buffer that stores up to cap log entries.
func NewLogBuffer(cap int) *LogBuffer {
	return &LogBuffer{
		entries: make([]LogEntry, cap),
		cap:     cap,
	}
}

// Write implements io.Writer so it can be used as a zerolog output.
// Each Write call is treated as one log line.
func (lb *LogBuffer) Write(p []byte) (n int, err error) {
	lb.mu.Lock()
	lb.entries[lb.pos] = LogEntry{
		Timestamp: time.Now().UTC(),
		Message:   string(p),
	}
	lb.pos = (lb.pos + 1) % lb.cap
	if lb.pos == 0 {
		lb.full = true
	}
	lb.mu.Unlock()
	return len(p), nil
}

// Entries returns the buffered log entries in chronological order.
// If limit > 0, only the last `limit` entries are returned.
func (lb *LogBuffer) Entries(limit int) []LogEntry {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	var result []LogEntry
	if lb.full {
		// Ring has wrapped: read from pos..end then 0..pos
		result = make([]LogEntry, lb.cap)
		copy(result, lb.entries[lb.pos:])
		copy(result[lb.cap-lb.pos:], lb.entries[:lb.pos])
	} else {
		result = make([]LogEntry, lb.pos)
		copy(result, lb.entries[:lb.pos])
	}

	if limit > 0 && len(result) > limit {
		result = result[len(result)-limit:]
	}
	return result
}

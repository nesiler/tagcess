package k8s

import (
	"sync"
	"time"
)

// Clock is a fake clock. Time only moves when the test calls Advance or Set, so threshold and
// freshness tests never sleep. A zero start is allowed; NewClock fixes an explicit one.
type Clock struct {
	mu  sync.Mutex
	now time.Time
}

// NewClock returns a clock stopped at start.
func NewClock(start time.Time) *Clock { return &Clock{now: start} }

// Now returns the clock's current time. Successive calls without Advance or Set return the same
// value.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// Advance moves the clock forward by d. It does not wait.
func (c *Clock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// Set moves the clock to t.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
}

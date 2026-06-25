package portscan

import (
	"sync/atomic"
	"time"

	"github.com/spectre-tool/spectre/internal/utils"
)

// AdaptiveController monitors scan metrics and adjusts the rate limiter dynamically.
// Prevents false negatives caused by ICMP/RST storms or target rate-limiting.
type AdaptiveController struct {
	rl *utils.RateLimiter

	// Counters (atomic)
	totalProbes      int64
	timeouts         int64
	icmpUnreachable  int64
	rstCount         int64
	windowStart      int64 // unix nano

	// Current level 0-3
	level int
	rps   [4]float64 // rates for each level

	lastRecovery int64 // unix nano
}

// NewAdaptiveController creates a controller initialized at the fastest level.
func NewAdaptiveController(rl *utils.RateLimiter, maxRPS float64) *AdaptiveController {
	c := &AdaptiveController{
		rl:          rl,
		windowStart: time.Now().UnixNano(),
		rps: [4]float64{
			maxRPS,          // Level 0: normal
			maxRPS * 0.5,    // Level 1: cautious
			maxRPS * 0.2,    // Level 2: slow
			maxRPS * 0.04,   // Level 3: paranoid
		},
	}
	return c
}

// RecordTimeout records a probe timeout.
func (c *AdaptiveController) RecordTimeout() {
	atomic.AddInt64(&c.timeouts, 1)
	atomic.AddInt64(&c.totalProbes, 1)
	c.maybeAdjust()
}

// RecordICMPUnreachable records receiving an ICMP port-unreachable (UDP scan).
func (c *AdaptiveController) RecordICMPUnreachable() {
	atomic.AddInt64(&c.icmpUnreachable, 1)
	c.maybeAdjust()
}

// RecordSuccess records a successful probe response.
func (c *AdaptiveController) RecordSuccess() {
	atomic.AddInt64(&c.totalProbes, 1)
	c.maybeRecovery()
}

// Level returns the current backoff level (0=normal, 3=paranoid).
func (c *AdaptiveController) Level() int { return c.level }

func (c *AdaptiveController) maybeAdjust() {
	total := atomic.LoadInt64(&c.totalProbes)
	if total < 100 {
		return // not enough samples
	}
	timeouts := atomic.LoadInt64(&c.timeouts)
	icmp := atomic.LoadInt64(&c.icmpUnreachable)

	// Check ICMP rate: Linux kernel limits to ~80/4sec
	elapsed := time.Since(time.Unix(0, atomic.LoadInt64(&c.windowStart))).Seconds()
	icmpRate := float64(icmp) / elapsed

	timeoutRate := float64(timeouts) / float64(total)

	shouldBackoff := icmpRate > 20.0 || timeoutRate > 0.5

	if shouldBackoff && c.level < 3 {
		c.level++
		c.rl.SetRate(c.rps[c.level])
		// Reset window
		atomic.StoreInt64(&c.timeouts, 0)
		atomic.StoreInt64(&c.icmpUnreachable, 0)
		atomic.StoreInt64(&c.totalProbes, 0)
		atomic.StoreInt64(&c.windowStart, time.Now().UnixNano())
	}
}

func (c *AdaptiveController) maybeRecovery() {
	if c.level == 0 {
		return
	}
	// Try to recover after 30s of clean traffic
	now := time.Now().UnixNano()
	last := atomic.LoadInt64(&c.lastRecovery)
	if now-last > int64(30*time.Second) {
		atomic.StoreInt64(&c.lastRecovery, now)
		c.level--
		if c.level < 0 {
			c.level = 0
		}
		c.rl.SetRate(c.rps[c.level])
	}
}

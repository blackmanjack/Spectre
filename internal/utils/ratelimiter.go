package utils

import (
	"context"

	"golang.org/x/time/rate"
)

// RateLimiter wraps golang.org/x/time/rate.Limiter with a context-aware Wait.
type RateLimiter struct {
	limiter *rate.Limiter
}

// NewRateLimiter creates a token-bucket limiter at rps requests/second.
// Pass 0 to disable rate limiting (unlimited).
func NewRateLimiter(rps float64) *RateLimiter {
	if rps <= 0 {
		return &RateLimiter{limiter: rate.NewLimiter(rate.Inf, 1)}
	}
	return &RateLimiter{limiter: rate.NewLimiter(rate.Limit(rps), int(rps)+1)}
}

// Wait blocks until a token is available or ctx is cancelled.
func (r *RateLimiter) Wait(ctx context.Context) error {
	return r.limiter.Wait(ctx)
}

// SetRate updates the rate limit dynamically (used by adaptive controller).
func (r *RateLimiter) SetRate(rps float64) {
	if rps <= 0 {
		r.limiter.SetLimit(rate.Inf)
		return
	}
	r.limiter.SetLimit(rate.Limit(rps))
	r.limiter.SetBurst(int(rps) + 1)
}

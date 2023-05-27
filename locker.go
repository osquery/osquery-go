package osquery

import (
	"context"
	"fmt"
	"time"
)

type locker struct {
	c              chan struct{}
	defaultTimeout time.Duration
	maxWait        time.Duration
}

func NewLocker(defaultTimeout time.Duration, maxWait time.Duration) *locker {
	return &locker{
		c:              make(chan struct{}, 1),
		defaultTimeout: defaultTimeout,
		maxWait:        maxWait,
	}
}

func (l *locker) Lock(ctx context.Context) error {

	// Assume most callers have set a deadline on the context, and start this as being the max allowed wait time
	wait := l.maxWait
	timeoutError := "timeout after maximum of %s"

	// If the caller has not set a deadline, use the default.
	if _, ok := ctx.Deadline(); !ok {
		wait = l.defaultTimeout
		timeoutError = "timeout after %s"

	}

	// Block until we get the lock, the context is canceled, or we time out.
	select {
	case l.c <- struct{}{}:
		// lock acquired
		return nil
	case <-ctx.Done():
		// context has been canceled
		return fmt.Errorf("context canceled: %w", ctx.Err())
	case <-time.After(wait):
		// timed out
		return fmt.Errorf(timeoutError, wait)
	}
}

func (l *locker) Unlock() {
	<-l.c
}

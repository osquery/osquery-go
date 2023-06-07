package osquery

import (
	"context"
	"fmt"
	"time"
)

// locker uses go channels to create a lock mechanism. We use channels, and not the more common mutexes, because the
// latter cannot be interrupted. This allows callers to timeout without blocking on the mutex.
//
// We need _some_ lock mechanism because the underlying thrift socket only allows a single actor at a time. If two
// goroutines are trying to use the socket at the same time, they will get protocol errors.
type locker struct {
	c              chan struct{}
	defaultTimeout time.Duration // Default wait time is used if context does not have a deadline
	maxWait        time.Duration // Maximum time something is allowed to wait
}

func NewLocker(defaultTimeout time.Duration, maxWait time.Duration) *locker {
	return &locker{
		c:              make(chan struct{}, 1),
		defaultTimeout: defaultTimeout,
		maxWait:        maxWait,
	}
}

// Lock attempts to lock l. It will wait for the shorter of (ctx deadline | defaultTimeout) and maxWait.
func (l *locker) Lock(ctx context.Context) error {
	// Assume most callers have set a deadline on the context, and start this as being the max allowed wait time
	wait := l.maxWait
	timeoutError := "timeout after maximum of %s"

	// If the caller has not set a deadline, use the default.
	if _, ok := ctx.Deadline(); !ok {
		wait = l.defaultTimeout
		timeoutError = "timeout after %s"

	}

	timeout := time.NewTimer(wait)
	defer timeout.Stop()

	// Block until we get the lock, the context is canceled, or we time out.
	select {
	case l.c <- struct{}{}:
		// lock acquired
		return nil
	case <-ctx.Done():
		// context has been canceled
		return fmt.Errorf("context canceled: %w", ctx.Err())
	case <-timeout.C:
		// timed out
		return fmt.Errorf(timeoutError, wait)
	}
}

// Unlock unlocks l. It is a runtime error to unlock an unlocked locker.
func (l *locker) Unlock() {
	select {
	case <-l.c:
		return
	default:
		// Calling Unlock on an unlocked mutex is a fatal error. We mirror that behavior here.
		panic("unlock of unlocked locker")
	}

}

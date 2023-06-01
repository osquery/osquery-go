package osquery

import (
	"context"
	"math/rand"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestLocker(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name               string
		sleepTime          time.Duration
		ctxTimeout         time.Duration
		parallelism        int
		expectedSuccesses  int
		expectedErrorCount int
		expectedErrors     []string
	}{
		{
			name:              "basic",
			sleepTime:         1 * time.Millisecond,
			ctxTimeout:        10 * time.Millisecond,
			parallelism:       5,
			expectedSuccesses: 5,
		},
		{
			name:               "some finishers",
			sleepTime:          4 * time.Millisecond,
			ctxTimeout:         10 * time.Millisecond,
			parallelism:        5,
			expectedSuccesses:  3,
			expectedErrorCount: 2,
		},
		{
			name:               "sleep longer than context",
			sleepTime:          150 * time.Millisecond,
			ctxTimeout:         10 * time.Millisecond,
			parallelism:        5,
			expectedSuccesses:  1,
			expectedErrorCount: 4,
			expectedErrors:     []string{"context canceled: context deadline exceeded"},
		},
		{
			name:               "no ctx fall back to default timeout",
			sleepTime:          150 * time.Millisecond,
			parallelism:        5,
			expectedSuccesses:  1,
			expectedErrorCount: 4,
			expectedErrors:     []string{"timeout after 100ms"},
		},
		{
			name:               "ctx longer than maxwait",
			sleepTime:          250 * time.Millisecond,
			ctxTimeout:         10 * time.Second,
			parallelism:        5,
			expectedSuccesses:  1,
			expectedErrorCount: 4,
			expectedErrors:     []string{"timeout after maximum of 200ms"},
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			doer := NewThingDoer()

			wait := sync.WaitGroup{}
			for i := 0; i < tt.parallelism; i++ {
				wait.Add(1)
				go func() {
					defer wait.Done()

					ctx := context.TODO()
					if tt.ctxTimeout != 0 {
						var cancel context.CancelFunc
						ctx, cancel = context.WithTimeout(ctx, tt.ctxTimeout)
						defer cancel()
					}

					_ = doer.Once(ctx, tt.sleepTime)
				}()
			}

			wait.Wait()

			assert.Equal(t, tt.expectedSuccesses, doer.Successes)
			assert.Equal(t, tt.expectedErrorCount, len(doer.Errors))

			for _, errMsg := range tt.expectedErrors {
				assert.Contains(t, doer.Errors, errMsg)
			}
		})
	}
}

func TestNeedlessUnlock(t *testing.T) {
	t.Parallel()

	locker := NewLocker(100*time.Millisecond, 200*time.Millisecond)

	wait := sync.WaitGroup{}
	wait.Add(1)
	go func() {
		locker.Unlock()
		defer wait.Done()
	}()

	wait.Wait()
}

func TestDoubleUnlock(t *testing.T) {
	t.Parallel()

	locker := NewLocker(100*time.Millisecond, 200*time.Millisecond)

	require.NoError(t, locker.Lock(context.TODO()))
	locker.Unlock()
	locker.Unlock()
}

func TestLockerChaos(t *testing.T) {
	t.Parallel()

	doer := NewThingDoer()

	wait := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()

			ctx := context.TODO()
			if rand.Intn(100) > 20 {
				var cancel context.CancelFunc
				ctx, cancel = context.WithTimeout(ctx, time.Duration(rand.Intn(500))*time.Millisecond)
				defer cancel()
			}

			_ = doer.Once(ctx, time.Duration(rand.Intn(100))*time.Millisecond)
		}()
	}
	wait.Wait()

	assert.GreaterOrEqual(t, doer.Successes, 1, "successes")
	assert.GreaterOrEqual(t, len(doer.Errors), 1, "failures")

}

type thingDoer struct {
	locker    *locker
	Successes int
	Errors    []string
	errMu     sync.Mutex
}

func NewThingDoer() *thingDoer {
	return &thingDoer{
		locker: NewLocker(100*time.Millisecond, 200*time.Millisecond),
		Errors: make([]string, 0),
	}
}

func (doer *thingDoer) Once(ctx context.Context, d time.Duration) error {
	if err := doer.locker.Lock(ctx); err != nil {
		doer.errMu.Lock()
		defer doer.errMu.Unlock()

		doer.Errors = append(doer.Errors, err.Error())
		return err
	}
	defer doer.locker.Unlock()

	// Note that we don't need to protect the success path with a mutext, that is the point of locker
	time.Sleep(d)
	doer.Successes += 1

	return nil
}

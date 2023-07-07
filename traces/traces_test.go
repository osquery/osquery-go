package traces

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestTraceInit(t *testing.T) {
	t.Parallel()

	// Start several spans in quick succession to confirm there's no data race on setting `internalVersion`
	var wg sync.WaitGroup
	for i := 0; i < 5; i += 1 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, span := StartSpan(context.TODO(), "TestSpan")
			span.End()
		}()
	}

	wg.Wait()
	assert.NotEmpty(t, internalVersion, "internal version should have been set")
}

package osquery

import (
	"context"
	"errors"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/osquery/osquery-go/gen/osquery"
	"github.com/osquery/osquery-go/mock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestQueryRows(t *testing.T) {
	t.Parallel()
	mock := &mock.ExtensionManager{}
	client, err := NewClient("", 5*time.Second, WithOsqueryThriftClient(mock))
	require.NoError(t, err)

	// Transport related error
	mock.QueryFunc = func(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
		return nil, errors.New("boom!")
	}
	rows, err := client.QueryRows("select 1")
	assert.NotNil(t, err)
	row, err := client.QueryRow("select 1")
	assert.NotNil(t, err)

	// Nil status
	mock.QueryFunc = func(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
		return &osquery.ExtensionResponse{}, nil
	}
	rows, err = client.QueryRows("select 1")
	assert.NotNil(t, err)
	row, err = client.QueryRow("select 1")
	assert.NotNil(t, err)

	// Query error
	mock.QueryFunc = func(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
		return &osquery.ExtensionResponse{
			Status: &osquery.ExtensionStatus{Code: 1, Message: "bad query"},
		}, nil
	}
	rows, err = client.QueryRows("select bad query")
	assert.NotNil(t, err)
	row, err = client.QueryRow("select bad query")
	assert.NotNil(t, err)

	// Good query (one row)
	expectedRows := []map[string]string{
		{"1": "1"},
	}
	mock.QueryFunc = func(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
		return &osquery.ExtensionResponse{
			Status:   &osquery.ExtensionStatus{Code: 0, Message: "OK"},
			Response: expectedRows,
		}, nil
	}
	rows, err = client.QueryRows("select 1")
	assert.Nil(t, err)
	assert.Equal(t, expectedRows, rows)
	row, err = client.QueryRow("select 1")
	assert.Nil(t, err)
	assert.Equal(t, expectedRows[0], row)

	// Good query (multiple rows)
	expectedRows = []map[string]string{
		{"1": "1"},
		{"1": "2"},
	}
	mock.QueryFunc = func(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
		return &osquery.ExtensionResponse{
			Status:   &osquery.ExtensionStatus{Code: 0, Message: "OK"},
			Response: expectedRows,
		}, nil
	}
	rows, err = client.QueryRows("select 1 union select 2")
	assert.Nil(t, err)
	assert.Equal(t, expectedRows, rows)
	row, err = client.QueryRow("select 1 union select 2")
	assert.NotNil(t, err)
}

// TestLocking tests the the client correctly locks access to the osquery socket. Thrift only supports a single
// actor on the socket at a time, this means that in parallel go code, it's very easy to have messages get
// crossed and generate errors. This tests to ensure the locking works
func TestLocking(t *testing.T) {
	t.Parallel()

	sock := os.Getenv("OSQ_SOCKET")
	if sock == "" {
		t.Skip("no osquery socket specified")
	}

	osq, err := NewClient(sock, 5*time.Second)
	require.NoError(t, err)

	// The issue we're testing is about multithreaded access. Let's hammer on it!
	wait := sync.WaitGroup{}
	for i := 0; i < 100; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()

			status, err := osq.Ping()
			require.NoError(t, err, "call to Ping()")
			if err != nil {
				require.Equal(t, 0, status.Code, fmt.Errorf("ping returned %d: %s", status.Code, status.Message))
			}
		}()
	}

	wait.Wait()
}

func TestLockTimeouts(t *testing.T) {
	t.Parallel()
	mock := &mock.ExtensionManager{}
	client, err := NewClient("", 5*time.Second, WithOsqueryThriftClient(mock), DefaultWaitTime(100*time.Millisecond), DefaultWaitTime(5*time.Second))
	require.NoError(t, err)

	wait := sync.WaitGroup{}

	errChan := make(chan error, 10)
	for i := 0; i < 3; i++ {
		wait.Add(1)
		go func() {
			defer wait.Done()

			ctx, cancel := context.WithTimeout(context.TODO(), 100*time.Millisecond)
			defer cancel()

			errChan <- client.SlowLocker(ctx, 75*time.Millisecond)
		}()
	}

	wait.Wait()
	close(errChan)

	var successCount, errCount int
	for err := range errChan {
		if err == nil {
			successCount += 1
		} else {
			errCount += 1
		}
	}

	assert.Equal(t, 2, successCount, "expected success count")
	assert.Equal(t, 1, errCount, "expected error count")
}

// WithOsqueryThriftClient sets the underlying thrift client. This can be used to set a mock
func WithOsqueryThriftClient(client osquery.ExtensionManager) ClientOption {
	return func(c *ExtensionManagerClient) {
		c.client = client
	}
}

// SlowLocker attempts to emulate a slow sql routine, so we can test how lock timeouts work.
func (c *ExtensionManagerClient) SlowLocker(ctx context.Context, d time.Duration) error {
	if err := c.lock.Lock(ctx); err != nil {
		return err
	}
	defer c.lock.Unlock()
	time.Sleep(d)
	return nil
}

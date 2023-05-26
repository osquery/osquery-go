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
	client := &ExtensionManagerClient{Client: mock}

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

// TestLocking tests the the client correctly locks access to the osquery socket. Thrift only support a single
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
	for i := 0; i < 20; i++ {
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

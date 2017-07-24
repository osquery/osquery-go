package osquery

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"git.apache.org/thrift.git/lib/go/thrift"

	"github.com/kolide/osquery-go/gen/osquery"
	"github.com/kolide/osquery-go/plugin/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verify that an error in server.Start will return an error instead of deadlock.
func TestNoDeadlockOnError(t *testing.T) {
	registry := make(map[string](map[string]OsqueryPlugin))
	for reg, _ := range validRegistryNames {
		registry[reg] = make(map[string]OsqueryPlugin)
	}
	mut := sync.Mutex{}
	mock := &MockExtensionManager{
		RegisterExtensionFunc: func(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
			mut.Lock()
			defer mut.Unlock()
			return nil, errors.New("boom!")
		},
	}
	server := &ExtensionManagerServer{
		serverClient: mock,
		registry:     registry,
	}

	log := func(ctx context.Context, typ logger.LogType, logText string) error {
		fmt.Printf("%s: %s\n", typ, logText)
		return nil
	}
	server.RegisterPlugin(logger.NewPlugin("testLogger", log))

	err := server.Run()
	assert.NotNil(t, err)
	mut.Lock()
	defer mut.Unlock()
	assert.True(t, mock.RegisterExtensionFuncInvoked)
}

// How many parallel tests to run (because sync issues do not occur on every
// run, this maximizes our chances of seeing any issue by quickly executing
// many runs of the test).
const parallelTestShutdownDeadlock = 20

func TestShutdownDeadlock(t *testing.T) {
	for i := 0; i < parallelTestShutdownDeadlock; i++ {
		t.Run("", func(t *testing.T) {
			t.Parallel()
			testShutdownDeadlock(t)
		})
	}
}
func testShutdownDeadlock(t *testing.T) {
	tempPath, err := ioutil.TempFile("", "")
	require.Nil(t, err)
	defer os.Remove(tempPath.Name())

	retUUID := osquery.ExtensionRouteUUID(0)
	mock := &MockExtensionManager{
		RegisterExtensionFunc: func(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
			return &osquery.ExtensionStatus{Code: 0, UUID: retUUID}, nil
		},
	}
	server := ExtensionManagerServer{serverClient: mock, sockPath: tempPath.Name()}
	go func() {
		err := server.Start()
		require.Nil(t, err)
	}()
	// Sleep long enough for server to start listening on socket
	time.Sleep(500 * time.Millisecond)

	// Create a raw client to access the shutdown method that is not
	// usually exposed.
	listenPath := fmt.Sprintf("%s.%d", tempPath.Name(), retUUID)
	addr, err := net.ResolveUnixAddr("unix", listenPath)
	require.Nil(t, err)
	timeout := 500 * time.Millisecond
	trans := thrift.NewTSocketFromAddrTimeout(addr, timeout)
	err = trans.Open()
	require.Nil(t, err)
	client := osquery.NewExtensionManagerClientFactory(trans,
		thrift.NewTBinaryProtocolFactoryDefault())

	// Simultaneously call shutdown through a request from the client and
	// directly on the server object.
	wait := sync.WaitGroup{}
	wait.Add(1)
	go func() {
		defer wait.Done()
		client.Shutdown()
	}()

	wait.Add(1)
	go func() {
		defer wait.Done()
		err = server.Shutdown()
		require.Nil(t, err)
	}()

	// Track whether shutdown completed
	completed := make(chan struct{})
	go func() {
		wait.Wait()
		close(completed)
	}()

	// Either indicate successful shutdown, or fatal the test because it
	// hung
	select {
	case <-completed:
		// Success. Do nothing.
	case <-time.After(5 * time.Second):
		t.Fatal("hung on shutdown")
	}
}

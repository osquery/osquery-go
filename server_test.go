package osquery

import (
	"context"
	"errors"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/osquery/osquery-go/gen/osquery"
	"github.com/osquery/osquery-go/plugin/logger"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Verify that an error in server.Start will return an error instead of deadlock.
func TestNoDeadlockOnError(t *testing.T) {
	registry := make(map[string](map[string]OsqueryPlugin))
	for reg := range validRegistryNames {
		registry[reg] = make(map[string]OsqueryPlugin)
	}
	mut := sync.Mutex{}
	mock := &MockExtensionManager{
		RegisterExtensionFunc: func(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
			mut.Lock()
			defer mut.Unlock()
			return nil, errors.New("boom!")
		},
		PingFunc: func() (*osquery.ExtensionStatus, error) {
			return &osquery.ExtensionStatus{}, nil
		},
		DeRegisterExtensionFunc: func(uuid osquery.ExtensionRouteUUID) (*osquery.ExtensionStatus, error) {
			return &osquery.ExtensionStatus{}, nil
		},
		CloseFunc: func() {},
	}
	server := &ExtensionManagerServer{
		serverClient:               mock,
		registry:                   registry,
		serverClientShouldShutdown: true,
	}

	log := func(ctx context.Context, typ logger.LogType, logText string) error {
		fmt.Printf("%s: %s\n", typ, logText)
		return nil
	}
	server.RegisterPlugin(logger.NewPlugin("testLogger", log))

	err := server.Run()
	assert.Error(t, err)
	mut.Lock()
	defer mut.Unlock()
	assert.True(t, mock.RegisterExtensionFuncInvoked)
}

// Ensure that the extension server will shutdown and return if the osquery
// instance it is talking to stops responding to pings.
func TestShutdownWhenPingFails(t *testing.T) {
	tempPath, err := ioutil.TempFile("", "")
	require.Nil(t, err)
	defer os.Remove(tempPath.Name())

	registry := make(map[string](map[string]OsqueryPlugin))
	for reg := range validRegistryNames {
		registry[reg] = make(map[string]OsqueryPlugin)
	}
	mock := &MockExtensionManager{
		RegisterExtensionFunc: func(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
			return &osquery.ExtensionStatus{}, nil
		},
		PingFunc: func() (*osquery.ExtensionStatus, error) {
			// As if the socket was closed
			return nil, syscall.EPIPE
		},
		DeRegisterExtensionFunc: func(uuid osquery.ExtensionRouteUUID) (*osquery.ExtensionStatus, error) {
			return &osquery.ExtensionStatus{}, nil
		},
		CloseFunc: func() {},
	}
	server := &ExtensionManagerServer{
		serverClient:               mock,
		registry:                   registry,
		serverClientShouldShutdown: true,
		pingInterval:               1 * time.Second,
		sockPath:                   tempPath.Name(),
	}

	err = server.Run()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "broken pipe")
	assert.True(t, mock.DeRegisterExtensionFuncInvoked)
	assert.True(t, mock.CloseFuncInvoked)
}

// How many parallel tests to run (because sync issues do not occur on every
// run, this maximizes our chances of seeing any issue by quickly executing
// many runs of the test).
const parallelTestShutdownDeadlock = 20

func TestShutdownDeadlock(t *testing.T) {
	for i := 0; i < parallelTestShutdownDeadlock; i++ {
		i := i
		t.Run("", func(t *testing.T) {
			t.Parallel()
			testShutdownDeadlock(t, i)
		})
	}
}

func testShutdownDeadlock(t *testing.T, uuid int) {
	tempPath, err := ioutil.TempFile("", "")
	require.Nil(t, err)
	defer os.Remove(tempPath.Name())

	retUUID := osquery.ExtensionRouteUUID(uuid)
	mock := &MockExtensionManager{
		RegisterExtensionFunc: func(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
			return &osquery.ExtensionStatus{Code: 0, UUID: retUUID}, nil
		},
		DeRegisterExtensionFunc: func(uuid osquery.ExtensionRouteUUID) (*osquery.ExtensionStatus, error) {
			return &osquery.ExtensionStatus{}, nil
		},
		CloseFunc: func() {},
	}
	server := ExtensionManagerServer{
		serverClient:               mock,
		sockPath:                   tempPath.Name(),
		timeout:                    defaultTimeout,
		serverClientShouldShutdown: true,
	}

	var wait sync.WaitGroup

	go func() {
		// We do not wait for this routine to finish because thrift.TServer.Serve
		// seems to sometimes hang after shutdowns. (This test is just testing
		// the Shutdown doesn't hang.)
		err := server.Start()
		require.NoError(t, err)
	}()

	// Wait for server to be set up
	server.waitStarted()

	// Create a raw client to access the shutdown method that is not
	// usually exposed.
	listenPath := fmt.Sprintf("%s.%d", tempPath.Name(), retUUID)
	addr, err := net.ResolveUnixAddr("unix", listenPath)
	require.Nil(t, err)
	timeout := 500 * time.Millisecond
	opened := false
	attempt := 0
	var transport *thrift.TSocket
	for !opened && attempt < 10 {
		transport = thrift.NewTSocketFromAddrTimeout(addr, timeout, timeout)
		err = transport.Open()
		attempt++
		if err != nil {
			time.Sleep(1 * time.Second)
		} else {
			opened = true
		}
	}
	require.NoError(t, err)
	client := osquery.NewExtensionManagerClientFactory(transport,
		thrift.NewTBinaryProtocolFactoryDefault())

	// Simultaneously call shutdown through a request from the client and
	// directly on the server object.
	wait.Add(1)
	go func() {
		defer wait.Done()
		client.Shutdown(context.Background())
	}()

	wait.Add(1)
	go func() {
		defer wait.Done()
		err = server.Shutdown(context.Background())
		require.NoError(t, err)
	}()

	// Track whether shutdown completed
	completed := make(chan struct{})
	go func() {
		wait.Wait()
		close(completed)
	}()

	// either indicate successful shutdown, or fatal the test because it
	// hung
	select {
	case <-completed:
		// Success. Do nothing.
	case <-time.After(10 * time.Second):
		pprof.Lookup("goroutine").WriteTo(os.Stdout, 1)
		t.Fatal("hung on shutdown")
	}
}

func TestShutdownBasic(t *testing.T) {
	dir := t.TempDir()

	tempPath := func() string {
		tmp, err := os.CreateTemp(dir, "")
		require.NoError(t, err)
		return tmp.Name()
	}

	retUUID := osquery.ExtensionRouteUUID(0)
	mock := &MockExtensionManager{
		RegisterExtensionFunc: func(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
			return &osquery.ExtensionStatus{Code: 0, UUID: retUUID}, nil
		},
		DeRegisterExtensionFunc: func(uuid osquery.ExtensionRouteUUID) (*osquery.ExtensionStatus, error) {
			return &osquery.ExtensionStatus{}, nil
		},
		CloseFunc: func() {},
	}

	for _, server := range []*ExtensionManagerServer{
		// Create the extension manager without using NewExtensionManagerServer.
		{serverClient: mock, sockPath: tempPath()},
		// Create the extension manager using ExtensionManagerServer.
		{serverClient: mock, sockPath: tempPath(), serverClientShouldShutdown: true},
	} {
		completed := make(chan struct{})
		go func() {
			err := server.Start()
			require.NoError(t, err)
			close(completed)
		}()

		server.waitStarted()

		err := server.Shutdown(context.Background())
		require.NoError(t, err)

		// Test that server.Shutdown is idempotent.
		err = server.Shutdown(context.Background())
		require.NoError(t, err)

		// Either indicate successful shutdown, or fatal the test because it
		// hung
		select {
		case <-completed:
			// Success. Do nothing.
		case <-time.After(5 * time.Second):
			t.Fatal("hung on shutdown")
		}

	}
}

func TestNewExtensionManagerServer(t *testing.T) {
	t.Parallel()

	type args struct {
		name     string
		sockPath string
		opts     []ServerOption
	}
	tests := []struct {
		name           string
		args           args
		want           *ExtensionManagerServer
		errContainsStr string
	}{
		{
			name: "socket path too long",
			args: args{
				name:     "socket_path_too_long",
				sockPath: strings.Repeat("a", MaxSocketPathCharacters+1),
				opts:     []ServerOption{},
			},
			errContainsStr: "exceeded the maximum socket path character length",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := NewExtensionManagerServer(tt.args.name, tt.args.sockPath, tt.args.opts...)
			if tt.errContainsStr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), tt.errContainsStr)
			} else {
				require.NoError(t, err)
				require.NotNil(t, got)
			}
		})
	}
}

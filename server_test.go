package osquery

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/kolide/osquery-go/gen/osquery"
	"github.com/kolide/osquery-go/plugin/logger"
	"github.com/stretchr/testify/assert"
)

type mockExtensionClient struct {
	mut    sync.Mutex
	called bool
}

func (me *mockExtensionClient) Close() {
	panic("not implemented")
}

func (me *mockExtensionClient) Ping() (*osquery.ExtensionStatus, error) {
	panic("not implemented")
}

func (me *mockExtensionClient) Call(registry string, item string, req osquery.ExtensionPluginRequest) (*osquery.ExtensionResponse, error) {
	panic("not implemented")
}

func (me *mockExtensionClient) Extensions() (osquery.InternalExtensionList, error) {
	panic("not implemented")
}

func (me *mockExtensionClient) RegisterExtension(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
	me.mut.Lock()
	defer me.mut.Unlock()
	me.called = true
	return nil, errors.New("boom!")
}

func (me *mockExtensionClient) Options() (osquery.InternalOptionList, error) {
	panic("not implemented")
}

func (me *mockExtensionClient) Query(sql string) (*osquery.ExtensionResponse, error) {
	panic("not implemented")
}

func (me *mockExtensionClient) GetQueryColumns(sql string) (*osquery.ExtensionResponse, error) {
	panic("not implemented")
}

func LogMe(ctx context.Context, typ logger.LogType, logText string) error {
	fmt.Printf("%s: %s\n", typ, logText)
	return nil
}

// Verify that an error in server.Start will return an error instead of deadlock.
func TestNoDeadlockOnError(t *testing.T) {
	registry := make(map[string](map[string]OsqueryPlugin))
	for reg, _ := range validRegistryNames {
		registry[reg] = make(map[string]OsqueryPlugin)
	}
	mock := new(mockExtensionClient)
	server := &ExtensionManagerServer{
		serverClient: mock,
		registry:     registry,
	}
	server.RegisterPlugin(logger.NewPlugin("testLogger", LogMe))
	err := server.Run()
	assert.NotNil(t, err)
	mock.mut.Lock()
	defer mock.mut.Unlock()
	assert.True(t, mock.called)
}

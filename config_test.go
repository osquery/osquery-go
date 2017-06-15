package osquery

import (
	"context"
	"errors"
	"testing"

	"github.com/kolide/osquery-golang/gen/osquery"
	"github.com/stretchr/testify/assert"
)

// Ensure configPluginImpl implements the OsqueryPlugin interface.
var _ OsqueryPlugin = (*configPluginImpl)(nil)

type mockConfigPlugin struct {
	NameFunc            func() string
	GenerateConfigsFunc func(context.Context) (map[string]string, error)
}

func (m *mockConfigPlugin) Name() string {
	return m.NameFunc()
}

func (m *mockConfigPlugin) GenerateConfigs(ctx context.Context) (map[string]string, error) {
	return m.GenerateConfigsFunc(ctx)
}

func TestConfigPlugin(t *testing.T) {
	var called bool
	plugin := NewConfigPlugin(
		&mockConfigPlugin{
			NameFunc: func() string {
				return "mock"
			},
			GenerateConfigsFunc: func(context.Context) (map[string]string, error) {
				called = true
				return map[string]string{
					"conf1": "foobar",
				}, nil
			},
		},
	)

	// Basic methods
	assert.Equal(t, "config", plugin.RegistryName())
	assert.Equal(t, "mock", plugin.Name())
	assert.Equal(t, StatusOK, plugin.Ping())
	assert.Equal(t, osquery.ExtensionPluginResponse{}, plugin.Routes())

	// Call with good action
	resp := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "genConfig"})
	assert.True(t, called)
	assert.Equal(t, &StatusOK, resp.Status)
	assert.Equal(t, osquery.ExtensionPluginResponse{{"conf1": "foobar"}}, resp.Response)
}

func TestConfigPluginErrors(t *testing.T) {
	var called bool
	plugin := NewConfigPlugin(
		&mockConfigPlugin{
			NameFunc: func() string {
				return "mock"
			},
			GenerateConfigsFunc: func(context.Context) (map[string]string, error) {
				called = true
				return nil, errors.New("foobar")
			},
		},
	)

	// Call with bad actions
	assert.Equal(t, int32(1), plugin.Call(context.Background(), osquery.ExtensionPluginRequest{}).Status.Code)
	assert.False(t, called)
	assert.Equal(t, int32(1), plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "bad"}).Status.Code)
	assert.False(t, called)

	// Call with good action but generate fails
	resp := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "genConfig"})
	assert.True(t, called)
	assert.Equal(t, int32(1), resp.Status.Code)
	assert.Equal(t, "error getting config: foobar", resp.Status.Message)
}

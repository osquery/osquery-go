package config

import (
	"context"
	"errors"
	"testing"

	"github.com/kolide/osquery-go/gen/osquery"
	"github.com/stretchr/testify/assert"
)

var StatusOK = osquery.ExtensionStatus{Code: 0, Message: "OK"}

func TestConfigPlugin(t *testing.T) {
	var called bool
	plugin := NewPlugin("mock", func(context.Context) (map[string]string, error) {
		called = true
		return map[string]string{
			"conf1": "foobar",
		}, nil
	})

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
	plugin := NewPlugin("mock", func(context.Context) (map[string]string, error) {
		called = true
		return nil, errors.New("foobar")
	})

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

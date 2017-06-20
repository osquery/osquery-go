package logger

import (
	"context"
	"errors"
	"testing"

	"github.com/kolide/osquery-go/gen/osquery"
	"github.com/stretchr/testify/assert"
)

type mockLoggerPlugin struct {
	NameFunc      func() string
	LogStringFunc func(context.Context, LogType, string) error
}

func (m *mockLoggerPlugin) Name() string {
	return m.NameFunc()
}

func (m *mockLoggerPlugin) LogString(ctx context.Context, typ LogType, log string) error {
	return m.LogStringFunc(ctx, typ, log)
}

func TestLoggerPlugin(t *testing.T) {
	var calledType LogType
	var calledLog string
	plugin := NewPlugin("mock", func(ctx context.Context, typ LogType, log string) error {
		calledType = typ
		calledLog = log
		return nil
	})

	StatusOK := osquery.ExtensionStatus{Code: 0, Message: "OK"}
	// Basic methods
	assert.Equal(t, "logger", plugin.RegistryName())
	assert.Equal(t, "mock", plugin.Name())
	assert.Equal(t, StatusOK, plugin.Ping())
	assert.Equal(t, osquery.ExtensionPluginResponse{}, plugin.Routes())

	// Log string
	resp := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"string": "logged string"})
	assert.Equal(t, &StatusOK, resp.Status)
	assert.Equal(t, LogTypeString, calledType)
	assert.Equal(t, "logged string", calledLog)

	// Log snapshot
	resp = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"snapshot": "logged snapshot"})
	assert.Equal(t, &StatusOK, resp.Status)
	assert.Equal(t, LogTypeSnapshot, calledType)
	assert.Equal(t, "logged snapshot", calledLog)

	// Log health
	resp = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"health": "logged health"})
	assert.Equal(t, &StatusOK, resp.Status)
	assert.Equal(t, LogTypeHealth, calledType)
	assert.Equal(t, "logged health", calledLog)

	// Log init
	resp = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"init": "logged init"})
	assert.Equal(t, &StatusOK, resp.Status)
	assert.Equal(t, LogTypeInit, calledType)
	assert.Equal(t, "logged init", calledLog)

	// Log status
	resp = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"status": "true", "log": `{"":{"s":"0","f":"events.cpp","i":"828","m":"Event publisher failed setup: kernel: Cannot access \/dev\/osquery"},"":{"s":"0","f":"events.cpp","i":"828","m":"Event publisher failed setup: scnetwork: Publisher not used"},"":{"s":"0","f":"scheduler.cpp","i":"74","m":"Executing scheduled query macos_kextstat: SELECT * FROM time"}}`})
	assert.Equal(t, &StatusOK, resp.Status)
	assert.Equal(t, LogTypeStatus, calledType)
	assert.Equal(t, `{"s":"0","f":"scheduler.cpp","i":"74","m":"Executing scheduled query macos_kextstat: SELECT * FROM time"}`, calledLog)
}

func TestLogPluginErrors(t *testing.T) {
	var called bool
	plugin := NewPlugin("mock", func(ctx context.Context, typ LogType, log string) error {
		called = true
		return errors.New("foobar")
	})

	// Call with bad actions
	assert.Equal(t, int32(1), plugin.Call(context.Background(), osquery.ExtensionPluginRequest{}).Status.Code)
	assert.False(t, called)
	assert.Equal(t, int32(1), plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "bad"}).Status.Code)
	assert.False(t, called)

	// Call with empty status
	assert.Equal(t, int32(1), plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"status": "true", "log": ""}).Status.Code)
	assert.False(t, called)

	// Call with good action but logging fails
	resp := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"string": "logged string"})
	assert.True(t, called)
	assert.Equal(t, int32(1), resp.Status.Code)
	assert.Equal(t, "error logging: foobar", resp.Status.Message)
}

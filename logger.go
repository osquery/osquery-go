package osquery

import (
	"context"

	"github.com/kolide/osquery-go/gen/osquery"
)

// LoggerPlugin is the minimum interface required to implement an osquery
// logger plugin. Any value that implements this interface can be passed to
// NewLoggerPlugin to satisfy the full OsqueryPlugin interface.
type LoggerPlugin interface {
	// Name returns the name of the logger plugin.
	Name() string

	// LogString should log the provided result string. The LogType
	// argument can be optionally used to log differently depending on the
	// type of log received. The context argument can optionally be used
	// for cancellation in long-running operations.
	LogString(ctx context.Context, typ LogType, log string) error
}

// NewLoggerPlugin takes a value that implements LoggerPlugin and wraps it with
// the appropriate methods to satisfy the OsqueryPlugin interface. Use this to
// easily create plugins implementing osquery tables.
func NewLoggerPlugin(plugin LoggerPlugin) *loggerPluginImpl {
	return &loggerPluginImpl{plugin}
}

type loggerPluginImpl struct {
	plugin LoggerPlugin
}

func (t *loggerPluginImpl) Name() string {
	return t.plugin.Name()
}

func (t *loggerPluginImpl) RegistryName() string {
	return "logger"
}

func (t *loggerPluginImpl) Routes() osquery.ExtensionPluginResponse {
	return []map[string]string{}
}

func (t *loggerPluginImpl) Ping() osquery.ExtensionStatus {
	return StatusOK
}

func (t *loggerPluginImpl) Call(ctx context.Context, request osquery.ExtensionPluginRequest) osquery.ExtensionResponse {
	var err error
	if log, ok := request["string"]; ok {
		err = t.plugin.LogString(ctx, LogTypeString, log)
	} else if log, ok := request["snapshot"]; ok {
		err = t.plugin.LogString(ctx, LogTypeSnapshot, log)
	} else if log, ok := request["health"]; ok {
		err = t.plugin.LogString(ctx, LogTypeHealth, log)
	} else if log, ok := request["init"]; ok {
		err = t.plugin.LogString(ctx, LogTypeInit, log)
	} else if log, ok := request["status"]; ok {
		err = t.plugin.LogString(ctx, LogTypeStatus, log)
	} else {
		return osquery.ExtensionResponse{
			Status: &osquery.ExtensionStatus{
				Code:    1,
				Message: "unknown log request",
			},
		}
	}

	if err != nil {
		return osquery.ExtensionResponse{
			Status: &osquery.ExtensionStatus{
				Code:    1,
				Message: "error logging: " + err.Error(),
			},
		}
	}

	return osquery.ExtensionResponse{
		Status:   &StatusOK,
		Response: osquery.ExtensionPluginResponse{},
	}
}

func (t *loggerPluginImpl) Shutdown() {}

//LogType encodes the type of log osquery is outputting.
type LogType int

const (
	LogTypeString LogType = iota
	LogTypeSnapshot
	LogTypeHealth
	LogTypeInit
	LogTypeStatus
)

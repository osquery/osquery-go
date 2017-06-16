package logger

import (
	"context"

	"github.com/kolide/osquery-go/gen/osquery"
)

// LogFunc is the logger function used by an osquery Logger plugin.
//
// The LogFunc should log the provided result string. The LogType
// argument can be optionally used to log differently depending on the
// type of log received. The context argument can optionally be used
// for cancellation in long-running operations.
type LogFunc func(ctx context.Context, typ LogType, log string) error

// Plugin is an osquery logger plugin.
// The Plugin struct implements the OsqueryPlugin interface.
type Plugin struct {
	name  string
	logFn LogFunc
}

// NewPlugin takes a value that implements LoggerPlugin and wraps it with
// the appropriate methods to satisfy the OsqueryPlugin interface. Use this to
// easily create plugins implementing osquery tables.
func NewPlugin(name string, fn LogFunc) *Plugin {
	return &Plugin{name: name, logFn: fn}
}

func (t *Plugin) Name() string {
	return t.name
}

func (t *Plugin) RegistryName() string {
	return "logger"
}

func (t *Plugin) Routes() osquery.ExtensionPluginResponse {
	return []map[string]string{}
}

func (t *Plugin) Ping() osquery.ExtensionStatus {
	return osquery.ExtensionStatus{Code: 0, Message: "OK"}
}

func (t *Plugin) Call(ctx context.Context, request osquery.ExtensionPluginRequest) osquery.ExtensionResponse {
	var err error
	if log, ok := request["string"]; ok {
		err = t.logFn(ctx, LogTypeString, log)
	} else if log, ok := request["snapshot"]; ok {
		err = t.logFn(ctx, LogTypeSnapshot, log)
	} else if log, ok := request["health"]; ok {
		err = t.logFn(ctx, LogTypeHealth, log)
	} else if log, ok := request["init"]; ok {
		err = t.logFn(ctx, LogTypeInit, log)
	} else if log, ok := request["status"]; ok {
		err = t.logFn(ctx, LogTypeStatus, log)
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
		Status:   &osquery.ExtensionStatus{Code: 0, Message: "OK"},
		Response: osquery.ExtensionPluginResponse{},
	}
}

func (t *Plugin) Shutdown() {}

//LogType encodes the type of log osquery is outputting.
type LogType int

const (
	LogTypeString LogType = iota
	LogTypeSnapshot
	LogTypeHealth
	LogTypeInit
	LogTypeStatus
)

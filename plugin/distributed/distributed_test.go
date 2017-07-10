package distributed

import (
	"context"
	"errors"
	"sort"
	"testing"

	"github.com/kolide/osquery-go/gen/osquery"
	"github.com/stretchr/testify/assert"
)

var StatusOK = osquery.ExtensionStatus{Code: 0, Message: "OK"}

func TestDistributedPlugin(t *testing.T) {
	var getCalled, writeCalled bool
	var results []Result
	plugin := NewPlugin(
		"mock",
		func(context.Context) (map[string]string, error) {
			getCalled = true
			return map[string]string{
				"query1": "select iso_8601 from time",
				"query2": "select version from osquery_info",
				"query3": "select foo from bar",
			}, nil
		},
		func(ctx context.Context, res []Result) error {
			writeCalled = true
			results = res
			return nil
		},
	)

	// Basic methods
	assert.Equal(t, "distributed", plugin.RegistryName())
	assert.Equal(t, "mock", plugin.Name())
	assert.Equal(t, StatusOK, plugin.Ping())
	assert.Equal(t, osquery.ExtensionPluginResponse{}, plugin.Routes())

	// Call getQueries
	resp := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "getQueries"})
	assert.True(t, getCalled)
	assert.False(t, writeCalled)
	assert.Equal(t, &StatusOK, resp.Status)
	if assert.Len(t, resp.Response, 1) {
		assert.JSONEq(t, `{"queries": {"query1": "select iso_8601 from time", "query2": "select version from osquery_info", "query3": "select foo from bar"}}`,
			resp.Response[0]["results"])
	}

	// Call writeResults
	getCalled = false
	resp = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "writeResults", "results": `{"queries":{"query1":[{"iso_8601":"2017-07-10T22:08:40Z"}],"query2":[{"version":"2.4.0"}]},"statuses":{"query1":"0","query2":"0","query3":"1"}}`})
	assert.False(t, getCalled)
	assert.True(t, writeCalled)
	assert.Equal(t, &StatusOK, resp.Status)
	// Ensure correct ordering for comparison
	sort.Slice(results, func(i, j int) bool { return results[i].QueryName < results[j].QueryName })
	assert.Equal(t, []Result{
		{"query1", 0, []map[string]string{{"iso_8601": "2017-07-10T22:08:40Z"}}},
		{"query2", 0, []map[string]string{{"version": "2.4.0"}}},
		{"query3", 1, []map[string]string{}},
	},
		results)
}

func TestDistributedPluginErrors(t *testing.T) {
	var getCalled, writeCalled bool
	plugin := NewPlugin(
		"mock",
		func(context.Context) (map[string]string, error) {
			getCalled = true
			return nil, errors.New("getQueries failed")
		},
		func(ctx context.Context, res []Result) error {
			writeCalled = true
			return errors.New("writeResults failed")
		},
	)

	// Call with bad actions
	assert.Equal(t, int32(1), plugin.Call(context.Background(), osquery.ExtensionPluginRequest{}).Status.Code)
	assert.False(t, getCalled)
	assert.False(t, writeCalled)
	assert.Equal(t, int32(1), plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "bad"}).Status.Code)
	assert.False(t, getCalled)
	assert.False(t, writeCalled)

	// Call with good action but getQueries fails
	resp := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "getQueries"})
	assert.True(t, getCalled)
	assert.False(t, writeCalled)
	assert.Equal(t, int32(1), resp.Status.Code)
	assert.Equal(t, "error getting queries: getQueries failed", resp.Status.Message)

	getCalled = false

	// Call with good action but writeResults fails
	// Error unmarshalling results
	resp = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "writeResults", "results": "foobar"})
	assert.False(t, getCalled)
	assert.False(t, writeCalled)
	assert.Equal(t, int32(1), resp.Status.Code)
	assert.Contains(t, resp.Status.Message, "error unmarshalling results")

	// Error converting status
	resp = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "writeResults", "results": `{"statuses": {"query1": "foo"}}`})
	assert.False(t, getCalled)
	assert.False(t, writeCalled)
	assert.Equal(t, int32(1), resp.Status.Code)
	assert.Contains(t, resp.Status.Message, "invalid status")

	// Error unmarshalling results
	resp = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "writeResults", "results": "{}"})
	assert.False(t, getCalled)
	assert.True(t, writeCalled)
	assert.Equal(t, int32(1), resp.Status.Code)
	assert.Contains(t, resp.Status.Message, "error writing results")
}

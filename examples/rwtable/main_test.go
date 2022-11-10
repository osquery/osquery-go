package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/osquery/osquery-go/gen/osquery"
	"github.com/osquery/osquery-go/plugin/table"
)

func TestRwTableExample(t *testing.T) {
	plugin := table.NewWritablePlugin("rw_example_table", ExampleColumns(), ExampleGenerate, ExampleInsert, ExampleUpdate, ExampleDelete)

	ok := osquery.ExtensionStatus{Code: 0, Message: "OK"}

	assert.Equal(t, "table", plugin.RegistryName())
	assert.Equal(t, "rw_example_table", plugin.Name())
	assert.Equal(t, ok, plugin.Ping())
	assert.Equal(t, osquery.ExtensionPluginResponse{
		{"id": "column", "name": "text", "type": "TEXT", "op": "0"},
		{"id": "column", "name": "integer", "type": "INTEGER", "op": "0"},
	}, plugin.Routes())

	// SELECT

	generateResponse := osquery.ExtensionResponse{
		Status:   &ok,
		Response: []map[string]string{},
	}
	assert.Equal(t, generateResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "generate", "context": "{}"}))

	// INSERT {a, 1}, {b, 2}, {c, 3}

	insertResponse := osquery.ExtensionResponse{
		Status:   &ok,
		Response: []map[string]string{{"id": "0", "status": "success"}},
	}
	assert.Equal(t, insertResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "insert", "context": "{}", "json_value_array": "[\"a\", 1]"}))
	insertResponse = osquery.ExtensionResponse{
		Status:   &ok,
		Response: []map[string]string{{"id": "1", "status": "success"}},
	}
	assert.Equal(t, insertResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "insert", "context": "{}", "json_value_array": "[\"b\", 2]"}))
	insertResponse = osquery.ExtensionResponse{
		Status:   &ok,
		Response: []map[string]string{{"id": "2", "status": "success"}},
	}
	assert.Equal(t, insertResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "insert", "context": "{}", "json_value_array": "[\"c\", 3]"}))

	// INSERT duplicate {b, 2}

	insertResponse = osquery.ExtensionResponse{
		Status:   &ok,
		Response: []map[string]string{{"status": "constraint"}},
	}
	assert.Equal(t, insertResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "insert", "context": "{}", "json_value_array": "[\"b\", 2]"}))

	// SELECT

	generateResponse = osquery.ExtensionResponse{
		Status: &ok,
		Response: []map[string]string{
			{"integer": "1", "text": "a"},
			{"integer": "2", "text": "b"},
			{"integer": "3", "text": "c"},
		},
	}
	assert.Equal(t, generateResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "generate", "context": "{}"}))

	// UPDATE duplicate {b, 2} to {c, 3}

	updateResponse := osquery.ExtensionResponse{
		Status:   &ok,
		Response: []map[string]string{{"status": "constraint"}},
	}
	assert.Equal(t, updateResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "update", "context": "{}", "id": "1", "json_value_array": "[\"c\", 3]"}))

	// UPDATE {a, 1} to {d, 4}

	updateResponse = osquery.ExtensionResponse{
		Status:   &ok,
		Response: []map[string]string{{"status": "success"}},
	}
	assert.Equal(t, updateResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "update", "context": "{}", "id": "0", "json_value_array": "[\"d\", 4]"}))

	// SELECT

	generateResponse = osquery.ExtensionResponse{
		Status: &ok,
		Response: []map[string]string{
			{"integer": "4", "text": "d"},
			{"integer": "2", "text": "b"},
			{"integer": "3", "text": "c"},
		},
	}
	assert.Equal(t, generateResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "generate", "context": "{}"}))

	// DELETE {b, 2}

	deleteResponse := osquery.ExtensionResponse{
		Status:   &ok,
		Response: []map[string]string{{"status": "success"}},
	}
	assert.Equal(t, deleteResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "delete", "context": "{}", "id": "1"}))

	// SELECT

	generateResponse = osquery.ExtensionResponse{
		Status: &ok,
		Response: []map[string]string{
			{"integer": "4", "text": "d"},
			{"integer": "3", "text": "c"},
		},
	}
	assert.Equal(t, generateResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "generate", "context": "{}"}))

	// UPDATE {d, 4} to {d, 8} and {c, 3} to {c, 6}

	updateResponse = osquery.ExtensionResponse{
		Status:   &ok,
		Response: []map[string]string{{"status": "success"}},
	}
	assert.Equal(t, updateResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "update", "context": "{}", "id": "0", "json_value_array": "[\"d\", 8]"}))

	updateResponse = osquery.ExtensionResponse{
		Status:   &ok,
		Response: []map[string]string{{"status": "success"}},
	}
	assert.Equal(t, updateResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "update", "context": "{}", "id": "1", "json_value_array": "[\"c\", 6]"}))

	// SELECT

	generateResponse = osquery.ExtensionResponse{
		Status: &ok,
		Response: []map[string]string{
			{"integer": "8", "text": "d"},
			{"integer": "6", "text": "c"},
		},
	}
	assert.Equal(t, generateResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "generate", "context": "{}"}))

	// DELETE {d, 8} and {c, 6}

	deleteResponse = osquery.ExtensionResponse{
		Status:   &ok,
		Response: []map[string]string{{"status": "success"}},
	}
	assert.Equal(t, deleteResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "delete", "context": "{}", "id": "0"}))

	deleteResponse = osquery.ExtensionResponse{
		Status:   &ok,
		Response: []map[string]string{{"status": "success"}},
	}
	// Note id=1 here and not id=0 after id=0 have been deleted since generate is only called once in a multiple delete statement.
	// It would have been id=0 if it was one delete at a time
	assert.Equal(t, deleteResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "delete", "context": "{}", "id": "1"}))

	// SELECT

	generateResponse = osquery.ExtensionResponse{
		Status:   &ok,
		Response: []map[string]string{},
	}
	assert.Equal(t, generateResponse, plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "generate", "context": "{}"}))
}

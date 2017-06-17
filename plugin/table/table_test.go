package table

import (
	"context"
	"encoding/json"
	"errors"
	"testing"

	"github.com/kolide/osquery-go/gen/osquery"
	"github.com/stretchr/testify/assert"
)

// Ensure tablePluginImpl implements the OsqueryPlugin interface.
var _ OsqueryPlugin = (*tablePluginImpl)(nil)

type mockTablePlugin struct {
	NameFunc     func() string
	ColumnsFunc  func() []ColumnDefinition
	GenerateFunc func(context.Context, QueryContext) ([]map[string]string, error)
}

func (m *mockTablePlugin) Name() string {
	return m.NameFunc()
}

func (m *mockTablePlugin) Columns() []ColumnDefinition {
	return m.ColumnsFunc()
}

func (m *mockTablePlugin) Generate(ctx context.Context, queryCtx QueryContext) ([]map[string]string, error) {
	return m.GenerateFunc(ctx, queryCtx)
}

func TestTablePlugin(t *testing.T) {
	var calledQueryCtx QueryContext
	plugin := NewTablePlugin(
		&mockTablePlugin{
			NameFunc: func() string {
				return "mock"
			},
			ColumnsFunc: func() []ColumnDefinition {
				return []ColumnDefinition{
					TextColumn("text"),
					IntegerColumn("integer"),
					BigIntColumn("big_int"),
					DoubleColumn("double"),
				}
			},
			GenerateFunc: func(ctx context.Context, queryCtx QueryContext) ([]map[string]string, error) {
				calledQueryCtx = queryCtx
				return []map[string]string{
					{
						"text":    "hello world",
						"integer": "123",
						"big_int": "-1234567890",
						"double":  "3.14159",
					},
				}, nil
			},
		},
	)

	// Basic methods
	assert.Equal(t, "table", plugin.RegistryName())
	assert.Equal(t, "mock", plugin.Name())
	assert.Equal(t, StatusOK, plugin.Ping())
	assert.Equal(t, osquery.ExtensionPluginResponse{
		{"id": "column", "name": "text", "type": "TEXT", "op": "0"},
		{"id": "column", "name": "integer", "type": "INTEGER", "op": "0"},
		{"id": "column", "name": "big_int", "type": "BIGINT", "op": "0"},
		{"id": "column", "name": "double", "type": "DOUBLE", "op": "0"},
	}, plugin.Routes())

	// Call explicit columns action
	resp := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "columns"})
	assert.Equal(t, &StatusOK, resp.Status)
	assert.Equal(t, osquery.ExtensionPluginResponse{
		{"id": "column", "name": "text", "type": "TEXT", "op": "0"},
		{"id": "column", "name": "integer", "type": "INTEGER", "op": "0"},
		{"id": "column", "name": "big_int", "type": "BIGINT", "op": "0"},
		{"id": "column", "name": "double", "type": "DOUBLE", "op": "0"},
	}, resp.Response)

	// Call with good action and context
	resp = plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "generate", "context": "{}"})
	assert.Equal(t, QueryContext{map[string]ConstraintList{}}, calledQueryCtx)
	assert.Equal(t, &StatusOK, resp.Status)
	assert.Equal(t, osquery.ExtensionPluginResponse{
		{
			"text":    "hello world",
			"integer": "123",
			"big_int": "-1234567890",
			"double":  "3.14159",
		},
	}, resp.Response)
}

func TestTablePluginErrors(t *testing.T) {
	var called bool
	plugin := NewTablePlugin(
		&mockTablePlugin{
			NameFunc: func() string {
				return "mock"
			},
			ColumnsFunc: func() []ColumnDefinition {
				return []ColumnDefinition{
					TextColumn("text"),
					IntegerColumn("integer"),
					BigIntColumn("big_int"),
					DoubleColumn("double"),
				}
			},
			GenerateFunc: func(ctx context.Context, queryCtx QueryContext) ([]map[string]string, error) {
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
	assert.Equal(t, int32(1), plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "generate", "context": "{[]}"}).Status.Code)
	assert.False(t, called)

	// Call with good action but generate fails
	resp := plugin.Call(context.Background(), osquery.ExtensionPluginRequest{"action": "generate", "context": "{}"})
	assert.True(t, called)
	assert.Equal(t, int32(1), resp.Status.Code)
	assert.Equal(t, "error generating table: foobar", resp.Status.Message)

}

func TestParseConstraintList(t *testing.T) {
	var testCases = []struct {
		json        string
		constraints []Constraint
		shouldErr   bool
	}{
		{
			json:      "bad",
			shouldErr: true,
		},
		{
			json:      `{"foo": "bar"}`,
			shouldErr: true,
		},
		{
			json:        `""`,
			constraints: []Constraint{},
		},
		{
			json: `[{"op":"2","expr":"foo"}]`,
			constraints: []Constraint{
				Constraint{OperatorEquals, "foo"},
			},
		},
		{
			json: `[{"op":"4","expr":"3"},{"op":"16","expr":"4"}]`,
			constraints: []Constraint{
				Constraint{OperatorGreaterThan, "3"},
				Constraint{OperatorLessThan, "4"},
			},
		},
	}

	for _, tt := range testCases {
		t.Run("", func(t *testing.T) {
			constraints, err := parseConstraintList(json.RawMessage(tt.json))
			if tt.shouldErr {
				assert.NotNil(t, err)
			} else {
				assert.Equal(t, tt.constraints, constraints)
			}
		})
	}
}

func TestParseQueryContext(t *testing.T) {
	var testCases = []struct {
		json      string
		context   QueryContext
		shouldErr bool
	}{
		{
			json:      "",
			shouldErr: true,
		},
		{
			json: `
{
  "constraints":[
    {
      "name":"big_int",
      "list":"",
      "affinity":"BIGINT"
    },
    {
      "name":"double",
      "list":"",
      "affinity":"DOUBLE"
    },
    {
      "name":"integer",
      "list":"",
      "affinity":"INTEGER"
    },
    {
      "name":"text",
      "list":[
        {
          "op":"2",
          "expr":"foo"
        }
      ],
      "affinity":"TEXT"
    }
  ]
}`,
			context: QueryContext{map[string]ConstraintList{
				"big_int": ConstraintList{ColumnTypeBigInt, []Constraint{}},
				"double":  ConstraintList{ColumnTypeDouble, []Constraint{}},
				"integer": ConstraintList{ColumnTypeInteger, []Constraint{}},
				"text":    ConstraintList{ColumnTypeText, []Constraint{{OperatorEquals, "foo"}}},
			}},
		},
		{
			json: `
{
  "constraints":[
    {
      "name":"big_int",
      "list":"",
      "affinity":"BIGINT"
    },
    {
      "name":"double",
      "list":[
        {
          "op":"32",
          "expr":"3.1"
        }
      ],
      "affinity":"DOUBLE"
    },
    {
      "name":"integer",
      "list":"",
      "affinity":"INTEGER"
    },
    {
      "name":"text",
      "list":[
        {
          "op":"2",
          "expr":"foobar"
        }
      ],
      "affinity":"TEXT"
    }
  ]
}
`,
			context: QueryContext{map[string]ConstraintList{
				"big_int": ConstraintList{ColumnTypeBigInt, []Constraint{}},
				"double":  ConstraintList{ColumnTypeDouble, []Constraint{{OperatorGreaterThanOrEquals, "3.1"}}},
				"integer": ConstraintList{ColumnTypeInteger, []Constraint{}},
				"text":    ConstraintList{ColumnTypeText, []Constraint{{OperatorEquals, "foobar"}}},
			}},
		},
	}
	for _, tt := range testCases {
		t.Run("", func(t *testing.T) {
			context, err := parseQueryContext(tt.json)
			if tt.shouldErr {
				assert.NotNil(t, err)
			} else {
				assert.Equal(t, &tt.context, context)
			}
		})
	}
}

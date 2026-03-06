package table

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTable_Spec(t *testing.T) {
	t.Parallel()

	mockGenerate := func(_ context.Context, _ QueryContext) ([]map[string]string, error) { return nil, nil }

	tests := []struct {
		name     string
		plugin   *Plugin
		expected string
	}{
		{
			name: "single text column",
			plugin: NewPlugin("simple", []ColumnDefinition{TextColumn("simple_text")}, mockGenerate,
				WithPlatforms(DarwinPlatform),
			),
			expected: `{
  "name": "simple",
  "cacheable": false,
  "evented": false,
  "columns": [
    { "name": "simple_text", "type": "TEXT", "index": false, "required": false, "additional": false, "optimized": false, "hidden": false }
  ],
  "description": "",
  "url": "",
  "platforms": ["darwin"]
}`,
		},
		{
			name: "multiple columns with mixed types",
			plugin: NewPlugin("mixed", []ColumnDefinition{
				TextColumn("name"),
				IntegerColumn("pid"),
				BigIntColumn("size"),
				DoubleColumn("score"),
			}, mockGenerate,
				WithPlatforms(DarwinPlatform),
			),
			expected: `{
  "name": "mixed",
  "cacheable": false,
  "evented": false,
  "columns": [
    { "name": "name", "type": "TEXT", "index": false, "required": false, "additional": false, "optimized": false, "hidden": false },
    { "name": "pid", "type": "INTEGER", "index": false, "required": false, "additional": false, "optimized": false, "hidden": false },
    { "name": "size", "type": "BIGINT", "index": false, "required": false, "additional": false, "optimized": false, "hidden": false },
    { "name": "score", "type": "DOUBLE", "index": false, "required": false, "additional": false, "optimized": false, "hidden": false }
  ],
  "description": "",
  "url": "",
  "platforms": ["darwin"]
}`,
		},
		{
			name: "columns with options",
			plugin: NewPlugin("opts", []ColumnDefinition{
				TextColumn("key", IndexColumn(), RequiredColumn()),
				IntegerColumn("count", HiddenColumn()),
			}, mockGenerate,
				WithPlatforms(DarwinPlatform),
			),
			expected: `{
  "name": "opts",
  "cacheable": false,
  "evented": false,
  "columns": [
    { "name": "key", "type": "TEXT", "index": true, "required": true, "additional": false, "optimized": false, "hidden": false },
    { "name": "count", "type": "INTEGER", "index": false, "required": false, "additional": false, "optimized": false, "hidden": true }
  ],
  "description": "",
  "url": "",
  "platforms": ["darwin"]
}`,
		},
		{
			name: "plugin with description, url, notes, examples, platforms",
			plugin: NewPlugin("full", []ColumnDefinition{TextColumn("id")}, mockGenerate,
				WithDescription("Table description"),
				WithURL("https://osquery.io/schema"),
				WithNotes("Some notes"),
				WithExample("SELECT * FROM full"),
				WithPlatforms(DarwinPlatform, LinuxPlatform),
			),
			expected: `{
  "name": "full",
  "cacheable": false,
  "evented": false,
  "columns": [
    { "name": "id", "type": "TEXT", "index": false, "required": false, "additional": false, "optimized": false, "hidden": false }
  ],
  "description": "Table description",
  "url": "https://osquery.io/schema",
  "notes": "Some notes",
  "examples": ["SELECT * FROM full"],
  "platforms": ["darwin", "linux"]
}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			generatedSpec := tt.plugin.Spec()

			var expectedSpec OsqueryTableSpec
			require.NoError(t, json.Unmarshal([]byte(tt.expected), &expectedSpec))

			require.EqualValues(t, expectedSpec, generatedSpec, "spec for %s", tt.name)
		})
	}
}

func TestTable_Spec_marshal_json_column_type_format(t *testing.T) {
	t.Parallel()

	// ColumnType should marshal to JSON as lowercase with underscores (e.g. "unsigned_bigint")
	plugin := NewPlugin("t", []ColumnDefinition{
		TextColumn("a"),
		NewColumn("b", ColumnTypeUnsignedBigInt),
	}, func(_ context.Context, _ QueryContext) ([]map[string]string, error) { return nil, nil })
	spec := plugin.Spec()

	data, err := json.Marshal(spec)
	require.NoError(t, err)

	var decoded struct {
		Columns []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"columns"`
	}
	require.NoError(t, json.Unmarshal(data, &decoded))
	require.Len(t, decoded.Columns, 2)
	require.Equal(t, "text", decoded.Columns[0].Type)
	require.Equal(t, "unsigned_bigint", decoded.Columns[1].Type)
}

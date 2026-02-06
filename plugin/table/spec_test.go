package table

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTable_Spec(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		name     string
		columns  []ColumnDefinition
		expected string
	}{
		{
			name:    "simple",
			columns: []ColumnDefinition{TextColumn("simple_text")},
			expected: `
{
  "name": "simple",
  "cacheable": false,
  "evented": false,
  "columns":[
    { "name": "simple_text", "type": "TEXT", "index": false, "required": false, "additional": false, "optimized": false, "hidden": false }
  ],
  "description": "",
  "url": "",
  "platforms": ["darwin"]
}`,
		},
	}

	mockGenerate := func(_ context.Context, _ QueryContext) ([]map[string]string, error) { return nil, nil }

	for _, tt := range tests {
		testTable := NewPlugin(tt.name, tt.columns, mockGenerate)
		testTable.platforms = []platformName{DarwinPlatform}
		generatedSpec := testTable.Spec()

		var expectedSpec OsqueryTableSpec
		require.NoError(t, json.Unmarshal([]byte(tt.expected), &expectedSpec))

		require.EqualValues(t, expectedSpec, generatedSpec, "spec for %s", tt.name)
	}
}

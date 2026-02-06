package table

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestColumnType_MarshalJSON(t *testing.T) {
	t.Parallel()

	tests := []struct {
		ct       ColumnType
		expected string
	}{
		{ColumnTypeUnknown, `"unknown"`},
		{ColumnTypeText, `"text"`},
		{ColumnTypeInteger, `"integer"`},
		{ColumnTypeBigInt, `"bigint"`},
		{ColumnTypeUnsignedBigInt, `"unsigned_bigint"`},
		{ColumnTypeDouble, `"double"`},
		{ColumnTypeBlob, `"blob"`},
		{ColumnType("CUSTOM TYPE"), `"custom_type"`},
	}

	for _, tt := range tests {
		got, err := json.Marshal(tt.ct)
		require.NoError(t, err)
		require.Equal(t, tt.expected, string(got))
	}
}

func TestColumnDefinition_Options(t *testing.T) {
	t.Parallel()

	var tests = []struct {
		in       []ColumnOpt
		expected uint8
	}{
		{
			in:       []ColumnOpt{},
			expected: 0,
		},
		{
			in:       []ColumnOpt{IndexColumn(), HiddenColumn()},
			expected: 17,
		},
	}

	for _, tt := range tests {
		cd := TextColumn("foo", tt.in...)
		require.Equal(t, tt.expected, cd.Options())
	}
}

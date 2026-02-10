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

	// Option bitmask values from osquery column.h: Index=1, Required=2, Additional=4, Optimized=8, Hidden=16
	tests := []struct {
		name     string
		in       []ColumnOpt
		expected uint8
	}{
		{
			name:     "no options",
			in:       []ColumnOpt{},
			expected: 0,
		},
		{
			name:     "Index only",
			in:       []ColumnOpt{IndexColumn()},
			expected: 1,
		},
		{
			name:     "Required only",
			in:       []ColumnOpt{RequiredColumn()},
			expected: 2,
		},
		{
			name:     "Additional only",
			in:       []ColumnOpt{AdditionalColumn()},
			expected: 4,
		},
		{
			name:     "Optimized only",
			in:       []ColumnOpt{OptimizedColumn()},
			expected: 8,
		},
		{
			name:     "Hidden only",
			in:       []ColumnOpt{HiddenColumn()},
			expected: 16,
		},
		{
			name:     "Index and Hidden",
			in:       []ColumnOpt{IndexColumn(), HiddenColumn()},
			expected: 17,
		},
		{
			name:     "all options",
			in:       []ColumnOpt{IndexColumn(), RequiredColumn(), AdditionalColumn(), OptimizedColumn(), HiddenColumn()},
			expected: 1 + 2 + 4 + 8 + 16,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			cd := TextColumn("foo", tt.in...)
			require.Equal(t, tt.expected, cd.Options())
		})
	}
}

func TestColumnOpts_set_fields(t *testing.T) {
	t.Parallel()

	t.Run("IndexColumn sets Index", func(t *testing.T) {
		t.Parallel()
		cd := TextColumn("c", IndexColumn())
		require.True(t, cd.Index)
		require.False(t, cd.Required)
	})
	t.Run("RequiredColumn sets Required", func(t *testing.T) {
		t.Parallel()
		cd := TextColumn("c", RequiredColumn())
		require.True(t, cd.Required)
	})
	t.Run("AdditionalColumn sets Additional", func(t *testing.T) {
		t.Parallel()
		cd := TextColumn("c", AdditionalColumn())
		require.True(t, cd.Additional)
	})
	t.Run("OptimizedColumn sets Optimized", func(t *testing.T) {
		t.Parallel()
		cd := TextColumn("c", OptimizedColumn())
		require.True(t, cd.Optimized)
	})
	t.Run("HiddenColumn sets Hidden", func(t *testing.T) {
		t.Parallel()
		cd := TextColumn("c", HiddenColumn())
		require.True(t, cd.Hidden)
	})
	t.Run("ColumnDescription sets Description", func(t *testing.T) {
		t.Parallel()
		cd := TextColumn("c", ColumnDescription("human-readable note"))
		require.Equal(t, "human-readable note", cd.Description)
	})
	t.Run("multiple opts apply in order", func(t *testing.T) {
		t.Parallel()
		cd := TextColumn("c", IndexColumn(), ColumnDescription("desc"), RequiredColumn())
		require.True(t, cd.Index)
		require.True(t, cd.Required)
		require.Equal(t, "desc", cd.Description)
	})
}

func TestColumn_helpers_produce_correct_type(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		column ColumnDefinition
		want   ColumnType
	}{
		{"TextColumn", TextColumn("x"), ColumnTypeText},
		{"IntegerColumn", IntegerColumn("x"), ColumnTypeInteger},
		{"BigIntColumn", BigIntColumn("x"), ColumnTypeBigInt},
		{"DoubleColumn", DoubleColumn("x"), ColumnTypeDouble},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			require.Equal(t, tt.want, tt.column.Type)
			require.Equal(t, "x", tt.column.Name)
		})
	}
}

func TestNewColumn_applies_opts(t *testing.T) {
	t.Parallel()

	cd := NewColumn("custom", ColumnTypeBlob, IndexColumn(), ColumnDescription("blob col"))
	require.Equal(t, "custom", cd.Name)
	require.Equal(t, ColumnType("BLOB"), cd.Type)
	require.True(t, cd.Index)
	require.Equal(t, "blob col", cd.Description)
}

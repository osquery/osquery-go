package sql

import osquery "github.com/kolide/osquery-golang"

// TextColumn is a helper for defining columns containing strings.
func TextColumn(name string) osquery.ColumnDefinition {
	return osquery.ColumnDefinition{
		Name: name,
		Type: osquery.ColumnTypeText,
	}
}

// IntegerColumn is a helper for defining columns containing integers.
func IntegerColumn(name string) osquery.ColumnDefinition {
	return osquery.ColumnDefinition{
		Name: name,
		Type: osquery.ColumnTypeInteger,
	}
}

// BigIntColumn is a helper for defining columns containing big integers.
func BigIntColumn(name string) osquery.ColumnDefinition {
	return osquery.ColumnDefinition{
		Name: name,
		Type: osquery.ColumnTypeBigInt,
	}
}

// DoubleColumn is a helper for defining columns containing floating point
// values.
func DoubleColumn(name string) osquery.ColumnDefinition {
	return osquery.ColumnDefinition{
		Name: name,
		Type: osquery.ColumnTypeDouble,
	}
}

// ColumnSlice is a helper that takes an N number of definions and creates an
// []osquery.ColumnDefinition.
func ColumnSlice(columns ...osquery.ColumnDefinition) []osquery.ColumnDefinition {
	return columns
}

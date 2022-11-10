package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"strconv"
	"time"

	"github.com/osquery/osquery-go"
	"github.com/osquery/osquery-go/plugin/table"
)

type Row map[string]string

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")

	// In-memory dummy state
	currentRowId    = 0
	data            = map[string]Row{}
	rowIdToRowIndex = map[string]string{}
)

func main() {
	flag.Parse()
	if *socket == "" {
		log.Fatalln("Missing required --socket argument")
	}
	serverTimeout := osquery.ServerTimeout(
		time.Second * time.Duration(*timeout),
	)
	serverPingInterval := osquery.ServerPingInterval(
		time.Second * time.Duration(*interval),
	)

	server, err := osquery.NewExtensionManagerServer(
		"rw_example_extension",
		*socket,
		serverTimeout,
		serverPingInterval,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(table.NewWritablePlugin("rw_example_table", ExampleColumns(), ExampleGenerate, ExampleInsert, ExampleUpdate, ExampleDelete))
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func ExampleColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("text"),
		table.IntegerColumn("integer"),
	}
}

// Determine unique constraints based on column names
func GetRowKeys() []string {
	return []string{"text", "integer"}
}

// Called for SELECT, but also when SQL finds row id to perform DELETE/UPDATE
// statements, so the indexing must line up with what is returned. It is called
// only once for multiple writable operations. It is only built once here
// rather than kept  in sync with all other calls since we know it is always
// called before writable operations.
func ExampleGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	rowIdToRowIndex = map[string]string{}
	result := []map[string]string{}
	i := 0
	for rowIndex, row := range data {
		result = append(result, row)
		rowIdToRowIndex[strconv.Itoa(i)] = rowIndex
		i = i + 1
	}
	return result, nil
}

func ExampleInsert(ctx context.Context, queryContext table.QueryContext, rowId string, autoRowId bool, jsonValueArray []interface{}) ([]map[string]string, error) {
	row, err := ParseRow(jsonValueArray)
	if err != nil {
		return nil, err
	}

	constraint := CheckConstraint("", row)
	if constraint != nil {
		return constraint, nil
	}

	if !autoRowId {
		rowId = strconv.Itoa(currentRowId)
		currentRowId = currentRowId + 1
	}

	data[rowId] = row

	return []map[string]string{{"id": rowId, "status": "success"}}, nil
}

func ExampleUpdate(ctx context.Context, queryContext table.QueryContext, rowId string, jsonValueArray []interface{}) ([]map[string]string, error) {
	rowIndex, err := GetRowIndex(rowId)
	if err != nil {
		return nil, err
	}

	row, err := ParseRow(jsonValueArray)
	if err != nil {
		return nil, err
	}

	constraint := CheckConstraint(rowIndex, row)
	if constraint != nil {
		return constraint, nil
	}

	data[rowIndex] = row

	return []map[string]string{{"status": "success"}}, nil
}

func ExampleDelete(ctx context.Context, rowId string) ([]map[string]string, error) {
	rowIndex, err := GetRowIndex(rowId)
	if err != nil {
		return nil, err
	}

	delete(data, rowIndex)

	return []map[string]string{{"status": "success"}}, nil
}

// Get SQL row id to our internal row index
func GetRowIndex(rowId string) (string, error) {
	if rowId == "" {
		return "", errors.New("Row id not provided")
	}

	rowIndex, exists := rowIdToRowIndex[rowId]
	if !exists {
		return "", errors.New("Row id mapping not found")
	}

	return rowIndex, nil
}

// Map incoming VALUES from INSERT SQL statement to our own row format
func ParseRow(jsonValueArray []interface{}) (Row, error) {
	cols := ExampleColumns()
	if len(cols) != len(jsonValueArray) {
		return nil, errors.New("Wrong column count")
	}
	row := map[string]string{}
	for i, val := range jsonValueArray {
		col := cols[i]
		var parsedVal string
		if val == nil {
			// can skip values if --extensions_default_index=false is provided
			return nil, errors.New("Missing value for column \"" + col.Name + "\"")
		} else if col.Type == table.ColumnTypeText {
			parsedVal = val.(string)
		} else if col.Type == table.ColumnTypeInteger || col.Type == table.ColumnTypeBigInt || col.Type == table.ColumnTypeDouble {
			parsedVal = fmt.Sprintf("%f", val.(float64))
		} else {
			return nil, errors.New("Unknown column type")
		}
		row[col.Name] = parsedVal
	}
	return row, nil
}

// Ensure unique values for specified row keys (if any)
func CheckConstraint(rowIndex string, row Row) []map[string]string {
	keys := GetRowKeys()
	if len(keys) == 0 {
		// no constraints
		return nil
	}
	for currentRowIndex, currentRow := range data {
		// ensure we do not check against row being updated (empty if insert)
		if rowIndex != currentRowIndex {
			for _, key := range keys {
				if row[key] == currentRow[key] {
					return []map[string]string{{"status": "constraint"}}
				}
			}
		}
	}
	return nil
}

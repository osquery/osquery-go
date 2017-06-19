package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/kolide/osquery-go"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf(`Usage: %s SOCKET_PATH\n

Registers an example table extension.

This extension provides the "example_table" table. Try 'SELECT * FROM
example_table' in the osquery process the extension attaches to.
`, os.Args[0])
		os.Exit(1)
	}

	server, err := osquery.NewExtensionManagerServer("example_table", os.Args[1])
	if err != nil {
		log.Printf("Error creating extension: %s\n", err)
		os.Exit(1)
	}
	server.RegisterPlugin(osquery.NewTablePlugin(&ExampleTable{}))
	if err := server.Run(); err != nil {
		log.Println(err)
		os.Exit(1)
	}
}

type ExampleTable struct{}

func (f *ExampleTable) Name() string {
	return "example_table"
}

func (f *ExampleTable) Columns() []osquery.ColumnDefinition {
	return []osquery.ColumnDefinition{
		osquery.TextColumn("text"),
		osquery.IntegerColumn("integer"),
		osquery.BigIntColumn("big_int"),
		osquery.DoubleColumn("double"),
	}
}

func (f *ExampleTable) Generate(ctx context.Context, queryContext osquery.QueryContext) ([]map[string]string, error) {
	return []map[string]string{
		{
			"text":    "hello world",
			"integer": "123",
			"big_int": "-1234567890",
			"double":  "3.14159",
		},
	}, nil
}

package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
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

	server, err := osquery.NewExtensionManagerServer("example_extension", os.Args[1])
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(table.NewPlugin("example_table", ExampleColumns(), ExampleGenerate))
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func ExampleColumns() []table.ColumnDefinition {
	return []table.ColumnDefinition{
		table.TextColumn("text"),
		table.IntegerColumn("integer"),
		table.BigIntColumn("big_int"),
		table.DoubleColumn("double"),
	}
}

func ExampleGenerate(ctx context.Context, queryContext table.QueryContext) ([]map[string]string, error) {
	return []map[string]string{
		{
			"text":    "hello world",
			"integer": "123",
			"big_int": "-1234567890",
			"double":  "3.14159",
		},
	}, nil
}

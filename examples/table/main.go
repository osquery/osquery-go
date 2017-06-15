package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

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

	serv, err := osquery.NewExtensionManagerServer("example_table", os.Args[1], 1*time.Second)
	if err != nil {
		fmt.Printf("Error creating extension: %v\n", err)
		os.Exit(1)
	}
	serv.RegisterPlugin(osquery.NewTablePlugin(&ExampleTable{}))

	// Shut down server when process killed so that we don't leave the unix
	// domain socket file on the filesystem.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, os.Kill, syscall.SIGTERM)
	go func() {
		<-sig
		fmt.Println("Stopping extension server.")
		err := serv.Shutdown()
		if err != nil {
			fmt.Println("Error shutting down server: " + err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}()

	fmt.Println("Starting extension server...")
	err = serv.Start()
	if err != nil {
		fmt.Println("Error starting server: " + err.Error())
		os.Exit(1)
	}
}

type ExampleTable struct{}

func (f *ExampleTable) TableName() string {
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

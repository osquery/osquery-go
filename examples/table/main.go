package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kolide/osquery-golang/server"
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

	serv, err := server.NewExtensionManagerServer("example_table", os.Args[1], 1*time.Second)
	if err != nil {
		fmt.Printf("Error creating extension: %v\n", err)
		os.Exit(1)
	}
	serv.RegisterPlugin(server.NewTablePlugin(&ExampleTable{}))

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

type ExampleTableRow struct {
	Text     string `column:"text"`
	NullText *string
	Integer  int     `column:"integer"`
	Double   float64 `column:"double"`
}

func (f *ExampleTable) TableName() string {
	return "example_table"
}

func (f *ExampleTable) Columns() interface{} {
	return ExampleTableRow{}
}

func stringPtr(s string) *string {
	return &s
}

func (f *ExampleTable) Generate(ctx context.Context, queryContext server.QueryContext) ([]interface{}, error) {
	return []interface{}{
		ExampleTableRow{
			Text:    "hello world",
			Integer: 1234,
			Double:  1.2345,
		},
		ExampleTableRow{
			Text:     "hello 2",
			NullText: stringPtr(""),
			Integer:  1234,
			Double:   1.2345,
		},
	}, nil
}

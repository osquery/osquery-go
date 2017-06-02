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

This extension provides the "FooTable" table. Try 'SELECT * FROM FooTable' in
the osquery process the extension attaches to.
`, os.Args[0])
		os.Exit(1)
	}

	serv, err := server.NewExtensionManagerServer("foobar", os.Args[1], 1*time.Second)
	if err != nil {
		fmt.Printf("Error creating extension: %v\n", err)
		os.Exit(1)
	}
	serv.RegisterPlugin(server.NewTablePlugin(&FooTable{}))

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

type FooTable struct{}

func (f *FooTable) TableName() string {
	return "FooTable"
}

func (f *FooTable) Columns() []server.ColumnDefinition {
	return []server.ColumnDefinition{
		server.StringColumn("foo"),
		server.StringColumn("bar"),
	}
}

func (f *FooTable) Generate(ctx context.Context, queryContext interface{}) ([]map[string]string, error) {
	return []map[string]string{
		{"foo": "hello", "bar": "world"},
		{"foo": "some", "bar": "thing"},
	}, nil
}

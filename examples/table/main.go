package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kolide/osquery-golang/gen/osquery"
	"github.com/kolide/osquery-golang/server"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf(`Usage: %s SOCKET_PATH\n

Registers an example table extension.
`, os.Args[0])
		os.Exit(1)
	}

	serv, err := server.NewExtensionManagerServer("foobar", os.Args[1], 1*time.Second)
	if err != nil {
		fmt.Printf("Error creating extension: %v\n", err)
		os.Exit(1)
	}
	serv.RegisterPlugin(&FooTable{})

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

func (f *FooTable) Name() string {
	return "FooTable"
}

func (f *FooTable) RegistryName() string {
	return "table"
}

func (f *FooTable) Routes() osquery.ExtensionPluginResponse {
	return []map[string]string{
		{"id": "column", "name": "foo", "type": "TEXT", "op": "0"},
		{"id": "column", "name": "bar", "type": "TEXT", "op": "0"},
	}
}

func (f *FooTable) Ping() osquery.ExtensionStatus {
	return osquery.ExtensionStatus{Code: 0, Message: "OK"}
}

func (f *FooTable) Call(ctx context.Context, request osquery.ExtensionPluginRequest) osquery.ExtensionResponse {
	switch request["action"] {
	case "generate":
		return osquery.ExtensionResponse{
			Status: &osquery.ExtensionStatus{Code: 0, Message: "OK"},
			Response: osquery.ExtensionPluginResponse{
				{"foo": "hello", "bar": "world"},
				{"foo": "some", "bar": "thing"},
			},
		}
	default:
		return osquery.ExtensionResponse{
			Status:   &osquery.ExtensionStatus{Code: 0, Message: "OK"},
			Response: f.Routes(),
		}
	}
}

func (f *FooTable) Shutdown() {
}

package main

import (
	"context"
	"flag"
	"fmt"
	"log"

	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/distributed"
)

func main() {
	socketPath := flag.String("socket", "", "path to osqueryd extensions socket")
	flag.Int("timeout", 0, "")
	flag.Int("interval", 0, "")
	flag.Parse()

	server, err := osquery.NewExtensionManagerServer("example_distributed", *socketPath)
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(distributed.NewPlugin("example_distributed", getQueries, writeResults))
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func getQueries(ctx context.Context) (*distributed.GetQueriesResult, error) {
	return &distributed.GetQueriesResult{Queries: map[string]string{"time": "select * from time"}}, nil
}

func writeResults(ctx context.Context, results []distributed.Result) error {
	fmt.Println(results)
	return nil
}

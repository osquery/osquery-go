package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"math/big"
	"time"

	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/table"
)

var (
	socket   = flag.String("socket", "", "Path to the extensions UNIX domain socket")
	timeout  = flag.Int("timeout", 3, "Seconds to wait for autoloaded extensions")
	interval = flag.Int("interval", 3, "Seconds delay between connectivity checks")
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
		"example_extension",
		*socket,
		serverTimeout,
		serverPingInterval,
	)

	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}

	exampleTable, err := table.NewPlugin("example_table",
		ExampleRow{},
		table.GenerateFunc(ExampleGenerate),
		table.InsertFunc(ExampleInsert))
	if err != nil {
		log.Fatalf("Error creating table plugin: %s\n", err)
	}

	server.RegisterPlugin(exampleTable)
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

type ExampleRow struct {
	Text    string   `column:"text"`
	Integer int      `column:"integer"`
	BigInt  *big.Int `column:"big_int"`
	Double  float64  `column:"double"`
}

func ExampleGenerate(ctx context.Context, queryContext table.QueryContext) ([]table.RowDefinition, error) {
	return []table.RowDefinition{
		ExampleRow{
			Text:    "hello world",
			Integer: 123,
			BigInt:  big.NewInt(1013010),
			Double:  3.14159,
		},
	}, nil
}

func ExampleInsert(ctx context.Context, row table.RowDefinition) (int, error) {
	rowValue, ok := row.(ExampleRow)
	if !ok {
		return 0, fmt.Errorf("you gave me a wrong row type")
	}

	fmt.Println("Inserting row", rowValue)
	return 7, nil
}

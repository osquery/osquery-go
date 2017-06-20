package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/kolide/osquery-go"
	"github.com/kolide/osquery-go/plugin/config"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Printf(`Usage: %s SOCKET_PATH\n

Registers an example config plugin.

Test with an invocation like:

sudo ./example_call /var/osquery/osquery.em config example_config genConfig
`, os.Args[0])
		os.Exit(1)
	}

	server, err := osquery.NewExtensionManagerServer("example_extension", os.Args[1])
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(config.NewPlugin("example", GenerateConfigs))
	if err := server.Run(); err != nil {
		log.Fatal(err)
	}
}

func GenerateConfigs(ctx context.Context) (map[string]string, error) {
	return map[string]string{
		"config1": `
{
  "options": {
    "host_identifier": "hostname",
    "schedule_splay_percent": 10
  },
  "schedule": {
    "macos_kextstat": {
      "query": "SELECT * FROM kernel_extensions;",
      "interval": 10
    },
    "foobar": {
      "query": "SELECT foo, bar, pid FROM foobar_table;",
      "interval": 600
    }
  }
}
`,
	}, nil
}

# osquery-go

[![CircleCI](https://circleci.com/gh/kolide/osquery-go/tree/master.svg?style=svg)](https://circleci.com/gh/kolide/osquery-go/tree/master)
[![GoDoc](https://godoc.org/github.com/kolide/osquery-go?status.svg)](http://godoc.org/github.com/kolide/osquery-go)

[osquery](https://github.com/facebook/osquery) exposes an operating system as a high-performance relational database. This allows you to write SQL-based queries to explore operating system data. With osquery, SQL tables represent abstract concepts such as running processes, loaded kernel modules, open network connections, browser plugins, hardware events or file hashes.

If you're interested in learning more about osquery, visit the [GitHub project](https://github.com/facebook/osquery), the [website](https://osquery.io), and the [users guide](https://osquery.readthedocs.io).

## What is osquery-go?

In osquery, SQL tables, configuration retrieval, log handling, etc are implemented via a robust plugin and extensions API. This project contains Go bindings for creating osquery extensions in Go.

### Creating a new osquery table

If you want to create a custom osquery table in Go, you'll need to write an extension which registers the implementation of your table. Consider the following Go program:

```go
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
```

To test this code, start an osquery shell:

```
osqueryi --nodisable_extensions
osquery> select value from osquery_flags where name = 'extensions_socket';
+-----------------------------------+
| value                             |
+-----------------------------------+
| /Users/USERNAME/.osquery/shell.em |
+-----------------------------------+
```

Then start the Go extension:

```
go run ./my_table_plugin.go --socket /Users/USERNAME/.osquery/shell.em
```

Alternatively, you can also autoload your extension when starting an osquery shell:

```
go build -o my_table_plugin my_table_plugin.go
osqueryi --extension /path/to/my_table_plugin
```

This will register a table called `example_table`. As you can see, the table will return one row:

```
osquery> select * from example_table;
+-------------+---------+-------------+---------+
| text        | integer | big_int     | double  |
+-------------+---------+-------------+---------+
| hello world | 123     | -1234567890 | 3.14159 |
+-------------+---------+-------------+---------+
osquery>
```

This is obviously a contrived example, but it's straightforward to imagine the possibilities.

Using the instructions found on the [wiki](https://osquery.readthedocs.io/en/latest/development/osquery-sdk/), you can easily deploy your extension with an existing osquery deployment.

### Creating logger and config plugins

The process required to create a config and/or logger plugin is very similar to the process outlined above for creating an osquery table. Specifically, you would create an `ExtensionManagerServer` instance in `func main`, register your plugin, and launch the extension as described above. The only difference is that the implementation of your plugin would be different. For example, consider the implementation of an example logger plugin:

```go
type ExampleLogger struct{}

func (f *ExampleLogger) Name() string {
	return "example_logger"
}

func (f *ExampleLogger) LogString(ctx context.Context, typ osquery.LogType, logText string) error {
	var typeString string
	switch typ {
	case osquery.LogTypeString:
		typeString = "string"
	case osquery.LogTypeSnapshot:
		typeString = "snapshot"
	case osquery.LogTypeHealth:
		typeString = "health"
	case osquery.LogTypeInit:
		typeString = "init"
	case osquery.LogTypeStatus:
		typeString = "status"
	default:
		typeString = "unknown"
	}

	log.Printf("%s: %s\n", typeString, logText)
	return nil
}
```

Additionally, consider the implementation of an example config plugin:

```go
type ExampleConfig struct{}

func (f *ExampleConfig) Name() string {
	return "example_config"
}

func (f *ExampleConfig) GenerateConfigs(ctx context.Context) (map[string]string, error) {
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
```

All of these examples and more can be found in the [examples](./examples) subdirectory of this repository.

### Execute queries in Go

The same Thrift bindings can be used to create a Go client for the osqueryd or osqueryi's extension socket.

```go
package main

import (
	"fmt"
	"os"
	"time"

	"github.com/kolide/osquery-go"
)

func main() {
	if len(os.Args) != 3 {
		log.Fatalf("Usage: %s SOCKET_PATH QUERY", os.Args[0])
	}

	client, err := osquery.NewClient(os.Args[1], 10*time.Second)
	if err != nil {
		log.Fatalf("Error creating Thrift client: %v", err)
	}
	defer client.Close()

	resp, err := client.Query(os.Args[2])
	if err != nil {
		log.Fatalf("Error communicating with osqueryd: %v",err)
	}
	if resp.Status.Code != 0 {
		log.Fatalf("osqueryd returned error: %s", resp.Status.Message)
	}

	fmt.Printf("Got results:\n%#v\n", resp.Response)
}
```

## Install

To install this library, run the following:

```
go get -u github.com/kolide/osquery-go/...
```

Alternatively, if you're using this in a project that uses a dependency management tool like [Glide](https://github.com/Masterminds/glide) or [Dep](https://github.com/golang/dep), then follow the relevant instructions provided by that tool.

## Contributing

For more information on contributing to this project, see [CONTRIBUTING.md](./CONTRIBUTING.md).

## Vulnerabilities

If you find a vulnerability in this software, please email [security@kolide.co](mailto:security@kolide.co).

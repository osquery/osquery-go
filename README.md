# osquery-go

[![CircleCI](https://circleci.com/gh/kolide/osquery-go/tree/master.svg?style=svg)](https://circleci.com/gh/kolide/osquery-go/tree/master)
[![GoDoc](https://godoc.org/github.com/kolide/osquery-go?status.svg)](http://godoc.org/github.com/kolide/osquery-go)

[osquery](https://github.com/facebook/osquery) exposes an operating system as a high-performance relational database. This allows you to write SQL-based queries to explore operating system data. With osquery, SQL tables represent abstract concepts such as running processes, loaded kernel modules, open network connections, browser plugins, hardware events or file hashes.

If you're interested in learning more about osquery, visit the [GitHub project](https://github.com/facebook/osquery), the [website](https://osquery.io), and the [users guide](https://osquery.readthedocs.io).

## What is osquery-go?

In osquery, SQL tables, configuration retrieval, log handling, etc. are implemented via a robust plugin and extensions API. This project contains Go bindings for creating osquery extensions in Go. To create an extension, you must create an executable binary which instantiates an `ExtensionManagerServer` and registers the plugins that you would like to be added to osquery. You can then have osquery load the extension in your desired context (ie: in a long running instance of `osqueryd` or during an interactive query session with `osqueryi`). For more information about how this process works at a lower level, see the osquery [wiki](https://osquery.readthedocs.io/en/latest/development/osquery-sdk/).

### Creating a new osquery table

If you want to create a custom osquery table in Go, you'll need to write an extension which registers the implementation of your table. Consider the following Go program:

```go
package main

import (
	"context"
	"log"
	"os"

	"github.com/kolide/osquery-go"
)

func main() {
	if len(os.Args) != 2 {
		log.Fatalf(`Usage: %s SOCKET_PATH`, os.Args[0])
	}

	server, err := osquery.NewExtensionManagerServer("foobar", os.Args[1])
	if err != nil {
		log.Fatalf("Error creating extension: %s\n", err)
	}
	server.RegisterPlugin(osquery.NewTablePlugin(&ExampleTable{}))
	if err := server.Run(); err != nil {
		log.Fatalln(err)
	}
}

// ExampleTable is a type that we create here so that we can attach methods
// onto it. These methods will satisfy the interface required by the call to
// osquery.NewTablePlugin when we register our table.
type ExampleTable struct{}

// Name returns the name of our table.
func (f *ExampleTable) Name() string {
	return "foobar"
}

// Columns returns the columns that our table will return.
func (f *ExampleTable) Columns() []osquery.ColumnDefinition {
	return []osquery.ColumnDefinition{
		osquery.TextColumn("foo"),
		osquery.TextColumn("baz"),
	}
}

// Generate will be called whenever the table is queried. It should return
// a full table scan.
func (f *ExampleTable) Generate(ctx context.Context, queryContext osquery.QueryContext) ([]map[string]string, error) {
	return []map[string]string{
		{
			"foo": "bar",
			"baz": "baz",
		},
		{
			"foo": "bar",
			"baz": "baz",
		},
	}, nil
}
```

To test this code, start an osquery shell and find the path of the osquery extension socket:

```
osqueryi --nodisable_extensions
osquery> select value from osquery_flags where name = 'extensions_socket';
+-----------------------------------+
| value                             |
+-----------------------------------+
| /Users/USERNAME/.osquery/shell.em |
+-----------------------------------+
```

Then start the Go extension and have it communicate with osqueryi via the extension socket that you retrieved above:

```
go run ./my_table_plugin.go --socket /Users/USERNAME/.osquery/shell.em
```

Alternatively, you can also autoload your extension when starting an osquery shell:

```
go build -o my_table_plugin my_table_plugin.go
osqueryi --extension /path/to/my_table_plugin
```

This will register a table called "foobar". As you can see, the table will return two rows:

```
osquery> select * from foobar;
+-----+-----+
| foo | baz |
+-----+-----+
| bar | baz |
| bar | baz |
+-----+-----+
osquery>
```

This is obviously a contrived example, but it's easy to imagine the possibilities.

Using the instructions found on the [wiki](https://osquery.readthedocs.io/en/latest/development/osquery-sdk/), you can deploy your extension with an existing osquery deployment.

### Creating logger and config plugins

The process required to create a config and/or logger plugin is very similar to the process outlined above for creating an osquery table. Specifically, you would create an `ExtensionManagerServer` instance in `func main()`, register your plugin and launch the extension as described above. The only difference is that the implementation of your plugin would be different. For example, consider the implementation of an example logger plugin:

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

This library can also be used to create a Go client for the osqueryd or osqueryi's extension socket. You can use this to add the ability to performantly execute osquery queries to your Go program. Consider the following example:

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
go get github.com/kolide/osquery-go
```

Alternatively, if you're using this in a project that uses a dependency management tool like [Glide](https://github.com/Masterminds/glide) or [Dep](https://github.com/golang/dep), then follow the relevant instructions provided by that tool.

## Contributing

For more information on contributing to this project, see [CONTRIBUTING.md](./CONTRIBUTING.md).

## Vulnerabilities

If you find a vulnerability in this software, please email [security@kolide.co](mailto:security@kolide.co).

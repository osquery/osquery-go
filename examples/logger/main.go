package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/kolide/osquery-golang"
)

func main() {
	socketPath := flag.String("socket", "", "path to osqueryd extensions socket")
	flag.Int("timeout", 0, "")
	flag.Int("interval", 0, "")
	flag.Parse()

	serv, err := osquery.NewExtensionManagerServer("example_logger", *socketPath, 1*time.Second)
	if err != nil {
		fmt.Printf("Error creating extension: %v\n", err)
		os.Exit(1)
	}
	serv.RegisterPlugin(osquery.NewLoggerPlugin(&ExampleLogger{}))

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

type ExampleLogger struct{}

func (f *ExampleLogger) Name() string {
	return "example_logger"
}

func logTypeToString(typ osquery.LogType) string {
	switch typ {
	case osquery.LogTypeString:
		return "string"
	case osquery.LogTypeSnapshot:
		return "snapshot"
	case osquery.LogTypeHealth:
		return "health"
	case osquery.LogTypeInit:
		return "init"
	case osquery.LogTypeStatus:
		return "status"
	default:
		return "unknown"
	}
}

func (f *ExampleLogger) LogString(ctx context.Context, typ osquery.LogType, logText string) error {
	log.Printf("%s: %s\n", logTypeToString(typ), logText)
	return nil
}

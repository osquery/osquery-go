package main

import (
	"fmt"
	"os"
	"time"

	"github.com/kolide/osquery-go"
)

func main() {
	if len(os.Args) != 5 {
		fmt.Printf(`Usage: %s SOCKET_PATH REGISTRY_NAME PLUGIN_NAME ACTION

Calls the provided action for the plugin with the given registry and plugin
name.
`, os.Args[0])
		os.Exit(1)
	}

	socketPath := os.Args[1]
	registryName := os.Args[2]
	pluginName := os.Args[3]
	action := os.Args[4]

	client, err := osquery.NewClient(socketPath, 10*time.Second)
	if err != nil {
		fmt.Println("Error creating Thrift client: " + err.Error())
		os.Exit(1)
	}
	defer client.Close()

	resp, err := client.Call(registryName, pluginName, map[string]string{"action": action})
	if err != nil {
		fmt.Println("Error communicating with osqueryd: " + err.Error())
		os.Exit(1)
	}
	if resp.Status.Code != 0 {
		fmt.Println("osqueryd returned error: " + resp.Status.Message)
		os.Exit(1)
	}

	fmt.Printf("Got results:\n%#v\n", resp.Response)
}

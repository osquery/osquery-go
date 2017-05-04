package main

import (
	"fmt"
	"os"
	"time"

	"github.com/kolide/osquery-golang/client"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Printf("Usage: %s SOCKET_PATH QUERY\n", os.Args[0])
		os.Exit(1)
	}

	client, err := client.NewClient(os.Args[1], 10*time.Second)
	if err != nil {
		fmt.Println("Error creating Thrift client: " + err.Error())
		os.Exit(1)
	}
	defer client.Close()

	resp, err := client.Query(os.Args[2])
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

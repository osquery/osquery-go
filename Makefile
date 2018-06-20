PATH := $(GOPATH)/bin:$(PATH)

all: gen examples

deps:
	go get -u github.com/golang/dep/cmd/dep
	dep ensure -vendor-only

gen: ./osquery.thrift
	rm -rf ./gen
	mkdir -p ./gen ./gen/osquery/mock
	thrift --gen go:package_prefix=github.com/kolide/osquery-go/gen/ -out ./gen ./osquery.thrift
	rm -rf gen/osquery/extension-remote gen/osquery/extension_manager-remote
	gofmt -w ./gen

examples: example_query example_call example_logger example_distributed example_table example_config

example_query: examples/query/*.go
	go build -o example_query ./examples/query/*.go

example_call: examples/call/*.go
	go build -o example_call ./examples/call/*.go

example_logger: examples/logger/*.go
	go build -o example_logger.ext  ./examples/logger/*.go

example_distributed: examples/distributed/*.go
	go build -o example_distributed.ext  ./examples/distributed/*.go

example_table: examples/table/*.go
	go build -o example_table ./examples/table/*.go

example_config: examples/config/*.go
	go build -o example_config ./examples/config/*.go

test: all
	go test -race -cover -v $(shell go list ./... | grep -v /vendor/)

clean:
	rm -rf ./build ./gen

.PHONY: all

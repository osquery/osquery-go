all: gen examples

gen: ./osquery.thrift
	rm -rf gen
	mkdir gen
	thrift --gen go:package_prefix=github.com/kolide/osquery-golang/gen/ -out gen ./osquery.thrift
	rm -rf gen/osquery/extension-remote gen/osquery/extension_manager-remote

examples: example_query

example_query: examples/query/*.go
	go build -o example_query ./examples/query/main.go

.PHONY: all

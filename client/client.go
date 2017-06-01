package client

import (
	"net"
	"time"

	"github.com/kolide/osquery-golang/gen/osquery"
	"github.com/pkg/errors"

	"git.apache.org/thrift.git/lib/go/thrift"
)

// ExtensionManagerClient is a wrapper for the osquery Thrift extensions API.
type ExtensionManagerClient struct {
	client    osquery.ExtensionManager
	transport thrift.TTransport
}

// NewClient creates a new client communicating to osquery over the socket at
// the provided path. If resolving the address or connecting to the socket
// fails, this function will error.
func NewClient(sockPath string, timeout time.Duration) (*ExtensionManagerClient, error) {
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return nil, errors.Wrap(err, "resolving socket path "+sockPath)
	}

	trans := thrift.NewTSocketFromAddrTimeout(addr, timeout)
	if err := trans.Open(); err != nil {
		return nil, errors.Wrap(err, "opening socket transport")
	}

	client := osquery.NewExtensionManagerClientFactory(trans,
		thrift.NewTBinaryProtocolFactoryDefault())

	return &ExtensionManagerClient{client, trans}, nil
}

// Close should be called to close the transport when use of the client is
// completed.
func (c *ExtensionManagerClient) Close() {
	if c.transport != nil && c.transport.IsOpen() {
		c.transport.Close()
	}
}

// Ping requests metadata from the extension manager.
func (c *ExtensionManagerClient) Ping() (*osquery.ExtensionStatus, error) {
	return c.client.Ping()
}

// Call requests a call to an extension (or core) registry plugin.
func (c *ExtensionManagerClient) Call(registry, item string, request osquery.ExtensionPluginRequest) (*osquery.ExtensionResponse, error) {
	return c.client.Call(registry, item, request)
}

// Extensions requests the list of active registered extensions.
func (c *ExtensionManagerClient) Extensions() (osquery.InternalExtensionList, error) {
	return c.client.Extensions()
}

// RegisterExtension registers the extension plugins with the osquery process.
func (c *ExtensionManagerClient) RegisterExtension(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
	return c.client.RegisterExtension(info, registry)
}

// Options requests the list of bootstrap or configuration options.
func (c *ExtensionManagerClient) Options() (osquery.InternalOptionList, error) {
	return c.client.Options()
}

// Query requests a query to be run and returns the result rows.
func (c *ExtensionManagerClient) Query(sql string) (*osquery.ExtensionResponse, error) {
	return c.client.Query(sql)
}

// GetQueryColumns requests the columns returned by the parsed query.
func (c *ExtensionManagerClient) GetQueryColumns(sql string) (*osquery.ExtensionResponse, error) {
	return c.client.GetQueryColumns(sql)
}

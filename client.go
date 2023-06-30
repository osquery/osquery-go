package osquery

import (
	"context"
	"time"

	"github.com/osquery/osquery-go/gen/osquery"
	"github.com/osquery/osquery-go/traces"
	"github.com/osquery/osquery-go/transport"

	"github.com/apache/thrift/lib/go/thrift"
	"github.com/pkg/errors"
)

const (
	defaultWaitTime    = 200 * time.Millisecond
	defaultMaxWaitTime = 1 * time.Minute
)

// ExtensionManagerClient is a wrapper for the osquery Thrift extensions API.
type ExtensionManagerClient struct {
	client    osquery.ExtensionManager
	transport thrift.TTransport

	waitTime    time.Duration
	maxWaitTime time.Duration
	lock        *locker
}

type ClientOption func(*ExtensionManagerClient)

// WaitTime sets the default amount of wait time for the osquery socket to free up. You can override this on a per
// call basis by setting a context deadline
func DefaultWaitTime(d time.Duration) ClientOption {
	return func(c *ExtensionManagerClient) {
		c.waitTime = d
	}
}

// MaxWaitTime is the maximum amount of time something is allowed to wait for the osquery socket. This takes precedence
// over the context deadline.
func MaxWaitTime(d time.Duration) ClientOption {
	return func(c *ExtensionManagerClient) {
		c.maxWaitTime = d
	}
}

// NewClient creates a new client communicating to osquery over the socket at
// the provided path. If resolving the address or connecting to the socket
// fails, this function will error.
func NewClient(path string, socketOpenTimeout time.Duration, opts ...ClientOption) (*ExtensionManagerClient, error) {
	c := &ExtensionManagerClient{
		waitTime:    defaultWaitTime,
		maxWaitTime: defaultMaxWaitTime,
	}

	for _, opt := range opts {
		opt(c)
	}

	if c.waitTime > c.maxWaitTime {
		return nil, errors.New("default wait time larger than max wait time")
	}

	c.lock = NewLocker(c.waitTime, c.maxWaitTime)

	if c.client == nil {
		trans, err := transport.Open(path, socketOpenTimeout)
		if err != nil {
			return nil, err
		}

		c.client = osquery.NewExtensionManagerClientFactory(
			trans,
			thrift.NewTBinaryProtocolFactoryDefault(),
		)
	}

	return c, nil
}

// Close should be called to close the transport when use of the client is
// completed.
func (c *ExtensionManagerClient) Close() {
	if c.transport != nil && c.transport.IsOpen() {
		c.transport.Close()
	}
}

// Ping requests metadata from the extension manager, using a new background context
func (c *ExtensionManagerClient) Ping() (*osquery.ExtensionStatus, error) {
	return c.PingContext(context.Background())
}

// PingContext requests metadata from the extension manager.
func (c *ExtensionManagerClient) PingContext(ctx context.Context) (*osquery.ExtensionStatus, error) {
	if err := c.lock.Lock(ctx); err != nil {
		return nil, err
	}
	defer c.lock.Unlock()
	return c.client.Ping(ctx)
}

// Call requests a call to an extension (or core) registry plugin, using a new background context
func (c *ExtensionManagerClient) Call(registry, item string, request osquery.ExtensionPluginRequest) (*osquery.ExtensionResponse, error) {
	return c.CallContext(context.Background(), registry, item, request)
}

// CallContext requests a call to an extension (or core) registry plugin.
func (c *ExtensionManagerClient) CallContext(ctx context.Context, registry, item string, request osquery.ExtensionPluginRequest) (*osquery.ExtensionResponse, error) {
	ctx, span := traces.StartSpan(ctx, "ExtensionManagerClient.CallContext")
	defer span.End()

	if err := c.lock.Lock(ctx); err != nil {
		return nil, err
	}
	defer c.lock.Unlock()
	return c.client.Call(ctx, registry, item, request)
}

// Extensions requests the list of active registered extensions, using a new background context
func (c *ExtensionManagerClient) Extensions() (osquery.InternalExtensionList, error) {
	return c.ExtensionsContext(context.Background())
}

// ExtensionsContext requests the list of active registered extensions.
func (c *ExtensionManagerClient) ExtensionsContext(ctx context.Context) (osquery.InternalExtensionList, error) {
	ctx, span := traces.StartSpan(ctx, "ExtensionManagerClient.ExtensionsContext")
	defer span.End()

	if err := c.lock.Lock(ctx); err != nil {
		return nil, err
	}
	defer c.lock.Unlock()
	return c.client.Extensions(ctx)
}

// RegisterExtension registers the extension plugins with the osquery process, using a new background context
func (c *ExtensionManagerClient) RegisterExtension(info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
	return c.RegisterExtensionContext(context.Background(), info, registry)
}

// RegisterExtensionContext registers the extension plugins with the osquery process.
func (c *ExtensionManagerClient) RegisterExtensionContext(ctx context.Context, info *osquery.InternalExtensionInfo, registry osquery.ExtensionRegistry) (*osquery.ExtensionStatus, error) {
	ctx, span := traces.StartSpan(ctx, "ExtensionManagerClient.RegisterExtensionContext")
	defer span.End()

	if err := c.lock.Lock(ctx); err != nil {
		return nil, err
	}
	defer c.lock.Unlock()
	return c.client.RegisterExtension(ctx, info, registry)
}

// DeregisterExtension de-registers the extension plugins with the osquery process, using a new background context
func (c *ExtensionManagerClient) DeregisterExtension(uuid osquery.ExtensionRouteUUID) (*osquery.ExtensionStatus, error) {
	return c.DeregisterExtensionContext(context.Background(), uuid)
}

// DeregisterExtensionContext de-registers the extension plugins with the osquery process.
func (c *ExtensionManagerClient) DeregisterExtensionContext(ctx context.Context, uuid osquery.ExtensionRouteUUID) (*osquery.ExtensionStatus, error) {
	ctx, span := traces.StartSpan(ctx, "ExtensionManagerClient.DeregisterExtensionContext")
	defer span.End()

	if err := c.lock.Lock(ctx); err != nil {
		return nil, err
	}
	defer c.lock.Unlock()
	return c.client.DeregisterExtension(ctx, uuid)
}

// Options requests the list of bootstrap or configuration options, using a new background context.
func (c *ExtensionManagerClient) Options() (osquery.InternalOptionList, error) {
	return c.OptionsContext(context.Background())
}

// OptionsContext requests the list of bootstrap or configuration options.
func (c *ExtensionManagerClient) OptionsContext(ctx context.Context) (osquery.InternalOptionList, error) {
	ctx, span := traces.StartSpan(ctx, "ExtensionManagerClient.OptionsContext")
	defer span.End()

	if err := c.lock.Lock(ctx); err != nil {
		return nil, err
	}
	defer c.lock.Unlock()
	return c.client.Options(ctx)
}

// Query requests a query to be run and returns the extension
// response, using a new background context.  Consider using the
// QueryRow or QueryRows helpers for a more friendly interface.
func (c *ExtensionManagerClient) Query(sql string) (*osquery.ExtensionResponse, error) {
	return c.QueryContext(context.Background(), sql)
}

// QueryContext requests a query to be run and returns the extension response.
// Consider using the QueryRow or QueryRows helpers for a more friendly
// interface.
func (c *ExtensionManagerClient) QueryContext(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
	ctx, span := traces.StartSpan(ctx, "ExtensionManagerClient.QueryContext")
	defer span.End()

	if err := c.lock.Lock(ctx); err != nil {
		return nil, err
	}
	defer c.lock.Unlock()
	return c.client.Query(ctx, sql)
}

// QueryRows is a helper that executes the requested query and returns the
// results. It handles checking both the transport level errors and the osquery
// internal errors by returning a normal Go error type.
func (c *ExtensionManagerClient) QueryRows(sql string) ([]map[string]string, error) {
	return c.QueryRowsContext(context.Background(), sql)
}

// QueryRowsContext is a helper that executes the requested query and returns the
// results. It handles checking both the transport level errors and the osquery
// internal errors by returning a normal Go error type.
func (c *ExtensionManagerClient) QueryRowsContext(ctx context.Context, sql string) ([]map[string]string, error) {
	ctx, span := traces.StartSpan(ctx, "ExtensionManagerClient.QueryRowsContext")
	defer span.End()

	res, err := c.QueryContext(ctx, sql)
	if err != nil {
		return nil, errors.Wrap(err, "transport error in query")
	}
	if res.Status == nil {
		return nil, errors.New("query returned nil status")
	}
	if res.Status.Code != 0 {
		return nil, errors.Errorf("query returned error: %s", res.Status.Message)
	}
	return res.Response, nil

}

// QueryRow behaves similarly to QueryRows, but it returns an error if the
// query does not return exactly one row.
func (c *ExtensionManagerClient) QueryRow(sql string) (map[string]string, error) {
	return c.QueryRowContext(context.Background(), sql)
}

// QueryRowContext behaves similarly to QueryRows, but it returns an error if the
// query does not return exactly one row.
func (c *ExtensionManagerClient) QueryRowContext(ctx context.Context, sql string) (map[string]string, error) {
	ctx, span := traces.StartSpan(ctx, "ExtensionManagerClient.QueryRowContext")
	defer span.End()

	res, err := c.QueryRowsContext(ctx, sql)
	if err != nil {
		return nil, err
	}
	if len(res) != 1 {
		return nil, errors.Errorf("expected 1 row, got %d", len(res))
	}
	return res[0], nil
}

// GetQueryColumns requests the columns returned by the parsed query, using a new background context.
func (c *ExtensionManagerClient) GetQueryColumns(sql string) (*osquery.ExtensionResponse, error) {
	return c.GetQueryColumnsContext(context.Background(), sql)
}

// GetQueryColumnsContext requests the columns returned by the parsed query.
func (c *ExtensionManagerClient) GetQueryColumnsContext(ctx context.Context, sql string) (*osquery.ExtensionResponse, error) {
	ctx, span := traces.StartSpan(ctx, "ExtensionManagerClient.GetQueryColumnsContext")
	defer span.End()

	if err := c.lock.Lock(ctx); err != nil {
		return nil, err
	}
	defer c.lock.Unlock()
	return c.client.GetQueryColumns(ctx, sql)
}

package transport

import (
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/pkg/errors"

	"git.apache.org/thrift.git/lib/go/thrift"
)

// Open opens the named pipe with the provided path and timeout,
// returning a TTransport.
func Open(path string, timeout time.Duration) (thrift.TTransport, error) {
	conn, err := winio.DialPipe(path, &timeout)
	if err != nil {
		return nil, errors.Wrapf(err, "dialing pipe '%s'", path)
	}
	return thrift.NewTSocketFromConnTimeout(conn, timeout), nil
}

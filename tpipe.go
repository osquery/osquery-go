// +build windows

package osquery

import (
	"net"
	"time"

	"github.com/Microsoft/go-winio"
	"github.com/pkg/errors"

	"git.apache.org/thrift.git/lib/go/thrift"
)

// TPipe is a Windows named pipe implementation of the thrift TTransport
// interface.
type TPipe struct {
	net.Conn
}

// Ensure this implements the thrift TTransport interface.
var _ thrift.TTransport = &TPipe{}

// OpenTransport opens the named pipe with the provided path and timeout,
// returning a TTransport implementation.
func OpenTransport(path string, timeout time.Duration) (*TPipe, error) {
	p, err := winio.DialPipe(path, &timeout)
	if err != nil {
		return nil, errors.Wrapf(err, "dialing pipe '%s'", path)
	}
	return &TPipe{p}, nil
}

// Flush is a noop in this implementation.
func (t *TPipe) Flush() error {
	return nil
}

// IsOpen is a noop in this implementation.
func (t *TPipe) IsOpen() bool {
	return true
}

// Open is a noop in this implementation.
func (t *TPipe) Open() error {
	return nil
}

// RemainingBytes is a noop in this implementation.
func (t *TPipe) RemainingBytes() uint64 {
	return 0
}

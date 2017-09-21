// +build !windows

// Package transport provides Thrift TTransport implementations for use on
// mac/linux (TSocket) and Windows (custom named pipe implementation)
package transport

import (
	"net"
	"time"

	"git.apache.org/thrift.git/lib/go/thrift"
	"github.com/pkg/errors"
)

// Open opens the unix domain socket with the provided path and timeout,
// returning a TTransport.
func Open(sockPath string, timeout time.Duration) (thrift.TTransport, error) {
	addr, err := net.ResolveUnixAddr("unix", sockPath)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving socket path '%s'", sockPath)
	}

	trans := thrift.NewTSocketFromAddrTimeout(addr, timeout)
	if err := trans.Open(); err != nil {
		return nil, errors.Wrap(err, "opening socket transport")
	}

	return trans, nil
}

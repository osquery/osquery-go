// +build !windows

package transport

import (
	"net"
	"time"

	"git.apache.org/thrift.git/lib/go/thrift"
	"github.com/pkg/errors"
)

// Open opens the unix domain socket with the provided path and timeout,
// returning a TTransport.
func Open(sockPath string, timeout time.Duration) (*thrift.TSocket, error) {
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

func OpenServer(listenPath string, timeout time.Duration) (*thrift.TServerSocket, error) {
	addr, err := net.ResolveUnixAddr("unix", listenPath)
	if err != nil {
		return nil, errors.Wrapf(err, "resolving addr (%s)", addr)
	}

	return thrift.NewTServerSocketFromAddrTimeout(addr, 0), nil
}

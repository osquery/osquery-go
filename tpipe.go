package osquery

import (
	"net"

	"github.com/Microsoft/go-winio"
	"github.com/pkg/errors"

	"git.apache.org/thrift.git/lib/go/thrift"
)

type TPipe struct {
	net.Conn
}

func OpenPipe(path string) (*TPipe, error) {
	p, err := winio.DialPipe(path, nil)
	if err != nil {
		return nil, errors.Wrapf(err, "dialing pipe %s", path)
	}
	return &TPipe{p}, nil
}

func (t *TPipe) Flush() error {
	return nil
}

func (t *TPipe) IsOpen() bool {
	return true
}

func (t *TPipe) Open() error {
	return nil
}

func (t *TPipe) RemainingBytes() uint64 {
	return 0
}

var _ thrift.TTransport = &TPipe{}

package transport

import (
	"bytes"
	"fmt"
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
	buf bytes.Buffer
}

// Ensure this implements the thrift TTransport interface.
var _ thrift.TTransport = &TPipe{}

// Open opens the named pipe with the provided path and timeout,
// returning a custom TTransport implementation.
func Open(path string, timeout time.Duration) (thrift.TTransport, error) {
	conn, err := winio.DialPipe(path, &timeout)
	if err != nil {
		return nil, errors.Wrapf(err, "dialing pipe '%s'", path)
	}
	return thrift.NewTBufferedTransport(&TPipe{Conn: conn}, 4096), nil
}

// func (t *TPipe) readAll() error {
// 	fmt.Println("readAll")
// 	_, err := io.Copy(&t.buf, t.Conn)
// 	return err
// }

// func (t *TPipe) Read(b []byte) (n int, err error) {
// 	t.readAll()
// 	fmt.Println("Read completed readAll")
// 	return t.buf.Read(b)
// }

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

func (t *TPipe) RemainingBytes() uint64 {
	// t.readAll()
	// return uint64(t.buf.Len())
	fmt.Println("returning length 0")
	return 0
}

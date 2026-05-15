package utils

import (
	"io"
	"sync"
)

var bufPool = sync.Pool{
	New: func() any {
		b := make([]byte, 128*1024) // 128KB buffer for high throughput
		return &b
	},
}

// Relay copies data bidirectionally between two connections.
// It uses a 128KB buffer pool to drastically reduce syscalls and flush overhead
// for high-throughput proxy tunnels, without allocating memory on every connection.
// Returns the first error encountered, or nil if both finish with EOF.
func Relay(left, right io.ReadWriteCloser) error {
	errChan := make(chan error, 2)

	go func() {
		buf := bufPool.Get().(*[]byte)
		_, err := io.CopyBuffer(right, left, *buf)
		bufPool.Put(buf)
		
		// Attempt half-close if supported
		if c, ok := right.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
		errChan <- err
	}()

	go func() {
		buf := bufPool.Get().(*[]byte)
		_, err := io.CopyBuffer(left, right, *buf)
		bufPool.Put(buf)
		
		// Attempt half-close if supported
		if c, ok := left.(interface{ CloseWrite() error }); ok {
			c.CloseWrite()
		}
		errChan <- err
	}()

	return <-errChan
}

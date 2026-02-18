package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// Dialer abstracts the connection creation.
type Dialer interface {
	Dial(target string) (io.ReadWriteCloser, error)
}

// NetDialer implements Dialer using standard net.Dial
type NetDialer struct{}

func (d *NetDialer) Dial(target string) (io.ReadWriteCloser, error) {
	return net.Dial("tcp", target)
}

// HandleConnection performs the SOCKS5 handshake.
// conn: The client connection.
// dialer: The strategy to connect to the target.
// enableUDP: Whether to allow UDP ASSOCIATE.
func HandleConnection(conn io.ReadWriteCloser, dialer Dialer, enableUDP bool) error {
	defer conn.Close()

	// 1. Negotiation Phase
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return fmt.Errorf("failed to read header: %v", err)
	}

	if header[0] != 0x05 {
		return fmt.Errorf("unsupported socks version: %d", header[0])
	}

	numMethods := int(header[1])
	methods := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, methods); err != nil {
		return fmt.Errorf("failed to read methods: %v", err)
	}

	// Reply: Select NoAuth
	conn.Write([]byte{0x05, 0x00})

	// 2. Request Phase
	reqHeader := make([]byte, 4)
	if _, err := io.ReadFull(conn, reqHeader); err != nil {
		return fmt.Errorf("failed to read request header: %v", err)
	}

	cmd := reqHeader[1]
	if cmd == 0x03 { // UDP ASSOCIATE
		if !enableUDP {
			// UDP Disabled
			conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0}) // Command not supported / prohibited
			return fmt.Errorf("udp associate disabled")
		}
		// Delegate to UDP Handler
		// Note: We need to consume the rest of the request packet first!
		// The request contains DST.ADDR and DST.PORT (which are ignored for UDP ASSOCIATE usually, but we must read them).
		// We already read [VER, CMD, RSV, ATYP].
		// Now read address.
	} else if cmd != 0x01 { // CONNECT
		return fmt.Errorf("unsupported command: %d", cmd)
	}

	addrType := reqHeader[3]
	var targetAddr string

	switch addrType {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		targetAddr = net.IP(buf).String()
	case 0x03: // Domain
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(conn, lenBuf); err != nil {
			return err
		}
		domainLen := int(lenBuf[0])
		domainBuf := make([]byte, domainLen)
		if _, err := io.ReadFull(conn, domainBuf); err != nil {
			return err
		}
		targetAddr = string(domainBuf)
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return err
		}
		// Fix IPv6 formatting for net.Dial
		targetAddr = fmt.Sprintf("[%s]", net.IP(buf).String())
	default:
		return fmt.Errorf("unknown address type: %d", addrType)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBuf); err != nil {
		return err
	}
	port := binary.BigEndian.Uint16(portBuf)

	// If UDP ASSOCIATE, handle it now
	if cmd == 0x03 {
		return HandleUDP(conn, dialer)
	}

	target := fmt.Sprintf("%s:%d", targetAddr, port)

	// 3. Connect via Dialer
	destConn, err := dialer.Dial(target)
	if err != nil {
		// Error reply
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return fmt.Errorf("failed to dial target %s: %v", target, err)
	}
	defer destConn.Close()

	// Success reply
	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	// 4. Proxy
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(destConn, conn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(conn, destConn)
		errChan <- err
	}()

	return <-errChan
}

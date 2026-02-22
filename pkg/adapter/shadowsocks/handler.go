package shadowsocks

import (
	"fmt"
	"io"
	"log"
	"net"
	"strings"

	"github.com/shadowsocks/go-shadowsocks2/core"
	"github.com/shadowsocks/go-shadowsocks2/socks"
)

// Dialer abstracts connection creation to the Phoenix server tunnel.
type Dialer interface {
	Dial(target string) (io.ReadWriteCloser, error)
}

// ListenAndServe starts a Shadowsocks server on the given address.
// It decrypts incoming SS connections, extracts the target address,
// and dials the Phoenix server to relay traffic.
//
// auth format: "method:password" (e.g., "aes-256-gcm:my-secret")
func ListenAndServe(addr, auth string, dialer Dialer) error {
	method, password, err := parseAuth(auth)
	if err != nil {
		return err
	}

	ciph, err := core.PickCipher(method, nil, password)
	if err != nil {
		return fmt.Errorf("failed to initialize cipher %s: %v", method, err)
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("failed to listen on %s: %v", addr, err)
	}
	log.Printf("[Shadowsocks] Listening on %s (cipher: %s)", addr, method)

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("[Shadowsocks] Accept error: %v", err)
			continue
		}
		go handleConn(ciph.StreamConn(conn), dialer)
	}
}

// handleConn handles a single Shadowsocks connection.
// The conn is already wrapped with the AEAD cipher (decrypted).
func handleConn(conn net.Conn, dialer Dialer) {
	defer conn.Close()

	// 1. Read target address from decrypted stream
	// In Shadowsocks, the first bytes of the decrypted stream contain the target address
	// in SOCKS address format: [ATYP][ADDR][PORT]
	tgt, err := socks.ReadAddr(conn)
	if err != nil {
		log.Printf("[Shadowsocks] Failed to read target address: %v", err)
		return
	}

	target := tgt.String()
	log.Printf("[Shadowsocks] Connecting to %s", target)

	// 2. Dial Phoenix server with the target
	stream, err := dialer.Dial(target)
	if err != nil {
		log.Printf("[Shadowsocks] Failed to dial %s: %v", target, err)
		return
	}
	defer stream.Close()

	// 3. Bidirectional relay
	errChan := make(chan error, 2)
	go func() {
		_, err := io.Copy(stream, conn)
		errChan <- err
	}()
	go func() {
		_, err := io.Copy(conn, stream)
		errChan <- err
	}()

	<-errChan
}

// parseAuth splits "method:password" into its components.
func parseAuth(auth string) (method, password string, err error) {
	parts := strings.SplitN(auth, ":", 2)
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return "", "", fmt.Errorf("invalid auth format: expected 'method:password', got %q", auth)
	}
	return parts[0], parts[1], nil
}

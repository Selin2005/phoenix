package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"strings"
	"sync"
)

// HandleUDPTunnel handles the server-side logic for a UDP tunnel stream.
// It reads encapsulated UDP packets from the stream, sends them to the target,
// and relays responses back.
func HandleUDPTunnel(stream io.ReadWriteCloser, dialer Dialer) error {
	defer stream.Close()

	// We use a map to keep track of active UDP connections per destination.
	conns := make(map[string]net.Conn)
	var mu sync.Mutex
	defer func() {
		mu.Lock()
		for _, c := range conns {
			c.Close()
		}
		mu.Unlock()
	}()

	// 2. Stream -> UDP Loop
	errChan := make(chan error, 2)
	
	// Ensure synchronized writes to stream
	var streamMu sync.Mutex

	go func() {
		header := make([]byte, 2)
		for {
			// Read Length
			if _, err := io.ReadFull(stream, header); err != nil {
				errStr := err.Error()
				if err != io.EOF && !strings.Contains(errStr, "CANCEL") && !strings.Contains(errStr, "client disconnected") {
					log.Printf("[SOCKS5-UDP-Server] Stream read error: %v", err)
				}
				errChan <- err
				return
			}
			pktLen := int(binary.BigEndian.Uint16(header))
			if pktLen > 65535 {
				errChan <- fmt.Errorf("packet too large: %d", pktLen)
				return
			}

			pktBuf := make([]byte, pktLen)
			if _, err := io.ReadFull(stream, pktBuf); err != nil {
				errChan <- err
				return
			}

			// Parse SOCKS5 UDP Header to extract Destination
			if len(pktBuf) < 10 { // Min header size (IPv4)
				log.Printf("[SOCKS5-UDP] Packet too short")
				continue
			}

			// Offset 3 is ATYP
			atyp := pktBuf[3]
			var destAddr string
			var dataOffset int
			var headerBytes []byte

			switch atyp {
			case 0x01: // IPv4
				if len(pktBuf) < 10 {
					continue
				}
				ip := net.IP(pktBuf[4:8])
				port := binary.BigEndian.Uint16(pktBuf[8:10])
				destAddr = fmt.Sprintf("%s:%d", ip, port)
				dataOffset = 10
				headerBytes = make([]byte, 10)
				copy(headerBytes, pktBuf[:10])
			case 0x03: // Domain
				if len(pktBuf) < 5 {
					continue
				}
				domainLen := int(pktBuf[4])
				if len(pktBuf) < 5+domainLen+2 {
					continue
				}
				domain := string(pktBuf[5 : 5+domainLen])
				port := binary.BigEndian.Uint16(pktBuf[5+domainLen : 5+domainLen+2])
				destAddr = fmt.Sprintf("%s:%d", domain, port)
				dataOffset = 5 + domainLen + 2
				headerBytes = make([]byte, dataOffset)
				copy(headerBytes, pktBuf[:dataOffset])
			case 0x04: // IPv6
				if len(pktBuf) < 22 {
					continue
				}
				ip := net.IP(pktBuf[4:20])
				port := binary.BigEndian.Uint16(pktBuf[20:22])
				destAddr = fmt.Sprintf("[%s]:%d", ip, port)
				dataOffset = 22
				headerBytes = make([]byte, 22)
				copy(headerBytes, pktBuf[:22])
			default:
				log.Printf("[SOCKS5-UDP] Unknown ATYP %d", atyp)
				continue
			}

			// Payload
			payload := pktBuf[dataOffset:]

			// Get or Create UDP Connection for this destination
			mu.Lock()
			conn, exists := conns[destAddr]
			if !exists {
				var err error
				conn, err = dialer.Dial("udp", destAddr)
				if err != nil {
					log.Printf("[SOCKS5-UDP] Failed to dial %s: %v", destAddr, err)
					mu.Unlock()
					continue
				}
				conns[destAddr] = conn

				// Start reader for this new connection
				go func(c net.Conn, dAddr string, hdr []byte) {
					buf := make([]byte, 65535)
					for {
						n, err := c.Read(buf)
						if err != nil {
							c.Close()
							mu.Lock()
							delete(conns, dAddr)
							mu.Unlock()
							return
						}

						// Construct SOCKS5 UDP Packet to send back
						totalLen := len(hdr) + n
						packet := make([]byte, 2+totalLen)
						binary.BigEndian.PutUint16(packet, uint16(totalLen))
						copy(packet[2:], hdr)
						copy(packet[2+len(hdr):], buf[:n])

						streamMu.Lock()
						_, err = stream.Write(packet)
						streamMu.Unlock()
						if err != nil {
							errStr := err.Error()
							if !strings.Contains(errStr, "CANCEL") && !strings.Contains(errStr, "client disconnected") {
								log.Printf("[SOCKS5-UDP-Server] Failed to write to stream: %v", err)
							}
							errChan <- err
							return
						}
					}
				}(conn, destAddr, headerBytes)
			}
			mu.Unlock()

			// Write to Target
			if _, err := conn.Write(payload); err != nil {
				log.Printf("[SOCKS5-UDP] Write error: %v", err)
				// Close connection on error to force reconnect next time
				conn.Close()
				mu.Lock()
				delete(conns, destAddr)
				mu.Unlock()
				continue
			}
		}
	}()

	err := <-errChan
	if err != nil && err != io.EOF {
		errStr := err.Error()
		if !strings.Contains(errStr, "CANCEL") && !strings.Contains(errStr, "client disconnected") && !strings.Contains(errStr, "connection reset by peer") {
			log.Printf("[SOCKS5-UDP-Server] Closing session due to: %v", err)
		}
	}
	return err
}

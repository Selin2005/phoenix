package socks5

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
)

// HandleUDP establishes a UDP relay.
// conn: The client TCP connection (must stay open).
// dialer: The strategy to verify target connectivity (or tunnel).
// clientAddr: The address of the client requesting UDP.
// header: The client's UDP request header containing initial destination (optional/ignored for ASSOCIATE usually).
func HandleUDP(conn io.ReadWriteCloser, dialer Dialer) error {
	// 1. Listen on a random UDP port
	udpConn, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return fmt.Errorf("failed to listen on UDP: %v", err)
	}
	defer udpConn.Close()

	addr := udpConn.LocalAddr().(*net.UDPAddr)
	log.Printf("[SOCKS5] UDP Associate bound to %s", addr)

	// 2. Send Reply: BND.ADDR and BND.PORT
	// We need IP and Port separate.
	// Assume IPv4 for simplicity or extract from addr.
	ip := addr.IP.To4()
	if ip == nil {
		ip = addr.IP.To16()
	}
	// Reply format: [VER, REP, RSV, ATYP, BND.ADDR, BND.PORT]
	// REP=00 (Success)
	reply := make([]byte, 4+len(ip)+2)
	reply[0] = 0x05
	reply[1] = 0x00
	reply[2] = 0x00
	if len(ip) == 4 {
		reply[3] = 0x01
	} else {
		reply[3] = 0x04
	}
	copy(reply[4:], ip)
	binary.BigEndian.PutUint16(reply[4+len(ip):], uint16(addr.Port))

	if _, err := conn.Write(reply); err != nil {
		return fmt.Errorf("failed to write UDP reply: %v", err)
	}

	// 3. Keep TCP Connection open and monitor UDP
	// The TCP connection serves as a keep-alive signal.
	// If it closes, we stop the UDP listener.

	// Create a tunnel stream to Server for UDP traffic
	// We initiate ONE stream for this association.
	// The Dialer here (PhoenixTunnelDialer) opens a stream with "socks5-udp" protocol.
	// We don't have a specific target yet (UDP packets have their own targets).
	// So we dial with empty target?
	// Or we use a special "udp-relay" target?
	// Server side "socks5-udp" logic expects packets.

	// stream, err := dialer.Dial("") // Empty target for UDP Tunnel
	stream, err := dialer.Dial("udp-tunnel")
	if err != nil {
		return fmt.Errorf("failed to dial UDP tunnel: %v", err)
	}
	defer stream.Close()

	// 4. Relay Loop
	// We need concurrent relay:
	// A) UDP -> Stream
	// B) Stream -> UDP

	errChan := make(chan error, 2)

	// UDP -> Stream
	go func() {
		buf := make([]byte, 65535) // Max UDP size
		for {
			n, peerAddr, err := udpConn.ReadFrom(buf)
			if err != nil {
				errChan <- err
				return
			}

			// Validate peerAddr?
			// RFC 1928 says we should only accept from the client causing the ASSOCIATION.
			// But for simplicity, accept all.

			// UDP Packet from Client has format: [RSV][FRAG][ATYP][DST.ADDR][DST.PORT][DATA]
			// We verify fragmentation is not supported (FRAG=0).
			if n < 3 {
				continue // Too short
			}
			frag := buf[2]
			if frag != 0x00 {
				log.Printf("[SOCKS5] UDP Frag %d not supported", frag)
				continue
			}

			// Encapsulate into Stream: [Length (2 bytes)][Packet]
			// Packet is buf[:n] (the SOCKS5 UDP request as is).
			// We send it AS IS to Server.
			// Server unwraps, extracts Dest, Sends.

			// Write length
			lenBuf := make([]byte, 2)
			binary.BigEndian.PutUint16(lenBuf, uint16(n))

			if _, err := stream.Write(lenBuf); err != nil {
				errChan <- err
				return
			}
			if _, err := stream.Write(buf[:n]); err != nil {
				errChan <- err
				return
			}

			// Log peerAddr for debug?
			_ = peerAddr
		}
	}()

	// Stream -> UDP
	go func() {
		header := make([]byte, 2)
		for {
			// Read Length
			if _, err := io.ReadFull(stream, header); err != nil {
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

			// The packet is a SOCKS5 UDP header + Data.
			// Format: [RSV][FRAG][ATYP][DST.ADDR][DST.PORT][DATA]
			// IMPORTANT: DST.ADDR here is the SOURCE of the UDP packet (e.g. YouTube Server).
			// The Client expects this so it knows who sent the data.
			// We simply forward to Client via udpConn.Wait?
			// We must send to the Client's UDP address.
			// But we don't know Client's UDP address until it sends us a packet!
			// `ReadFrom` tells us `peerAddr`.
			// We should store `clientAddr` from the first ReadFrom?
			//
			// RFC 1928: "The server MUST relay the UDP datagram to the client... using the value of the port and IP address from the UDP REQUEST header sending it to the client."
			// Wait, no. The server sends TO the client's address.
			// But which address? The one that sent the ASSOCIATION request? Or the one sending UDP packets?
			// Usually the one sending UDP packets.
			// So we need to capture `peerAddr` from the `ReadFrom` loop and use it here.
			//
			// Solution: Use a `currentClientAddr` variable protected by mutex/atomic.
			// Or pass it via channel?
			// Since SOCKS5 UDP Associate is 1-to-1 usually, we can just latch on the first packet's source.

			// We'll trust that client sends a packet first.
			// If stream sends data before client sends packet, we drop it?
			// Actually, SOCKS5 UDP Associate flow: Client sends UDP packet first to establish mapping.
			// So we can wait for `peerAddr` to be set.

			// But `udpConn.WriteTo` requires an address.
			// I'll implement a simple address cache.
			// But `net.PacketConn` `WriteTo` needs `net.Addr`.
			// I can't access `peerAddr` from the other goroutine easily without synchronization.
			// Simplest hack: The TCP connection stays open.
			// Can we get Client IP from TCP conn?
			// `HandleConnection` receives `io.ReadWriteCloser`. Not `net.Conn`.
			// But `cmd/client/main.go` passes `net.Conn`.
			// I should cast it.
		}
	}()

	// Wait for TCP close or Stream error
	// Also wait for TCP input to detect closure.
	go func() {
		buf := make([]byte, 1)
		conn.Read(buf) // Block until EOF
		errChan <- fmt.Errorf("tcp control connection closed")
	}()

	return <-errChan
}

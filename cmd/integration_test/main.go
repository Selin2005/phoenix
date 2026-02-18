package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"time"

	"golang.org/x/net/proxy"
)

func main() {
	// 1. Build binaries
	log.Println("Building binaries...")
	cmd := exec.Command("make", "build")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatalf("Build failed: %v", err)
	}

	// 2. Start Echo Servers
	go startTCPEchoServer(":9001")
	go startUDPEchoServer(":9002")

	// 3. Start Phoenix Server
	log.Println("Starting Phoenix Server...")
	serverCmd := exec.Command("./bin/server", "--config", "example_server.toml")
	serverCmd.Stdout = os.Stdout
	serverCmd.Stderr = os.Stderr
	if err := serverCmd.Start(); err != nil {
		log.Fatalf("Failed to start server: %v", err)
	}
	defer func() {
		serverCmd.Process.Kill()
	}()

	// 4. Start Phoenix Client
	log.Println("Starting Phoenix Client...")
	clientCmd := exec.Command("./bin/client", "--config", "example_client.toml")
	clientCmd.Stdout = os.Stdout
	clientCmd.Stderr = os.Stderr
	if err := clientCmd.Start(); err != nil {
		log.Fatalf("Failed to start client: %v", err)
	}
	defer func() {
		clientCmd.Process.Kill()
	}()

	time.Sleep(2 * time.Second) // Wait for startup

	// 5. Test TCP
	log.Println("=== Testing TCP via SOCKS5 ===")
	testTCP("127.0.0.1:1080", "127.0.0.1:9001")

	// 6. Test UDP
	log.Println("=== Testing UDP via SOCKS5 ===")
	testUDP("127.0.0.1:1080", "127.0.0.1:9002")

	log.Println("=== ALL TESTS PASSED ===")
}

func startTCPEchoServer(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("TCP Echo Listen failed: %v", err)
	}
	for {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		go io.Copy(conn, conn)
	}
}

func startUDPEchoServer(addr string) {
	conn, err := net.ListenPacket("udp", addr)
	if err != nil {
		log.Fatalf("UDP Echo Listen failed: %v", err)
	}
	buf := make([]byte, 1024)
	for {
		n, peer, err := conn.ReadFrom(buf)
		if err != nil {
			continue
		}
		conn.WriteTo(buf[:n], peer)
	}
}

func testTCP(proxyAddr, targetAddr string) {
	dialer, err := proxy.SOCKS5("tcp", proxyAddr, nil, proxy.Direct)
	if err != nil {
		log.Fatalf("Failed to create SOCKS5 dialer: %v", err)
	}

	conn, err := dialer.Dial("tcp", targetAddr)
	if err != nil {
		log.Fatalf("TCP Dial failed: %v", err)
	}
	defer conn.Close()

	msg := "Hello TCP"
	conn.Write([]byte(msg))

	buf := make([]byte, 1024)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatalf("TCP Read failed: %v", err)
	}

	reply := string(buf[:n])
	if reply != msg {
		log.Fatalf("TCP Mismatch: got %q, want %q", reply, msg)
	}
	log.Printf("TCP Success: %s", reply)
}

func testUDP(proxyAddr, targetAddr string) {
	// Standard Go proxy package does NOT support UDP Associate.
	// We must implement SOCKS5 UDP Associate handshake manually.

	// 1. Connect TCP to Proxy
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		log.Fatalf("UDP Handshake TCP Dial failed: %v", err)
	}
	defer conn.Close()

	// 2. Handshake (Auth)
	// Send [HEX: 05 01 00] (VER 5, NMETHODS 1, METHOD 0)
	conn.Write([]byte{0x05, 0x01, 0x00})

	buf := make([]byte, 2)
	if _, err := io.ReadFull(conn, buf); err != nil {
		log.Fatalf("UDP Handshake Read failed: %v", err)
	}
	if buf[0] != 0x05 || buf[1] != 0x00 {
		log.Fatalf("UDP Handshake Method rejected: %v", buf)
	}

	// 3. Request UDP ASSOCIATE
	// Format: [05, 03, 00, 01, 0,0,0,0, 0,0] (Listen on 0.0.0.0:0)
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	conn.Write(req)

	// 4. Read Reply
	// Format: [05, 00, 00, ATYP, BND.ADDR, BND.PORT]
	// We need BND.PORT to know where to send UDP packets.
	reply := make([]byte, 10) // IPv4 response usually
	if _, err := io.ReadFull(conn, reply); err != nil {
		log.Fatalf("UDP Handshake Reply Read failed: %v", err)
	}
	if reply[1] != 0x00 {
		log.Fatalf("UDP Handshake Failed with Rep: %d", reply[1])
	}

	// Parse BND.ADDR/PORT
	var relayIP net.IP
	var relayPort int
	if reply[3] == 0x01 {
		// IPv4
		relayIP = net.IP(reply[4:8])
		relayPort = int(binary.BigEndian.Uint16(reply[8:10]))
	} else if reply[3] == 0x04 {
		// IPv6
		// We already read 10 bytes: [VER, REP, RSV, ATYP(1), ADDR(4), PORT(2)? NO]
		// Reply buffer size was 10.
		// If ATYP=4 (IPv6), header is: 4 bytes (VER..ATYP) + 16 bytes IP + 2 bytes PORT = 22 bytes.
		// We read 10 bytes. So we have VER..ATYP (4) + first 6 bytes of IPv6.
		// We need to read 12 more bytes.
		rest := make([]byte, 12)
		if _, err := io.ReadFull(conn, rest); err != nil {
			log.Fatalf("UDP Handshake IPv6 Read failed: %v", err)
		}
		// Full Buffer = reply (10) + rest (12) = 22.
		full := append(reply, rest...)
		relayIP = net.IP(full[4:20])
		relayPort = int(binary.BigEndian.Uint16(full[20:22]))
	}
	_ = relayIP

	// Note: BND.ADDR might be 0.0.0.0 or internal IP.
	// We should send to proxyAddr's IP, but use relayPort.
	proxyHost, _, _ := net.SplitHostPort(proxyAddr)
	relayAddr := fmt.Sprintf("%s:%d", proxyHost, relayPort)
	log.Printf("UDP Relay is at: %s", relayAddr)

	// 5. Send UDP Packet
	uConn, err := net.Dial("udp", relayAddr)
	if err != nil {
		log.Fatalf("UDP Dial failed: %v", err)
	}
	defer uConn.Close()

	// SOCKS5 UDP Header: [00 00 00 01 DST_IP DST_PORT DATA]
	// DST = 127.0.0.1:9002
	pkt := make([]byte, 0, 1024)
	pkt = append(pkt, 0x00, 0x00, 0x00, 0x01) // RSV, FRAG, ATYP=IPv4
	pkt = append(pkt, []byte{127, 0, 0, 1}...)
	port := make([]byte, 2)
	binary.BigEndian.PutUint16(port, 9002)
	pkt = append(pkt, port...)

	msg := "Hello UDP"
	pkt = append(pkt, []byte(msg)...)

	if _, err := uConn.Write(pkt); err != nil {
		log.Fatalf("UDP Write failed: %v", err)
	}

	// 6. Read Reply
	// SOCKS5 UDP Header + Data
	resp := make([]byte, 1024)
	uConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := uConn.Read(resp)
	if err != nil {
		log.Fatalf("UDP Read failed: %v", err)
	}

	// Parse header
	// [00 00 00 01 ...] 10 bytes header
	if n < 10 {
		log.Fatalf("UDP Reply too short: %d", n)
	}

	replyMsg := string(resp[10:n])
	if replyMsg != msg {
		log.Fatalf("UDP Mismatch: got %q, want %q", replyMsg, msg)
	}
	log.Printf("UDP Success: %s", replyMsg)
}

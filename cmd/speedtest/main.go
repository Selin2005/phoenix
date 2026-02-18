package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"phoenix/pkg/config"
	"phoenix/pkg/protocol"
	"phoenix/pkg/transport"
	"time"
)

func main() {
	// 1. Setup Server
	serverPort := "127.0.0.1:0"
	l, err := net.Listen("tcp", serverPort)
	if err != nil {
		log.Fatal(err)
	}
	serverAddr := l.Addr().String()
	l.Close() // Close to allow server to listen

	serverCfg := config.DefaultServerConfig()
	serverCfg.ListenAddr = serverAddr
	serverCfg.Security.EnableSOCKS5 = true
	serverCfg.Security.EnableSSH = true

	go func() {
		if err := transport.StartServer(serverCfg); err != nil {
			log.Printf("Server error: %v", err)
		}
	}()

	// Wait for server to start
	time.Sleep(1 * time.Second)

	// 2. Setup Client
	clientCfg := config.DefaultClientConfig()
	clientCfg.RemoteAddr = serverAddr

	client := transport.NewClient(clientCfg)

	// 3. Test Upload Speed (Direct Tunnel)
	fmt.Println("Starting Upload Speed Test (Client -> Server)...")
	start := time.Now()
	dataSize := 100 * 1024 * 1024 // 100MB

	// We need a way to measure without reading from disk.
	// We dial an SSH/Echo endpoint that consumes data?
	// Our server implementation copies input to output if unknown or just consumes?
	// If protocol is SSH and target is empty -> it copies back (Echo).
	// If we send 100MB to Echo and read 100MB back, that's Download + Upload?
	//
	// Better: We implement a special "benchmark" protocol or use existing behavior.
	// If we use "ssh" with target "", it echoes.
	// Upload: Write 100MB, discard reads.
	// Download: Read 100MB (trigger echo), discard writes? No, Echo requires input.

	// Let's rely on standard SSH tunnel to a local Echo server.

	// Start a local Echo Server (Target)
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	echoAddr := echoLn.Addr().String()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c) // Echo
		}
	}()

	// Dial via Client
	stream, err := client.Dial(protocol.ProtocolSSH, echoAddr)
	if err != nil {
		log.Fatalf("Dial failed: %v", err)
	}

	// Generate data
	chunk := make([]byte, 32*1024)
	totalWritten := 0

	go func() {
		// Read/Discard response to prevent blocking
		io.Copy(io.Discard, stream)
	}()

	for totalWritten < dataSize {
		n, err := stream.Write(chunk)
		if err != nil {
			log.Fatalf("Write failed: %v", err)
		}
		totalWritten += n
	}
	duration := time.Since(start)
	mbps := float64(dataSize) / 1024 / 1024 / duration.Seconds()
	fmt.Printf("Upload Speed: %.2f MB/s\n", mbps)

	if mbps < 1.0 {
		fmt.Println("WARNING: Speed < 1MB/s. Consider increasing buffer sizes in transport/server.go handles.")
	}

	// 4. Test Download Speed (Server -> Client)
	// We use the same Echo connection we just flooded? No, we closed it implicitly/explicitly?
	stream.Close()

	// New connection for Download
	// We send commands to Echo server to "Push Data"?
	// Standard Echo server only echoes. So we must Upload X to Download X.
	// So Upload speed is entangled with Download speed if we use Echo.

	// Alternative: Only measure Round Trip for simplicity or combined throughput.
	// The prompt asks for "Upload Speed" AND "Download Speed".
	// To separate them, we need a Sink and a Source.
	//
	// I'll create a Sink Server (discards input) and Source Server (generates garbage).

	// Sink Server
	sinkLn, _ := net.Listen("tcp", "127.0.0.1:0")
	sinkAddr := sinkLn.Addr().String()
	go func() {
		for {
			c, _ := sinkLn.Accept()
			io.Copy(io.Discard, c)
		}
	}()

	// Source Server
	sourceLn, _ := net.Listen("tcp", "127.0.0.1:0")
	sourceAddr := sourceLn.Addr().String()
	go func() {
		for {
			c, _ := sourceLn.Accept()
			// Generate 100MB
			data := make([]byte, 32*1024)
			limit := 100 * 1024 * 1024
			written := 0
			for written < limit {
				n, _ := c.Write(data)
				written += n
			}
			c.Close()
		}
	}()

	// Measure Upload (Client -> Sink via Server)
	start = time.Now()
	upStream, _ := client.Dial(protocol.ProtocolSSH, sinkAddr)
	totalWritten = 0
	for totalWritten < dataSize {
		n, _ := upStream.Write(chunk)
		totalWritten += n
	}
	upDuration := time.Since(start)
	upMbps := float64(dataSize) / 1024 / 1024 / upDuration.Seconds()
	fmt.Printf("Pure Upload Speed: %.2f MB/s\n", upMbps)
	upStream.Close()

	// Measure Download (Client <- Source via Server)
	start = time.Now()
	downStream, _ := client.Dial(protocol.ProtocolSSH, sourceAddr)
	// Trigger source (it starts on accept) - actually we need to read.
	// The dial connects, accept happens, source starts writing.
	received, _ := io.Copy(io.Discard, downStream)
	downDuration := time.Since(start)
	downMbps := float64(received) / 1024 / 1024 / downDuration.Seconds()
	fmt.Printf("Pure Download Speed: %.2f MB/s\n", downMbps)

	// Latency
	start = time.Now()
	pingStream, _ := client.Dial(protocol.ProtocolSSH, echoAddr)
	pingStream.Write([]byte("ping"))
	buf := make([]byte, 4)
	pingStream.Read(buf)
	latency := time.Since(start)
	fmt.Printf("Latency (RTT): %v\n", latency)
	pingStream.Close()

	os.Exit(0)
}

package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"phoenix/pkg/config"
	"phoenix/pkg/crypto"
	"phoenix/pkg/protocol"
	"phoenix/pkg/transport"
	"time"
)

func main() {
	// Start shared helper servers
	echoAddr := startEchoServer()
	sinkAddr := startSinkServer()
	sourceAddr := startSourceServer(100 * 1024 * 1024) // 100MB
	time.Sleep(500 * time.Millisecond)

	// Generate keys + token once (for TLS phases)
	privServer, _, _ := crypto.GenerateKeypair() // Ed25519 — for phases 3
	ecdsaServer, _ := crypto.GenerateECDSAKey()  // ECDSA P256 — for Chrome fingerprint phase
	token, _ := crypto.GenerateToken()
	os.WriteFile("spd_server.key", privServer, 0600)
	os.WriteFile("spd_ecdsa_server.key", ecdsaServer, 0600)
	defer os.Remove("spd_server.key")
	defer os.Remove("spd_ecdsa_server.key")

	results := []benchResult{}

	// ── Phase 1: Direct h2c ───────────────────────────────
	printPhase("PHASE 1: Direct h2c (No Auth, No TLS)")
	cfg1s := config.DefaultServerConfig()
	cfg1s.ListenAddr = findFreeAddr()
	cfg1s.Security.EnableSOCKS5 = true
	cfg1s.Security.EnableSSH = true

	cfg1c := config.DefaultClientConfig()
	cfg1c.RemoteAddr = cfg1s.ListenAddr

	results = append(results, runBenchmark("Direct h2c", cfg1s, cfg1c, echoAddr, sinkAddr, sourceAddr))

	// ── Phase 2: h2c + Token ──────────────────────────────
	printPhase("PHASE 2: h2c + Token Auth")
	cfg2s := config.DefaultServerConfig()
	cfg2s.ListenAddr = findFreeAddr()
	cfg2s.Security.EnableSOCKS5 = true
	cfg2s.Security.EnableSSH = true
	cfg2s.Security.AuthToken = token

	cfg2c := config.DefaultClientConfig()
	cfg2c.RemoteAddr = cfg2s.ListenAddr
	cfg2c.AuthToken = token

	results = append(results, runBenchmark("h2c + Token", cfg2s, cfg2c, echoAddr, sinkAddr, sourceAddr))

	// ── Phase 3: Insecure TLS + Token ─────────────────────
	printPhase("PHASE 3: Insecure TLS + Token Auth")
	cfg3s := config.DefaultServerConfig()
	cfg3s.ListenAddr = findFreeAddr()
	cfg3s.Security.EnableSOCKS5 = true
	cfg3s.Security.EnableSSH = true
	cfg3s.Security.PrivateKeyPath = "spd_server.key"
	cfg3s.Security.AuthToken = token

	cfg3c := config.DefaultClientConfig()
	cfg3c.RemoteAddr = cfg3s.ListenAddr
	cfg3c.TLSMode = "insecure"
	cfg3c.AuthToken = token

	results = append(results, runBenchmark("Insecure TLS + Token", cfg3s, cfg3c, echoAddr, sinkAddr, sourceAddr))

	// ── Phase 4: Insecure TLS + Chrome Fingerprint ────────
	printPhase("PHASE 4: Insecure TLS + Chrome Fingerprint")
	cfg4s := config.DefaultServerConfig()
	cfg4s.ListenAddr = findFreeAddr()
	cfg4s.Security.EnableSOCKS5 = true
	cfg4s.Security.EnableSSH = true
	cfg4s.Security.PrivateKeyPath = "spd_ecdsa_server.key"

	cfg4c := config.DefaultClientConfig()
	cfg4c.RemoteAddr = cfg4s.ListenAddr
	cfg4c.TLSMode = "insecure"
	cfg4c.Fingerprint = "chrome"

	results = append(results, runBenchmark("Insecure TLS + Chrome", cfg4s, cfg4c, echoAddr, sinkAddr, sourceAddr))

	// ── Summary ───────────────────────────────────────────
	fmt.Println("\n╔════════════════════════════════════════════════════════╗")
	fmt.Println("║                  BENCHMARK SUMMARY                    ║")
	fmt.Println("╠════════════════╦══════════════╦══════════════╦════════╣")
	fmt.Printf("║ %-14s ║ %-12s ║ %-12s ║ %-6s ║\n", "Mode", "Upload MB/s", "Download MB/s", "RTT")
	fmt.Println("╠════════════════╬══════════════╬══════════════╬════════╣")
	for _, r := range results {
		fmt.Printf("║ %-14s ║ %11.1f  ║ %11.1f  ║ %s ║\n",
			truncate(r.name, 14), r.uploadMBs, r.downloadMBs, formatRTT(r.latency))
	}
	fmt.Println("╚════════════════╩══════════════╩══════════════╩════════╝")

	fmt.Println("\n  ALL BENCHMARKS COMPLETE ✓")
	os.Exit(0)
}

// ─── Benchmark ─────────────────────────────────────────────

type benchResult struct {
	name        string
	uploadMBs   float64
	downloadMBs float64
	latency     time.Duration
}

func runBenchmark(name string, serverCfg *config.ServerConfig, clientCfg *config.ClientConfig, echoAddr, sinkAddr, sourceAddr string) benchResult {
	// Start server
	go func() {
		if err := transport.StartServer(serverCfg); err != nil {
			log.Printf("[%s] Server error: %v", name, err)
		}
	}()
	time.Sleep(1 * time.Second)

	client := transport.NewClient(clientCfg)
	dataSize := 100 * 1024 * 1024 // 100MB
	chunk := make([]byte, 32*1024)

	// Upload
	fmt.Printf("[%s] Upload Speed Test (100MB)...\n", name)
	start := time.Now()
	upStream, err := client.Dial(protocol.ProtocolSSH, sinkAddr)
	if err != nil {
		log.Fatalf("[%s] Upload Dial failed: %v", name, err)
	}
	totalWritten := 0
	for totalWritten < dataSize {
		n, err := upStream.Write(chunk)
		if err != nil {
			log.Fatalf("[%s] Upload Write failed: %v", name, err)
		}
		totalWritten += n
	}
	upDuration := time.Since(start)
	upMBs := float64(dataSize) / 1024 / 1024 / upDuration.Seconds()
	fmt.Printf("[%s] Upload Speed:   %.2f MB/s\n", name, upMBs)
	upStream.Close()

	// Download
	fmt.Printf("[%s] Download Speed Test (100MB)...\n", name)
	start = time.Now()
	downStream, err := client.Dial(protocol.ProtocolSSH, sourceAddr)
	if err != nil {
		log.Fatalf("[%s] Download Dial failed: %v", name, err)
	}
	received, _ := io.Copy(io.Discard, downStream)
	downDuration := time.Since(start)
	downMBs := float64(received) / 1024 / 1024 / downDuration.Seconds()
	fmt.Printf("[%s] Download Speed: %.2f MB/s\n", name, downMBs)

	// Latency (RTT)
	start = time.Now()
	pingStream, err := client.Dial(protocol.ProtocolSSH, echoAddr)
	if err != nil {
		log.Fatalf("[%s] Latency Dial failed: %v", name, err)
	}
	pingStream.Write([]byte("ping"))
	buf := make([]byte, 4)
	pingStream.Read(buf)
	latency := time.Since(start)
	fmt.Printf("[%s] Latency (RTT):  %v\n", name, latency)
	pingStream.Close()

	return benchResult{name: name, uploadMBs: upMBs, downloadMBs: downMBs, latency: latency}
}

// ─── Helpers ───────────────────────────────────────────────

func printPhase(title string) {
	fmt.Printf("\n====================================\n  %s\n====================================\n", title)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n-1] + "…"
}

func formatRTT(d time.Duration) string {
	ms := d.Milliseconds()
	if ms < 10 {
		return fmt.Sprintf("%5.1fms", float64(d.Microseconds())/1000)
	}
	return fmt.Sprintf("%5dms", ms)
}

// ─── Helper Servers ────────────────────────────────────────

func startEchoServer() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(c, c)
		}
	}()
	return ln.Addr().String()
}

func startSinkServer() string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go io.Copy(io.Discard, c)
		}
	}()
	return ln.Addr().String()
}

func startSourceServer(limit int) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				data := make([]byte, 32*1024)
				written := 0
				for written < limit {
					n, err := conn.Write(data)
					if err != nil {
						return
					}
					written += n
				}
			}(c)
		}
	}()
	return ln.Addr().String()
}

func findFreeAddr() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	addr := l.Addr().String()
	l.Close()
	return addr
}

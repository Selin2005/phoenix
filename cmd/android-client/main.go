package main

import (
	"encoding/base64"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"path/filepath"
	"phoenix/pkg/adapter/socks5"
	"phoenix/pkg/config"
	"phoenix/pkg/crypto"
	"phoenix/pkg/protocol"
	"phoenix/pkg/transport"
	"sync"
	"syscall"

	"github.com/xjasonlyu/tun2socks/v2/engine"
)

// PhoenixTunnelDialer implements socks5.Dialer by tunneling over HTTP/2.
type PhoenixTunnelDialer struct {
	Client *transport.Client
	Proto  protocol.ProtocolType
}

func (d *PhoenixTunnelDialer) Dial(target string) (io.ReadWriteCloser, error) {
	proto := d.Proto
	if target == "udp-tunnel" {
		proto = protocol.ProtocolSOCKS5UDP
		target = ""
	}
	return d.Client.Dial(proto, target)
}

func main() {
	configPath := flag.String("config", "client.toml", "Path to client configuration file")
	filesDir := flag.String("files-dir", ".", "Directory for writing key files (use Android Context.getFilesDir())")
	getSS := flag.Bool("get-ss", false, "Generate Shadowsocks config from client config")
	genKeys := flag.Bool("gen-keys", false, "Generate a new pair of Ed25519 keys (public/private)")
	tunSocket := flag.String("tun-socket", "", "Abstract Unix socket name for receiving TUN fd via SCM_RIGHTS (VPN mode)")
	flag.Parse()

	if *genKeys {
		priv, pub, err := crypto.GenerateKeypair()
		if err != nil {
			log.Fatalf("Failed to generate keys: %v", err)
		}
		keyPath := filepath.Join(*filesDir, "client.private.key")
		if err := os.WriteFile(keyPath, priv, 0600); err != nil {
			log.Fatalf("Failed to save private key: %v", err)
		}
		// Print to stdout so the Android Service can read the public key.
		fmt.Printf("KEY_PATH=%s\n", keyPath)
		fmt.Printf("PUBLIC_KEY=%s\n", pub)
		return
	}

	cfg, err := config.LoadClientConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	if *getSS {
		generateShadowsocksConfig(cfg)
		return
	}

	client := transport.NewClient(cfg)
	log.Printf("Phoenix Client started. Connecting to %s", cfg.RemoteAddr)

	var wg sync.WaitGroup

	if *tunSocket != "" {
		// ── VPN mode ─────────────────────────────────────────────────────────
		// Find the SOCKS5 inbound address — tun2socks routes into it.
		socksAddr := "127.0.0.1:10080"
		for _, in := range cfg.Inbounds {
			if in.Protocol == protocol.ProtocolSOCKS5 {
				socksAddr = in.LocalAddr
				break
			}
		}

		// ready is closed once the first SOCKS5 listener has bound,
		// ensuring tun2socks doesn't forward packets before the proxy is ready.
		ready := make(chan struct{})
		first := true

		for _, inbound := range cfg.Inbounds {
			wg.Add(1)
			var readyCh chan<- struct{}
			if first {
				readyCh = ready
				first = false
			}
			go func(in config.ClientInbound, ch chan<- struct{}) {
				defer wg.Done()
				startInbound(client, in, ch)
			}(inbound, readyCh)
		}

		// Block until the SOCKS5 listener is bound before receiving the TUN fd.
		<-ready

		tunFd, err := receiveTunFd(*tunSocket)
		if err != nil {
			log.Fatalf("Failed to receive TUN fd: %v", err)
		}
		log.Printf("TUN fd received (%d), starting tun2socks → socks5://%s", tunFd, socksAddr)

		go runTun2socks(tunFd, "socks5://"+socksAddr)

	} else {
		// ── Normal / SOCKS5-only mode ─────────────────────────────────────────
		for _, inbound := range cfg.Inbounds {
			wg.Add(1)
			go func(in config.ClientInbound) {
				defer wg.Done()
				startInbound(client, in, nil)
			}(inbound)
		}
	}

	// Block until all inbounds exit (Android Service kills this process to stop).
	wg.Wait()
}

// receiveTunFd connects to the abstract Unix socket created by the Android
// VpnService, receives the TUN file descriptor via SCM_RIGHTS ancillary data,
// and returns a duplicate of it that is safe to use in this process.
func receiveTunFd(socketName string) (int, error) {
	// Abstract namespace: Go uses "@" prefix which maps to the null byte Linux uses.
	conn, err := net.DialUnix("unix", nil, &net.UnixAddr{
		Name: "@" + socketName,
		Net:  "unix",
	})
	if err != nil {
		return -1, fmt.Errorf("connect to tun socket %q: %w", socketName, err)
	}
	defer conn.Close()

	buf := make([]byte, 1)
	oob := make([]byte, syscall.CmsgSpace(4)) // room for exactly one int (fd)

	_, oobn, _, _, err := conn.ReadMsgUnix(buf, oob)
	if err != nil {
		return -1, fmt.Errorf("ReadMsgUnix: %w", err)
	}

	scms, err := syscall.ParseSocketControlMessage(oob[:oobn])
	if err != nil {
		return -1, fmt.Errorf("ParseSocketControlMessage: %w", err)
	}

	for _, scm := range scms {
		fds, err := syscall.ParseUnixRights(&scm)
		if err != nil {
			continue
		}
		if len(fds) > 0 {
			return fds[0], nil
		}
	}

	return -1, fmt.Errorf("no file descriptor in SCM_RIGHTS ancillary data")
}

// runTun2socks starts the tun2socks engine that reads packets from the TUN
// device (identified by tunFd) and forwards them through the local SOCKS5
// proxy. It blocks indefinitely — the Android service kills this process
// via SIGKILL to stop the VPN, so no explicit shutdown path is needed.
func runTun2socks(tunFd int, proxyURL string) {
	key := &engine.Key{
		Device:   fmt.Sprintf("fd://%d", tunFd),
		Proxy:    proxyURL,
		LogLevel: "warn",
	}

	engine.Insert(key)
	engine.Start() // no return value; calls log.Fatalf internally on setup error

	log.Printf("tun2socks engine running (fd=%d → %s)", tunFd, proxyURL)

	// Block until the process is killed by the Android service.
	select {}
}

func generateShadowsocksConfig(cfg *config.ClientConfig) {
	found := false
	for _, in := range cfg.Inbounds {
		if in.Protocol == protocol.ProtocolShadowsocks {
			found = true
			if in.Auth == "" {
				fmt.Println("Error: Shadowsocks inbound found but 'auth' (method:password) is empty.")
				continue
			}
			userInfo := base64.URLEncoding.EncodeToString([]byte(in.Auth))
			link := fmt.Sprintf("ss://%s@%s#Phoenix-Client", userInfo, in.LocalAddr)
			fmt.Println("Shadowsocks Configuration:")
			fmt.Println(link)
		}
	}
	if !found {
		fmt.Println("No Shadowsocks inbound found in configuration.")
	}
}

// startInbound starts a TCP listener for an inbound proxy and accepts
// connections. If ready is non-nil it is closed once the listener is
// successfully bound — callers can use this to synchronise on readiness.
func startInbound(client *transport.Client, in config.ClientInbound, ready chan<- struct{}) {
	ln, err := net.Listen("tcp", in.LocalAddr)
	if err != nil {
		log.Printf("Failed to listen on %s: %v", in.LocalAddr, err)
		if ready != nil {
			close(ready)
		}
		return
	}
	log.Printf("Listening on %s (%s)", in.LocalAddr, in.Protocol)
	if ready != nil {
		close(ready)
	}

	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Printf("Accept error on %s: %v", in.LocalAddr, err)
			continue
		}
		go handleConnection(client, in, conn)
	}
}

func handleConnection(client *transport.Client, in config.ClientInbound, conn net.Conn) {
	switch in.Protocol {
	case protocol.ProtocolSOCKS5:
		dialer := &PhoenixTunnelDialer{
			Client: client,
			Proto:  protocol.ProtocolSOCKS5,
		}
		if err := socks5.HandleConnection(conn, dialer, in.EnableUDP); err != nil {
			log.Printf("SOCKS5 Handler Error: %v", err)
		}

	case protocol.ProtocolSSH:
		target := in.TargetAddr
		stream, err := client.Dial(protocol.ProtocolSSH, target)
		if err != nil {
			log.Printf("Failed to dial server: %v", err)
			conn.Close()
			return
		}
		go func() {
			defer conn.Close()
			defer stream.Close()
			io.Copy(conn, stream)
		}()
		go func() {
			defer conn.Close()
			defer stream.Close()
			io.Copy(stream, conn)
		}()

	case protocol.ProtocolShadowsocks:
		stream, err := client.Dial(protocol.ProtocolShadowsocks, in.TargetAddr)
		if err != nil {
			log.Printf("Failed to dial server: %v", err)
			conn.Close()
			return
		}
		go func() {
			defer conn.Close()
			defer stream.Close()
			io.Copy(conn, stream)
		}()
		go func() {
			defer conn.Close()
			defer stream.Close()
			io.Copy(stream, conn)
		}()

	default:
		log.Printf("Unknown protocol inbound: %s", in.Protocol)
		conn.Close()
	}
}

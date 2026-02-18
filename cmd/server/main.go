package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"phoenix/pkg/config"
	"phoenix/pkg/transport"
	"syscall"
)

func main() {
	configPath := flag.String("config", "server.toml", "Path to server configuration file")
	flag.Parse()

	cfg, err := config.LoadServerConfig(*configPath)
	if err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	// Make sure security is strict by default if config is missing values
	log.Printf("Starting Phoenix Server on %s", cfg.ListenAddr)
	log.Printf("Enabled Protocols: SOCKS5=%v, Shadowsocks=%v, SSH=%v",
		cfg.Security.EnableSOCKS5,
		cfg.Security.EnableShadowsocks,
		cfg.Security.EnableSSH)

	go func() {
		if err := transport.StartServer(cfg); err != nil {
			log.Fatalf("Server failed: %v", err)
		}
	}()

	// Graceful shutdown
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt, syscall.SIGTERM)
	<-c
	log.Println("Shutting down...")
	os.Exit(0)
}

package config

import (
	"phoenix/pkg/protocol"
	"testing"

	"github.com/pelletier/go-toml"
)

func TestServerConfig(t *testing.T) {
	tomlData := `
listen_addr = ":9090"
[security]
enable_socks5 = true
enable_ssh = false
`
	config := DefaultServerConfig()
	err := toml.Unmarshal([]byte(tomlData), config)
	if err != nil {
		t.Fatalf("Failed to unmarshal server config: %v", err)
	}

	if config.ListenAddr != ":9090" {
		t.Errorf("Expected ListenAddr :9090, got %s", config.ListenAddr)
	}
	if !config.Security.EnableSOCKS5 {
		t.Errorf("Expected EnableSOCKS5 true, got false")
	}
	if config.Security.EnableSSH {
		t.Errorf("Expected EnableSSH false, got true")
	}
}

func TestClientConfig(t *testing.T) {
	tomlData := `
remote_addr = "example.com:443"

[[inbounds]]
protocol = "socks5"
local_addr = ":1080"

[[inbounds]]
protocol = "ssh"
local_addr = ":2222"
auth = "/key"
`
	config := DefaultClientConfig()
	err := toml.Unmarshal([]byte(tomlData), config)
	if err != nil {
		t.Fatalf("Failed to unmarshal client config: %v", err)
	}

	if config.RemoteAddr != "example.com:443" {
		t.Errorf("Expected RemoteAddr example.com:443, got %s", config.RemoteAddr)
	}
	if len(config.Inbounds) != 2 {
		t.Fatalf("Expected 2 inbounds, got %d", len(config.Inbounds))
	}
	if config.Inbounds[0].Protocol != protocol.ProtocolSOCKS5 {
		t.Errorf("Expected inbound 0 to be socks5, got %s", config.Inbounds[0].Protocol)
	}
	if config.Inbounds[1].Protocol != protocol.ProtocolSSH {
		t.Errorf("Expected inbound 1 to be ssh, got %s", config.Inbounds[1].Protocol)
	}
}

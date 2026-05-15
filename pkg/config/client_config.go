package config

import (
	"phoenix/pkg/protocol"
)

// ClientInbound defines a single inbound protocol binding on the client side.
type ClientInbound struct {
	// Protocol specifies the protocol type (e.g., "socks5", "shadowsocks", "ssh").
	Protocol protocol.ProtocolType `toml:"protocol"`

	// LocalAddr is the address and port the client should listen on (e.g., "127.0.0.1:1080").
	LocalAddr string `toml:"local_addr"`

	// EnableUDP allows UDP Associate for SOCKS5
	EnableUDP bool `toml:"enable_udp,omitempty"`

	// TargetAddr is the remote destination address (optional, mainly for SSH/Port Forwarding).
	TargetAddr string `toml:"target_addr,omitempty"`

	// Encryption and authentication parameters for the protocol (if applicable).
	// For Shadowsocks, this might be "aes-256-gcm:password".
	// For SSH, this might be a key file path or simple forwarding.
	Auth string `toml:"auth,omitempty"`
}

// ClientRecovery defines settings for zombie connection detection and full-jitter backoff.
type ClientRecovery struct {
	Enabled        bool `toml:"enabled"`
	ErrorThreshold int  `toml:"error_threshold"`
	ErrorWindowS   int  `toml:"error_window_s"`
	BackoffBaseMs  int  `toml:"backoff_base_ms"`
	BackoffCapMs   int  `toml:"backoff_cap_ms"`
	BackoffJitter  bool `toml:"backoff_jitter"`
}

// ClientConfig defines the full structure of the client configuration.
// It allows for multiple simultaneous inbound listeners on different ports.
type ClientConfig struct {
	// RemoteAddr is the address of the Phoenix server (e.g., "example.com:8080").
	RemoteAddr string `toml:"remote_addr"`

	// AuthToken is sent to the server for authentication.
	// Must match the server's auth_token.
	AuthToken string `toml:"auth_token"`

	// Inbounds is a list of local listeners that the client will open.
	// Each inbound corresponds to a specific protocol and local port.
	Inbounds []ClientInbound `toml:"inbounds"`

	// ClientID is a unique identifier or token for authentication with the server (optional, for future use).
	ClientID string `toml:"client_id,omitempty"`

	// PrivateKeyPath is the path to the client's private key file (PEM).
	PrivateKeyPath string `toml:"private_key"`

	// ServerPublicKey is the detailed public key of the server (Base64).
	ServerPublicKey string `toml:"server_public_key"`

	// TLSMode controls the TLS verification strategy.
	// "system" = use system CA store (for CDN/Cloudflare setups)
	// "" (empty) = use Phoenix Ed25519 pinning or h2c based on other fields
	TLSMode string `toml:"tls_mode"`

	// CustomSNI specifies an arbitrary SNI value to be sent during the TLS handshake.
	// If set, it overrides the remote address's hostname.
	CustomSNI string `toml:"custom_sni"`

	// Fingerprint controls TLS ClientHello fingerprint spoofing.
	// Mimics a browser to bypass DPI-based filtering on some ISPs.
	// ""        → Go default TLS (no spoofing)
	// "chrome"  → Mimic Chrome (recommended)
	// "firefox" → Mimic Firefox
	// "safari"  → Mimic Safari
	// "random"  → Random browser fingerprint per connection
	Fingerprint string `toml:"fingerprint"`

	// Recovery controls how the client handles zombie connections and disconnects.
	Recovery ClientRecovery `toml:"recovery"`
}

// DefaultClientConfig returns a basic client configuration with a single SOCKS5 inbound.
func DefaultClientConfig() *ClientConfig {
	return &ClientConfig{
		RemoteAddr: "127.0.0.1:8080",
		Inbounds: []ClientInbound{
			{
				Protocol:  protocol.ProtocolSOCKS5,
				LocalAddr: "127.0.0.1:1080",
			},
		},
		Recovery: ClientRecovery{
			Enabled:        true,
			ErrorThreshold: 10,
			ErrorWindowS:   30,
			BackoffBaseMs:  500,
			BackoffCapMs:   15000,
			BackoffJitter:  true,
		},
	}
}

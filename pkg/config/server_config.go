package config

// ServerSecurity defines the security configuration for the server.
// It controls which protocols are allowed to be tunneled.
type ServerSecurity struct {
	// EnableSOCKS5 enables or disables the SOCKS5 proxy protocol (TCP).
	EnableSOCKS5 bool `toml:"enable_socks5"`

	// EnableUDP enables or disables UDP tunneling (SOCKS5 UDP Associate).
	EnableUDP bool `toml:"enable_udp"`

	// EnableShadowsocks enables or disables the Shadowsocks proxy protocol.
	EnableShadowsocks bool `toml:"enable_shadowsocks"`

	// EnableSSH enables or disables SSH tunneling.
	EnableSSH bool `toml:"enable_ssh"`
}

// DefaultServerSecurity returns the default security configuration (all disabled by default).
func DefaultServerSecurity() ServerSecurity {
	return ServerSecurity{
		EnableSOCKS5:      false,
		EnableShadowsocks: false,
		EnableSSH:         false,
	}
}

// ServerConfig defines the full structure of the server configuration file.
type ServerConfig struct {
	// ListenAddr is the address and port the server will bind to (e.g., ":8080").
	// This uses the underlying h2c protocol.
	ListenAddr string `toml:"listen_addr"`

	// Security defines the protocol access controls.
	Security ServerSecurity `toml:"security"`
}

// DefaultServerConfig returns a server configuration with safe defaults.
func DefaultServerConfig() *ServerConfig {
	return &ServerConfig{
		ListenAddr: ":8080",
		Security:   DefaultServerSecurity(),
	}
}

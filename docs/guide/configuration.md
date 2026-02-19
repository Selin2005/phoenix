# Configuration Reference

Phoenix uses TOML for configuration.

## Client Configuration

Refer to `example_client.toml` in the repository for a full list of options.

### Common Options

- `remote_addr`: The address of the Phoenix server.
- `inbounds`: A list of local listeners.

## Server Configuration

Refer to `example_server.toml` in the repository for a full list of options.

### Common Options

- `listen_addr`: The TCP address to bind to.
- `security`: Enable or disable specific protocols.

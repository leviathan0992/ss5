# SS5

A SOCKS5 proxy with mutually authenticated TLS for client–server connections.

- **Transport:** TLS 1.3 for TCP traffic and the SOCKS5 control connection.
- **Authentication:** mutual TLS, with optional SOCKS5 username and password authentication.
- **Proxy commands:** TCP CONNECT and UDP ASSOCIATE.

## Quick start

### 1. Get the binaries

Download the binaries for your platform from the [releases page](https://github.com/leviathan0992/ss5/releases), or build from source with a Go toolchain compatible with `go.mod`:

```sh
go build -o ss5-client ./client
go build -o ss5-server ./server
```

### 2. Configure and start the server

Save as `.ss5-server.json`:

```json
{
  "listen_addr": "0.0.0.0:58",
  "public_addr": "",
  "server_key": "/etc/ss5/server.key",
  "server_pem": "/etc/ss5/server.pem",
  "client_pem": "/etc/ss5/client-ca.pem",
  "username": "your-user",
  "password": "your-password"
}
```

- `server_pem` and `server_key` contain the server certificate chain and matching private key.
- `client_pem` contains the CA certificates trusted to authenticate clients.
- Set both `username` and `password` to require SOCKS5 credentials in addition to mTLS; omit both for certificate-only authentication.
- For UDP behind NAT or a cloud public-IP mapping, set `public_addr` to the IP or hostname reachable by clients.

```sh
./ss5-server -c .ss5-server.json
```

### 3. Configure and start the client

Save as `.ss5-client.json`:

```json
{
  "server_addr": ["127.0.0.1:58"],
  "listen_addr": "127.0.0.1:2024",
  "client_pem": "/etc/ss5/client.pem",
  "client_key": "/etc/ss5/client.key",
  "server_pem": "/etc/ss5/server-ca.pem",
  "server_auth": {
    "127.0.0.1:58": {
      "username": "your-user",
      "password": "your-password"
    }
  }
}
```

- Replace the example loopback address with the remote server address. Its IP or hostname must match the server certificate SAN.
- `client_pem` and `client_key` contain the client certificate chain and matching private key; `server_pem` contains the trusted server CA certificates.
- Optional `server_auth` keys must exactly match entries in `server_addr`. When configured, the client accepts local SOCKS5 without authentication and supplies the configured credentials to the upstream server.

```sh
./ss5-client -c .ss5-client.json
```

Applications connect to the local SOCKS5 listener at `127.0.0.1:2024`.

## Protocol and operational limits

- **TLS:** both components require TLS 1.3. The client validates the server certificate chain and endpoint identity; the server validates client certificates against its configured CA trust. Certificate fingerprint allowlists are not supported.
- **UDP:** datagrams use native SOCKS5 UDP and are **not encrypted by TLS**. TLS protects the control connection. Per-target relay sockets preserve stable UDP source tuples within an association.
- **Capacity:** UDP resources are limited to 128 associations, 128 targets per association, and 1,024 target relays in total. New work is rejected at capacity while existing relays remain usable.
- **Failover:** the client starts with the first upstream and switches after three connection failures. It stays on the selected upstream until another switch or a restart; existing connections retain their original upstream.
- **Shutdown:** SIGINT or SIGTERM stops new connections and allows active sessions up to 10 seconds to finish before cancellation.

## License

[Apache-2.0](LICENSE)

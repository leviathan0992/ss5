# ss5

A Golang Implementation of SOCKS5 over TLS.

This project provides a Golang implementation of a SOCKS5 over TLS proxy
system, including client and server components. The client runs locally to
convert regular SOCKS5 requests into encrypted TLS requests and forwards them
to the remote server. The server receives and decrypts these requests for
further processing.

Currently, the ss5 supports the TCP/CONNECT and UDP/ASSOCIATE commands. The
server keeps per-target UDP relay sockets within each UDP association so
stateful UDP protocols can retain a stable upstream tuple.

```
 --------------                              --------------
|              |                            |              |
|              |   SOCKS5 OVER TLS (TCP)    |              |
|  ss5-client  |  ----------------------->  |  ss5-server  |
|              |                            |              |
|              |                            |              |
 --------------                              --------------
```

## Usage:

1. Download the latest release package, for example:
   ``` shell
   wget https://github.com/leviathan0992/ss5/releases/download/v0.1.3/ss5_0.1.3_Linux_x86_64.tar.gz
   
   tar -zxvf ss5_0.1.3_Linux_x86_64.tar.gz
   
   cd ss5_0.1.3_Linux_x86_64
   ```

2. Configure the ss5-client and fill in the ss5-server address:

   ```shell
   # vim .ss5-client.json
   
   {
    "server_addr": [
      "127.0.0.1:443",
      "127.0.0.1:53"
    ],
    "listen_addr": "127.0.0.1:2024",
    "client_pem": "/etc/client.pem",
    "client_key": "/etc/client.key",
    "server_pem": "/etc/server.pem",
    "server_auth": {
      "127.0.0.1:443": {
        "username": "your-user",
        "password": "your-password"
      }
    }
    }
   ```

   Optional `server_auth` maps upstream addresses to SOCKS5 credentials.
   Each address must match an entry in `server_addr`. When configured, the
   client accepts local SOCKS5 without authentication and authenticates to
   each upstream using its configured credentials.

   With multiple upstreams, the client automatically selects by smoothed
   connection setup time: `score = 0.75 * previous + 0.25 * sample` (milliseconds;
   failures count as 5000). Probes use the configured credentials every 30 seconds.
   A node must score at least 20% lower for two rounds before switching; connection
   failures trigger failover immediately. Existing tunnels stay on their original
   upstream. This measures connection reliability and latency, not bandwidth.

3. Start the ss5-client:
   ```shell
   ./ss5-client -c .ss5-client.json
   ```

4. Configure the ss5-server:

   ```shell
   # vim .ss5-server.json
   
   {
    "listen_addr": "0.0.0.0:443",
    "public_addr": "",
    "server_key": "/etc/server.key",
    "server_pem": "/etc/server.pem",
    "client_pem": "/etc/client.pem",
    "username": "your-user",
    "password": "your-password"
    }
   ```

   Set both `username` and `password` to require matching client credentials
   in addition to mTLS. Omit both for certificate-only authentication.

   `public_addr` is optional, but it is recommended when the server runs
   behind NAT, an Elastic IP, a cloud private network, or any other topology
   where the server's local interface address is not directly reachable by the
   client. In those environments, set it to the public IP or hostname clients
   actually use to reach the server.

5. Start the ss5-server:
   ```shell
   ./ss5-server -c .ss5-server.json
   ```

## License:

Apache-2.0 license

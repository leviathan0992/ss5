# ss5

A Golang Implementation of SOCKS5 over TLS.

This project provides a Golang implementation of a SOCKS5 over TLS proxy system, including client and server components.
The client runs locally to convert regular SOCKS5 requests into encrypted TLS requests and forwards them to the remote
server. The server receives and decrypts these requests for further processing.

Currently, the ss5 supports the TCP/CONNECT and UDP/ASSOCIATE commands.

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
   wget https://github.com/leviathan0992/ss5/releases/download/v0.0.3/ss5_0.0.3_Linux_x86_64.tar.gz
   
   tar -zxvf ss5_0.0.3_Linux_x86_64.tar.gz
   
   cd ss5_0.0.3_Linux_x86_64
   ```

2. Configure the ss5-client and fill in the ss5-server address:

   ```shell
   # vim .ss5-client.json
   
   {
    "server_addr": [
      "127.0.0.1:58",
      "127.0.0.1:53"
    ],
    "listen_addr": "127.0.0.1:2024",
    "client_pem": "/etc/client.pem",
    "client_key": "/etc/client.key"
    }
   ```

3. Start the ss5-client:
   ```shell
   ./ss5-client -c .ss5-client.json
   ```

4. Configure the ss5-server:

   ```shell
   # vim .ss5-server.json
   
   {
    "listen_addr": "0.0.0.0:443",
    "server_key": "/etc/server.key",
    "server_pem": "/etc/server.pem",
    "client_pem": "/etc/client.pem"
    }
   ```
5. Start the ss5-server:
   ```shell
   ./ss5-server -c .ss5-server.json
   ```

## License:

Apache-2.0 license


# ss5
A Golang Implementation of SOCKS5 over TLS.

This project provides a Golang implementation of a SOCKS5 over TLS proxy system, including client and server components. The client runs locally to convert regular SOCKS5 requests into encrypted TLS requests and forwards them to the remote server. The server receives and decrypts these requests for further processing.

Currently, the ss5 only supports the TCP/CONNECT command.

## Usage:
1. Download the latest release package, for example:
   ``` shell
   wget https://github.com/Mesaukee/ss5/releases/download/v0.0.1/ss5_0.0.1_Linux_64-bit.tar.gz
   
   tar -zxvf ss5_0.0.1_Linux_64-bit.tar.gz
   
   cd ss5_0.0.1_Linux_64-bit
   ```
2. Configure the Client:
   `vim .ss5-client.json`
   
   ```json
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
   
3. Start the Client:
   `./ss5-client -c .ss5-client.json`
   
4. Configure the Server:
   `vim .ss5-server.json`
   
   ```json
   {
    "listen_addr": "0.0.0.0:443",
    "server_key": "/etc/server.key",
    "server_pem": "/etc/server.pem",
    "client_pem": "/etc/client.pem"
    }
   ```
7. Start the Server:
   `./ss5-server -c .ss5-server.json`

## License:

Apache-2.0 license


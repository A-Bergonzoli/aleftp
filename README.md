# Secure File Transfer Toy Project

Hey there! This is a little C project I hacked together to play with OpenSSL and get a feel for TLS sockets, config-driven servers, and a bit of protocol design. It's practical, a bit hacky, and focused on learning by doing. This is not production code, but it's fun and educational. Some parts are more thought out than others.

## What is this?

It's a simple client/server system for transferring files over a TLS-encrypted connection. The server listens for connections, and the client can request files using a minimalistic protocol. Everything is encrypted with OpenSSL (no plaintext allowed!).

- **Server:** Listens on a configurable port, serves files from a configurable root directory, always requires TLS.
- **Client:** Connects to the server, requests files, saves them locally (in the current working directory).
- **Config:** Both server and client are driven by a config file (see `example.cfg`).

## Why?

I wanted to get my hands dirty with OpenSSL, see how the API feels, and understand the pain points. I avoided using the OpenSSL BIO abstraction on purpose. Everything is done with the raw SSL* API, so you see all the gory details.

## How it works

- The server loads a certificate and private key (self-signed is fine for testing).
- The client loads the server's certificate as a trusted root (so it will trust the self-signed cert).
- The client verifies the server's hostname (using SNI and SAN in the cert).
- The protocol is dead simple: the client sends `GET <filename>`, the server replies with a header (status, length), then the file bytes.

## Building

You need a C compiler (gcc or clang) and OpenSSL development headers installed (depends on your OS and distro):

```sh
gcc -Wall -Wextra -I<project_root> lib/config.c lib/logging.c wrap/io.c wrap/socket.c include/protocol.h src/server.c -o srv -lssl -lcrypto

gcc -Wall -Wextra -I<project_root> lib/config.c lib/logging.c wrap/io.c wrap/socket.c include/protocol.h src/client.c -o cli -lssl -lcrypto
```

## Generating Certificates and Keys

You need a certificate and key for the server. Here's how to make a self-signed one with SAN for both DNS and IP:

1. Create a file `san.cnf`:
   ```ini
   [req]
   default_bits       = 2048
   prompt             = no
   default_md         = sha256
   distinguished_name = dn
   req_extensions     = req_ext

   [dn]
   CN = <your_cn>

   [req_ext]
   subjectAltName = @alt_names

   [alt_names]
   DNS.1   = <your_dns>
   IP.1    = 127.0.0.1
   ```
2. Generate a private key (2048-bit RSA)
   ```sh
   openssl genrsa -out server.key 2048
   ```
3. Generate a self-signed certificate valid for 365 days
   ```
   openssl req -new -x509 -key server.key -out server.crt -days 365 \
           -subj "/C=Country/ST=State/L=City/O=Org/CN=Cn"
   ```
4. Place `server.crt` and `server.key` in the same directory as the server executable.

## Example Usage

1. Start the server:
   ```sh
   ./srv conf.cfg
   ```
2. Start the client (from another terminal):
   ```sh
   ./cli 127.0.0.1 conf.cfg
   ```
3. At the client prompt, request a file:
   ```
   > GET myfile.txt
   ```
   The file will be saved in the current directory (see Weaknesses below).

## Configuration

See `example.cfg` for an example. You can set:
- `srv_root` — where the server serves files from
- `srv_port` — which port to listen on
- `srv_hostname` — what the client expects the server's hostname to be (must match the cert's SAN)

## Weaknesses / TODOs / WONTDOs

- **Client always saves files in the current directory.** If you request `GET foo.txt` and you already have a `foo.txt`, it will be overwritten. (A better design would let you set the download directory in the config, or prompt for a save path.)
- **No authentication.** Anyone who can connect can request files. (Add user auth if you want to be serious.)
- **No BIO.** I avoided OpenSSL's BIO abstraction to see what the raw API is like. It's more verbose, but you learn more.
- **Error handling is basic.** It tries to be robust, but you can probably crash it if you try hard enough.
- **No upload support.** Only GET is implemented.
- **No concurrency.** The server is single-threaded and handles one client at a time.
- **No file size limits.** Be careful with huge files.
- **No logging to file.** All logs go to stderr.

## License

Do whatever you want. This is for learning and fun. If you break something, you get to keep both pieces.

---

Enjoy poking around!

## References
[ossl-guide-introduction](https://docs.openssl.org/master/man7/ossl-guide-introduction/#what-is-openssl)

# MCProxy RakNet Transport

A standalone experimental transport that carries TCP streams and native UDP
datagrams over an encrypted RakNet-style UDP session.

The repository contains a reusable RakNet transport package, a SOCKS5 client,
and a UDP relay server. TCP connections are delivered through reliable,
ordered RakNet frames, while SOCKS5 UDP ASSOCIATE traffic is relayed as native
UDP datagrams.

> This project is intended for protocol research, private networking, and
> interoperability experiments. Follow the laws and network policies that
> apply to you. It is not affiliated with Mojang, Microsoft, Minecraft, or the
> RakNet project.

## Features

- RakNet-style unconnected ping and connection opening
- TCP-over-RakNet with reliable and ordered delivery
- Native UDP relay through SOCKS5 UDP ASSOCIATE
- Shared RakNet sessions for multiplexed UDP associations
- ACK and NACK processing
- Packet loss recovery and fast retransmission
- RTT estimation and adaptive retransmission timeout
- Congestion window, slow start, congestion avoidance, and pacing
- Duplicate packet suppression and out-of-order buffering
- Packet fragmentation and reassembly
- X25519 ephemeral key exchange
- Argon2id password-based authentication
- ChaCha20-Poly1305 encrypted tunnel frames
- Replay-window and handshake timestamp checks
- Linux and Windows support

## Architecture

```text
Application
    |
    | SOCKS5 CONNECT or UDP ASSOCIATE
    v
MCProxy UDP client
    |
    | encrypted RakNet-style UDP session
    v
MCProxy UDP server
    |
    +---- TCP connection ----> TCP destination
    |
    +---- UDP datagram ------> UDP destination
```

### TCP path

```text
TCP application
  -> SOCKS5 CONNECT
  -> reliable ordered frames
  -> RakNet-style UDP transport
  -> server TCP socket
```

### UDP path

```text
UDP application
  -> SOCKS5 UDP ASSOCIATE
  -> tunnel datagram frame
  -> RakNet-style UDP transport
  -> server UDP socket
```

## Repository Layout

```text
cmd/
  udp-client/       SOCKS5 client and RakNet tunnel endpoint
  udp-server/       RakNet tunnel server and TCP/UDP relay

pkg/
  crypto/           authentication, key exchange, and encryption
  raknet/           RakNet framing, handshake, reliability, and tunnel logic
  socks5/           SOCKS5 CONNECT and UDP ASSOCIATE support
```

## Requirements

- Go 1.21 or newer
- A server with an accessible UDP port
- Correct system time on both endpoints

The authenticated handshake accepts a limited clock difference. Use NTP or
another time synchronization service on the client and server.

## Build

Clone the repository and run:

```bash
go mod download
go test ./...
```

Build the client:

```bash
go build -trimpath -ldflags="-s -w" \
  -o bin/mcproxy-udp-client ./cmd/udp-client
```

Build the Linux amd64 server:

```bash
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
  go build -trimpath -ldflags="-s -w" \
  -o bin/mcproxy-udp-server-linux-amd64 ./cmd/udp-server
```

Build the Windows client from PowerShell:

```powershell
$env:GOOS = "windows"
$env:GOARCH = "amd64"
$env:CGO_ENABLED = "0"
go build -trimpath -ldflags="-s -w" `
  -o bin\mcproxy-udp-client.exe .\cmd\udp-client
```

## Server

Start the server on UDP port `19132`:

```bash
./mcproxy-udp-server-linux-amd64 \
  -listen 0.0.0.0:19132 \
  -password 'replace-with-a-strong-password'
```

Available options:

```text
-listen        UDP listen address (default: 0.0.0.0:19132)
-password      shared authentication secret (required)
-max-sessions  maximum active and pending sessions (default: 256)
```

Allow the selected UDP port in both the operating-system firewall and the
hosting provider's security rules.

Example with UFW:

```bash
sudo ufw allow 19132/udp
```

## Client

Start a local SOCKS5 listener:

```bash
./mcproxy-udp-client \
  -listen 127.0.0.1:1080 \
  -server example.com:19132 \
  -password 'replace-with-the-same-password'
```

Available options:

```text
-listen    local SOCKS5 listen address (default: 127.0.0.1:1080)
-server    remote UDP server address (required)
-password  shared authentication secret (required)
```

Configure applications to use:

```text
SOCKS5 host: 127.0.0.1
SOCKS5 port: 1080
```

TCP applications use SOCKS5 CONNECT and are carried as TCP-over-RakNet.
Applications that support SOCKS5 UDP ASSOCIATE can also send native UDP
traffic through the same local SOCKS5 endpoint.

## LAN Access

The default client listener is local-only. To let another device on the same
trusted LAN use the proxy, bind it to a LAN interface or all interfaces:

```bash
./mcproxy-udp-client \
  -listen 0.0.0.0:1080 \
  -server example.com:19132 \
  -password 'replace-with-the-same-password'
```

Binding to `0.0.0.0` exposes the SOCKS5 listener to the network. This client
does not currently require a SOCKS5 username or password, so restrict access
with the host firewall and do not expose port `1080` to the public Internet.

## Updating

The client and server share a private tunnel framing protocol. When frame
formats change, update the server first and then update all clients. A new
client may not be compatible with an older server.

## Security Notes

- Use a long, randomly generated password.
- Do not reuse the tunnel password for SSH, control panels, or other services.
- Keep configuration files, logs, private keys, and real node information out
  of the repository.
- Encryption does not make an endpoint immune to traffic analysis, blocking,
  implementation bugs, or active probing.
- The implementation has not received an independent security audit.
- This is a focused transport implementation, not a complete general-purpose
  RakNet or Minecraft Bedrock server.

Recommended `.gitignore` entries:

```gitignore
bin/
*.exe

.gocache/
.gopath/

*.log
.env
config.json
*.key
*.pem
*.crt
```

## Testing

Run the complete test suite:

```bash
go test ./...
```

The tests cover:

- RakNet opening and authenticated handshake
- TCP data ordering
- retransmission after packet loss
- duplicate packet suppression
- ACK/NACK handling
- congestion-window behavior
- fragmentation and datagram encoding
- multiplexed UDP associations
- end-to-end TCP-over-RakNet relay

For a lower-resource machine:

```bash
GOMAXPROCS=2 go test -p 1 ./...
```

## Limitations

- TCP-over-UDP can perform poorly on lossy networks because both the
  application TCP connection and the tunnel reliability layer react to loss.
- UDP transport availability depends on the network, NAT, firewall, and
  hosting provider.
- SOCKS5 UDP support varies between applications.
- The current congestion controller is a transport-local, Reno-style design;
  it is not Linux TCP BBR.
- No protocol camouflage can guarantee indistinguishability from genuine game
  traffic.

## License

Apache License 2.0 is recommended for this repository. Add a `LICENSE` file
before publishing.


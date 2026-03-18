# Floki

Floki is an RTP relay based on iptables NAT rules. Instead of proxying RTP traffic at the application level, Floki dynamically manages DNAT/SNAT rules to route media streams between network interfaces — without touching UDP packets in userspace.

It implements the rtpengine NG protocol over UDP, making it compatible with any SIP server that supports the `rtpengine` module (e.g. OpenSIPS, Kamailio).

## How it works

```
SIP Client ──► OpenSIPS (rtpengine module)
                    │
                    ▼ UDP (NG protocol / bencode)
                  Floki
                    │
                    ├── Parses the SDP (offer/answer)
                    ├── Allocates local RTP ports
                    ├── Inserts DNAT/SNAT rules into iptables
                    └── Returns the modified SDP with the new ports
```

When a call is terminated (`delete`), the rules are removed and the ports are released.

## Requirements

- Linux with `iptables`
- Root permission (required to manage iptables)
- Go 1.23+ (only for building)

## Installation

### Via script (recommended)

The script builds the binary, installs the files, and enables the service automatically.

```bash
sudo bash scripts/install.sh
```

What the script does:
1. Builds the binary with production optimizations (`CGO_ENABLED=0`, `-ldflags="-s -w"`)
2. Installs the binary at `/usr/local/bin/floki`
3. Creates `/etc/floki/` and copies `configs/floki.conf` (only if it does not already exist)
4. Installs `deploy/floki.service` into `/etc/systemd/system/`
5. Enables the service to start on boot (`systemctl enable floki`)

After installation, edit the configuration and start the service:

```bash
nano /etc/floki/floki.conf
systemctl start floki
```

### Via Makefile

```bash
sudo make install
```

### Manual

```bash
# Build
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o floki ./src

# Install binary
sudo cp floki /usr/local/bin/
sudo chmod +x /usr/local/bin/floki

# Configuration
sudo mkdir -p /etc/floki
sudo cp configs/floki.conf /etc/floki/

# Systemd service
sudo cp deploy/floki.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now floki
```

## Systemd service

The `floki.service` file defines the process behaviour under systemd.

```ini
[Unit]
Description=Floki RTP Relay
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/floki -config /etc/floki/floki.conf
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
RestartSec=5s
TimeoutStopSec=10s
PIDFile=/var/run/floki.pid
StandardOutput=journal
StandardError=journal
SyslogIdentifier=floki
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
```

### Service management commands

```bash
# Start
systemctl start floki

# Stop (graceful — removes iptables rules for active calls)
systemctl stop floki

# Reload configuration without restarting (SIGHUP)
systemctl reload floki

# Restart
systemctl restart floki

# Status
systemctl status floki

# Live logs
journalctl -u floki -f

# Last 100 log lines
journalctl -u floki -n 100
```

### `TimeoutStopSec`

The service waits up to 10 seconds for a graceful shutdown (removal of iptables rules for active calls) before sending `SIGKILL`. Adjust this value according to the expected call volume.

## Configuration

File: `/etc/floki/floki.conf`

```ini
[general]
manager_ip=0.0.0.0
manager_port=2223
rtp_port_min=16384
rtp_port_max=32767
cleanup_on_start=false
log_level=info

[wan]
ip=192.168.0.199

[lan]
ip=192.168.56.105

;[lan2]
;ip=172.16.0.1
```

### Parameters

| Parameter | Default | Description |
|---|---|---|
| `manager_ip` | `0.0.0.0` | Listen address for the UDP and HTTP servers |
| `manager_port` | `2223` | UDP port (NG protocol). HTTP listens on `manager_port + 1` |
| `rtp_port_min` | `16384` | Start of the allocatable RTP port range |
| `rtp_port_max` | `32767` | End of the allocatable RTP port range |
| `cleanup_on_start` | `false` | If `true`, removes all Floki iptables rules on startup |
| `log_level` | `info` | Log level: `debug`, `info`, `warn`, `error` |

Sections other than `[general]` define the available network interfaces. The section name is used as the interface identifier in the `direction` field of the NG protocol.

## Usage

```bash
# Default configuration (/etc/floki/floki.conf)
sudo floki

# Custom configuration path
sudo floki -config /path/to/floki.conf
```

### Signals

| Signal | Behaviour |
|---|---|
| `SIGTERM` / `SIGINT` | Shuts down the process and removes iptables rules for all active calls |
| `SIGHUP` | Reloads the configuration file without restarting |

```bash
# Reload configuration
sudo kill -HUP $(cat /var/run/floki.pid)
```

## Management API

The HTTP server listens on `manager_port + 1` (default: `2224`).

### `GET /status`

```bash
curl http://localhost:2224/status
```

```json
{
  "start_epoch": 1700000000,
  "uptime_sec": 3600,
  "processed_calls": 150,
  "active_calls": 12,
  "rtp_port_range_size": 16383,
  "rtp_used_ports": 24,
  "rtp_available_ports": 16359,
  "rtp_port_min": 16384,
  "rtp_port_max": 32767,
  "rtp_interfaces": {
    "lan": "192.168.56.105",
    "wan": "192.168.0.199"
  }
}
```

### `GET /list_calls`

Returns the full map of active calls with their endpoints and allocated ports.

```bash
curl http://localhost:2224/list_calls
```

### `GET /metrics`

Prometheus-compatible metrics endpoint.

```bash
curl http://localhost:2224/metrics
```

| Metric | Type | Description |
|---|---|---|
| `floki_processed_calls_total` | Counter | Total number of processed calls |
| `floki_active_calls` | Gauge | Number of currently active calls |
| `floki_deleted_calls_total` | Counter | Total number of terminated calls |
| `floki_iptables_errors_total` | Counter | Errors inserting or removing iptables rules |
| `floki_port_allocation_failures_total` | Counter | RTP port allocation failures |

## NG Protocol

Floki accepts commands via the rtpengine NG protocol over UDP using bencode serialisation.

| Command | Description |
|---|---|
| `ping` | Connectivity check. Returns `pong` |
| `offer` | Processes an SDP offer, allocates ports and inserts iptables rules |
| `answer` | Processes an SDP answer, allocates ports in the reverse direction |
| `delete` | Removes the call, its iptables rules and releases the ports |

### OpenSIPS configuration example

```
loadmodule "rtpengine.so"
modparam("rtpengine", "rtpengine_sock", "udp:localhost:2223")
```

## Development

```bash
# Download dependencies
go mod download

# Run locally
sudo go run ./src -config configs/floki.conf

# Format and lint
go fmt ./...
go vet ./...

# Run tests
go test -v ./...

# Production build (static binary)
CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o floki ./src
```

## Contributors

- **Carlos Eduardo Wagner** — kaduww@gmail.com / carlos@sippulse.com
  - [github.com/kaduww](https://github.com/kaduww)

## License

Project started on 2021-11-04.

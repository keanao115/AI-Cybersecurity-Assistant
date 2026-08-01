# Enterprise Live Packet Capture Subsystem (Npcap / libpcap)

## Architecture Overview

The **Live Packet Capture Subsystem** provides a cross-platform abstraction layer for capturing network packets in enterprise SOC environments:
- **Windows**: Npcap driver
- **Linux**: libpcap (`AF_PACKET` / raw sockets)
- **macOS**: libpcap (`bpf` devices)

```
                       +-----------------------------------+
                       |    Physical / Virtual Interface   |
                       +-----------------+-----------------+
                                         |
                       +-----------------v-----------------+
                       | Npcap (Windows) / libpcap (Unix)  |
                       +-----------------+-----------------+
                                         |
                       +-----------------v-----------------+
                       |      InterfaceManager             |
                       +-----------------+-----------------+
                                         |
                       +-----------------v-----------------+
                       |       CaptureManager (BPF)        |
                       +-----------------+-----------------+
                                         |
                       +-----------------v-----------------+
                       |      Layered Packet Decoder       |
                       |  (Ethernet, IP, TCP/UDP, TLS JA3) |
                       +-----------------+-----------------+
                                         |
                       +-----------------v-----------------+
                       |           Flow Engine             |
                       +-----------------------------------+
```

---

## BPF Filtering Examples

| Filter Expression | Defensive Use Case |
|---|---|
| `tcp port 443 or tcp port 80` | Capture web HTTP/HTTPS traffic |
| `udp port 53` | Inspect DNS queries and responses |
| `tcp port 445` | Monitor SMB/CIFS lateral movement |
| `ip host 192.168.1.10` | Monitor Domain Controller traffic |

---

## REST API Reference

- `GET /api/capture/interfaces` — List available network adapters.
- `GET /api/capture/status` — Active capture session state & packet metrics.
- `POST /api/capture/start` — Start packet capture session (`{ interfaceId: "iface-1", bpfFilter: "tcp" }`).
- `POST /api/capture/stop` — Stop active capture session.

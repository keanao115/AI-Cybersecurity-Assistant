# Enterprise Telemetry Collector Architecture

## Overview

The platform uses a modular, non-blocking collector architecture based on `BaseCollector` and `IMessageQueue`:

```
+-----------------------------------------------------------------+
|                    BaseCollector Abstract Class                 |
| (State Machine: Initializing -> Running -> Paused -> Stopped)   |
+--------------------------------+--------------------------------+
                                 |
     +---------------------------+---------------------------+
     |                           |                           |
+----v-----+                +----v-----+                +----v-----+
|  Syslog  |                |   WEF    |                | NetFlow  |
| Collector|                | Collector|                | Collector|
+----+-----+                +----+-----+                +----+-----+
     |                           |                           |
     +---------------------------+---------------------------+
                                 |
                       +---------v---------+
                       |   IMessageQueue   |
                       |  (Backpressure)   |
                       +-------------------+
```

---

## Collector Matrix

| Collector | Transport Protocol | Default Port | Decoder |
|---|---|---|---|
| Syslog | UDP / TCP | `5514` / `5515` | RFC 3164 / 5424 + Cisco ASA / Fortinet |
| WEF XML | HTTP | `5516` | WinRM XML Event ID 4625/4688 Parser |
| NetFlow | UDP | `2055` | NetFlow v5 / v9 / IPFIX Binary Frame Decoder |
| Live Pcap | Raw Sockets / Npcap | Dynamic | Layered Frame Decoder + JA3/JA4 |
| Zeek | JSON Stream / File | API / File | Zeek conn/dns/http/ssl/notice Parser |
| Suricata | EVE JSON | API / File | Suricata EVE Alert Normalizer |

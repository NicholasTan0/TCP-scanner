# tcpscan: TCP Port Scanner & Service Fingerprinter

tcpscan.py is a network security tool developed in Python using Scapy and native sockets. It performs an efficient stealth TCP SYN scan against a target host and applies best-effort banner-grabbing and active probing heuristics to accurately fingerprint the underlying services irrespective of their port configurations.

---

## Technical Architecture & Scanning Logic

The application follows a strict two-stage process to minimize both time overhead and socket interaction:

### Phase 1: Stealth SYN Scan

1. **Probe**: Using Scapy, tcpscan.py crafts a raw layer-3 packet containing a TCP segment with the `SYN` flag enabled (`flags="S"`) and dispatches it via standard network routes.
2. **Analysis**: It intercepts incoming handshake replies. If a packet returns bearing both `SYN` and `ACK` flags (`0x12`), the target port is marked as **Open**.
3. **Teardown**: To maintain stealth and avoid leaving dangling semi-open TCP connections on the target machine, tcpscan.py immediately handles state termination by transmitting a resetting payload (`RST`).

### Phase 2: Active Service Fingerprinting

For each discovered open port, the tool detaches from Scapy and uses standard sockets to perform stateful protocol resolution across up to six distinct server states, executing probes in this hierarchy:

* **TLS Evaluation**:
  * **TLS Server-Initiated (Type 2)**: The tool establishes a standard socket connection and wraps it in an unverified TLS context. It waits up to 2 seconds to capture a server-initiated cryptographic handshake banner. If it succeeds, it extracts the SSL certificate's **Common Name (CN)**.
  * **HTTPS Server (Type 4)**: If no banner appears, it transmits a plaintext `GET / HTTP/1.0\r\n\r\n` block through the TLS channel to catch active web application structures.
  * **Generic TLS Server (Type 6)**: If the HTTP request fails, generic trailing line breaks (`\r\n\r\n\r\n\r\n`) are pushed down the TLS pipeline to attempt to force a fallback response.


* **Cleartext TCP Fallback**:
  * **TCP Server-Initiated (Type 1)**: If the TLS handshake framework drops connection or rejects negotiation entirely, a raw cleartext TCP socket connection is opened. The tool listens for 2 seconds to collect native application headers (e.g., standard SSH or SMTP greeting banners).
  * **HTTP Server (Type 3)**: Lacking an incoming banner, an unencrypted `GET` request is transmitted over the wire to identify cleartext HTTP daemons.
  * **Generic TCP Server (Type 5)**: As a final resort, generic newlines are pushed over the socket. If data returns, it is logged; otherwise, the port is reported as yielding a response of `none`.



---

## Dependencies & Setup

The tool is optimized for **Kali Linux 2025.4 (64-bit)** and requires Python 3 alongside the Scapy framework. Install the dependencies natively using the package manager:

```bash
sudo apt update
sudo apt install -y python3 python3-scapy

```

---

## Usage

### Syntax

```bash
sudo python3 tcpscan.py [-p port_range] <target_ip>

```

### Options

* `-p`: The target ports to inspect. Supports a single port (`80`), a port range (`20-25`), or a comma-separated array (`22,80,443`). If omitted, the tool scans the following commonly used TCP ports: (`21, 22, 23, 25, 80, 110, 143, 443, 587, 853, 993, 3389, 8080`).

### Examples

**Scan default ports on a local host:**

```bash
sudo python3 tcpscan.py 192.168.0.123

```

**Scan a custom range of ports on an external target:**

```bash
sudo python3 tcpscan.py -p 80-9000 8.8.8.8

```

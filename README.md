# PS2 DNAS replacement server, pure Python

A DNAS server for PlayStation 2 online games, written in pure Python. Lets DNAS-protected games pass
authentication again. No Apache, no PHP, and no specially built OpenSSL.

This is a Python reimplementation of DNASrep by the_fog, which replays
DNAS packets captured by the DNAS Forever project. The packet data and certificates come from DNASrep.

**Status:** tested and working with PCSX2 (Sockets network mode) against a server on a Raspberry Pi, using a
US title. EU and JP titles are untested.

## How it works

Three small servers, each in its own folder with its own dependencies:

```
PS2 / PCSX2
   │  1. DNS lookup: gate1.us.dnas.playstation.org
   ▼
dns/                 DNS server (UDP 53). Answers the DNAS hostnames with your server's IP,
   │                 forwards every other lookup to a normal DNS server.
   │  2. HTTPS to port 443
   ▼
ssl_reverse_proxy/   TLS terminator (TCP 443). Speaks the PS2's legacy TLS 1.0 / 3DES handshake,
   │                 forwards the decrypted HTTP to the backend.
   │  3. plain HTTP
   ▼
dnas/                DNAS backend (TCP 8000, localhost). Python port of DNASrep's connect.php
                     and others.php. Looks up the game's stored reply packet and encrypts it.
```

All three can run on one machine (e.g. a Raspberry Pi), or the DNS server can live elsewhere.

### Why not just use OpenSSL?

The PS2 only offers 3DES, RC4, single DES and export ciphers. Current OpenSSL builds (including the one bundled
with Python on Windows) are compiled without any of these, so no configuration can make them talk to a PS2.
`ssl_reverse_proxy` uses [tlslite-ng](https://github.com/tlsfuzzer/tlslite-ng) instead, a pure Python TLS
library, set up to match the original DNAS server as seen in packet captures:

- TLS 1.0 from an SSLv2-format ClientHello, `TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA` preferred, RSA and RC4 as fallbacks
- 1024-bit DH (RFC 2409 group 2)
- leaf + CA certificate chain. The DNASrep CA uses an ancient signature OID tlslite can't parse, so it is sent as raw bytes.
- application data is not split into 1-byte + rest records. tlslite does this by default on TLS 1.0, the original server didn't.

## Requirements

- Python 3.9 or newer
- Ports 53/udp and 443/tcp free on the server (root/sudo on Linux)
- A PS2 emulator or console whose DNS you can set manually

## Setup

Do this in **each** of the three folders (`dns`, `dnas`, `ssl_reverse_proxy`):

Linux / Raspberry Pi:
```bash
python3 -m venv venv
venv/bin/pip install -r requirements.txt
```

Windows:
```bat
python -m venv venv
venv\Scripts\pip install -r requirements.txt
```

Then edit **`dns/dns_map.json`** and replace `192.168.1.100` with the LAN IP of the machine running
`ssl_reverse_proxy`. Give that machine a fixed IP (DHCP reservation or static).

## Running

Start each server from its own folder, in this order (Linux shown, ports below 1024 need sudo):

```bash
cd dns && sudo venv/bin/python dns.py
```
```bash
cd dnas && venv/bin/python dnas_async.py
```
```bash
cd ssl_reverse_proxy && sudo venv/bin/python reverse_proxy.py
```

Every server takes `--config <file.ini>` and `--debug`. Each reads its ini from its own folder by default and
writes a default one if it is missing.

Check DNS from another machine before starting the game. It should answer with your server's IP:
```bash
nslookup gate1.us.dnas.playstation.org <server-ip>
```

## PCSX2 setup

In the network settings (labels vary between versions):

- enable networking, Ethernet device type **Sockets** (PCAP bridging is unreliable over Wi-Fi)
- with **Intercept DHCP** on, set **DNS1** to manual: your DNS server's IP

Or set the DNS manually in the game's own network configuration. Don't use `127.0.0.1`: inside the emulator
that means the emulated PS2 itself, not your PC.

A successful DNAS check is three short HTTPS sessions. In the logs:

```
dns                [192.168.1.50:58094] A gate1.us.dnas.playstation.org. -> 192.168.1.100
ssl_reverse_proxy  [192.168.1.50:59691] Handshake OK: TLS 1.0 TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA
dnas               POST /us-gw/v2.5_i-connect (308 byte body)
dnas               us-gw fce93cdf12e5623e_01080000 -> 328 bytes
dnas               POST /us-gw/v2.5_others (184 byte body)
dnas               us-gw 8df6b52939ecf543_01080001 -> 170 bytes
dnas               POST /us-gw/v2.5_others (44 byte body)
dnas               us-gw 8df6b52939ecf543_01088008 -> 77 bytes
```

## Configuration

| File | What to change |
|---|---|
| `dns/dns_map.json` | Hostname → IP. Case-insensitive; `"*.dnas.playstation.org"` style wildcards work. |
| `dns/ps2_dns.ini` | Listen address, upstream DNS servers (`ip` or `ip:port`), or `enabled = no` to answer only mapped names. |
| `ssl_reverse_proxy/ssl_reverse_proxy.ini` | Listen address, backend address, certificate (`cert-us`, `cert-eu`, `cert-jp`), TLS options, timeouts. |
| `dnas/dnas_server.ini` | Listen address and `packet_root` (the folder with `us-gw`, `eu-gw`, `gai-gw`). |

## Game support

Games are only supported if DNASrep has captured packets for them, in `dnas/gateways/<region>-gw/packets/`,
named `<game id>_<query type>`. A game without packets gets DNASrep's `error.raw` reply and the backend logs:

```
MISSING us-gw/packets/<game id>_<query type> -> error.raw
```

Each game uses two IDs: one in the `v2.5_i-connect` request and another in the `v2.5_others` requests.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| No lookup in the DNS log | The emulator isn't using your DNS server. Check the DNS1 setting. |
| Lookup logged, nothing in the proxy log | Port 443 blocked by a firewall, or `dns_map.json` points at the wrong IP. |
| `Handshake failed` in the proxy log | TLS problem. A `tcpdump -i any -w dnas.pcap port 443` capture on the server shows why. |
| `Backend ... unreachable` in the proxy log | `dnas_async.py` isn't running, or the `[BACKEND]` address is wrong. |
| `MISSING ...` in the backend log | No packets for this game in DNASrep's data. |
| Game times out, slow server | Pure Python crypto, about 0.5 s per handshake on a Pi. `pip install gmpy2 pycryptodome` in `ssl_reverse_proxy`'s venv speeds it up; tlslite uses them automatically. |

Notes:
- The DNASrep certificates expired in April 2026. The tested US title didn't check this.
- `cert-*-key.pem` are DNASrep's public keys, not secrets. The PS2 only works with these certificates.

## Credits

- **the_fog**: DNASrep, the PHP server, packets and certificates this is based on: https://github.com/FogNo23/
- **DNAS Forever project**: the original packet captures
- **tlsfuzzer/tlslite-ng**: pure Python TLS
- **dnslib**: DNS packet handling

## License

GNU Affero General Public License v3.0, the same as DNASrep. See [LICENSE](LICENSE).

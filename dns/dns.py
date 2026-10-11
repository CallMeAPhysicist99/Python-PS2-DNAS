"""
DNS server for PS2 DNAS: answers the DNAS gateway hostnames with your server's IP, forwards everything else.

Point the PS2 / PCSX2 DNS at the machine running this. Names in dns_map.json get an A record with the mapped
IP; all other queries are relayed to an upstream resolver so games can still reach their own servers.

dns_map.json format (names are case-insensitive, "*." prefix matches any subdomain):
    {
        "gate1.us.dnas.playstation.org": "192.168.1.50",
        "*.dnas.playstation.org": "192.168.1.50"
    }

Requires: pip install -r requirements.txt
Usage:    python dns.py [--config ps2_dns.ini] [--debug]
Note: UDP only. PS2 DNS lookups are small enough that TCP fallback isn't needed.
"""

import argparse
import ipaddress
import json
import logging
import socket
import socketserver
from configparser import ConfigParser
from pathlib import Path

from dnslib import DNSRecord, DNSError, RR, QTYPE, RCODE, A

log = logging.getLogger("dns")

MAX_PACKET = 4096
ANSWER_TTL = 60

DEFAULT_CONFIG = {
    "DNS": {
        "host": "0.0.0.0",
        "port": "53",
        # Note: Relative to this ini file.
        "map_path": "dns_map.json",
    },
    "UPSTREAM": {
        # Note: Forward names that aren't in the map. Disable to answer only mapped names (others get NXDOMAIN).
        "enabled": "yes",
        # Note: Tried in order until one answers. "ip" or "ip:port".
        "servers": "8.8.8.8, 1.1.1.1",
        "timeout": "3",
    },
}


class DnsConfig:
    def __init__(self, ini_path: Path):
        config = ConfigParser()
        config.read_dict(DEFAULT_CONFIG)

        if not ini_path.exists():
            with open(ini_path, "w") as cfg_file:
                config.write(cfg_file)
            log.info("Created default config: %s", ini_path)

        config.read(ini_path)
        base_dir = ini_path.resolve().parent

        dns_sec = config["DNS"]
        self.host = str(ipaddress.IPv4Address(dns_sec.get("host").strip()))
        self.port = dns_sec.getint("port")
        self.map_path = base_dir / dns_sec.get("map_path").strip()

        upstream_sec = config["UPSTREAM"]
        self.upstream_enabled = upstream_sec.getboolean("enabled")
        self.upstream_servers = [_parse_upstream(s) for s in upstream_sec.get("servers").split(",") if s.strip()]
        self.upstream_timeout = upstream_sec.getfloat("timeout")
        if self.upstream_enabled and not self.upstream_servers:
            raise ValueError("Upstream forwarding is enabled but no upstream servers are configured")


def _parse_upstream(server: str) -> tuple:
    """"ip" or "ip:port" -> (ip, port)."""
    host, _, port = server.strip().partition(":")
    return str(ipaddress.IPv4Address(host)), int(port or 53)


class HostMap:
    """Exact names and "*.suffix" wildcards, case-insensitive. Exact names win."""

    def __init__(self, map_path: Path):
        if not map_path.exists():
            raise FileNotFoundError(f"No DNS map at {map_path}. Create it with host:ip entries (see dns.py).")
        with open(map_path, "r") as map_file:
            entries = json.load(map_file)

        self.exact = {}
        self.wildcards = {}
        for name, ip in entries.items():
            name = name.strip().lower().rstrip(".")
            ip = str(ipaddress.IPv4Address(ip.strip()))
            if name.startswith("*."):
                self.wildcards[name[2:]] = ip
            else:
                self.exact[name] = ip

    def lookup(self, name: str):
        name = name.lower().rstrip(".")
        if name in self.exact:
            return self.exact[name]
        # Note: Longest matching suffix wins, so "*.us.dnas.playstation.org" beats "*.playstation.org".
        labels = name.split(".")
        for i in range(1, len(labels)):
            suffix = ".".join(labels[i:])
            if suffix in self.wildcards:
                return self.wildcards[suffix]
        return None

    def __len__(self):
        return len(self.exact) + len(self.wildcards)


class DnsHandler(socketserver.BaseRequestHandler):
    server: "PS2DnsServer"

    def handle(self) -> None:
        data, sock = self.request
        client = f"{self.client_address[0]}:{self.client_address[1]}"

        try:
            query = DNSRecord.parse(data)
        except (DNSError, ValueError, IndexError) as e:
            # Note: Not DNS (or mangled). Nothing sensible to reply to.
            log.warning("[%s] Dropped malformed packet (%d bytes): %s", client, len(data), e)
            return

        if not query.questions:
            self._send(sock, self._reply(query, RCODE.FORMERR), client)
            return

        question = query.questions[0]
        qname = str(question.qname)
        qtype = QTYPE.get(question.qtype, str(question.qtype))
        mapped_ip = self.server.host_map.lookup(qname)

        if mapped_ip is not None:
            reply = query.reply()
            if question.qtype in (QTYPE.A, QTYPE.ANY):
                reply.add_answer(RR(question.qname, QTYPE.A, rdata=A(mapped_ip), ttl=ANSWER_TTL))
                log.info("[%s] %s %s -> %s", client, qtype, qname, mapped_ip)
            else:
                # Note: Name exists but has no record of this type (e.g. AAAA). Empty NOERROR, don't forward.
                log.info("[%s] %s %s -> no data (mapped name, only A records)", client, qtype, qname)
            self._send(sock, reply.pack(), client)
            return

        if not self.server.cfg.upstream_enabled:
            log.info("[%s] %s %s -> NXDOMAIN (not mapped, forwarding disabled)", client, qtype, qname)
            self._send(sock, self._reply(query, RCODE.NXDOMAIN), client)
            return

        upstream_reply = self._forward(data, query.header.id)
        if upstream_reply is None:
            log.warning("[%s] %s %s -> SERVFAIL (no upstream answered)", client, qtype, qname)
            self._send(sock, self._reply(query, RCODE.SERVFAIL), client)
        else:
            log.debug("[%s] %s %s -> forwarded", client, qtype, qname)
            self._send(sock, upstream_reply, client)

    def _forward(self, data: bytes, query_id: int):
        for upstream in self.server.cfg.upstream_servers:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream_sock:
                upstream_sock.settimeout(self.server.cfg.upstream_timeout)
                try:
                    upstream_sock.connect(upstream)
                    upstream_sock.send(data)
                    while True:
                        reply = upstream_sock.recv(MAX_PACKET)
                        # Note: Ignore stray datagrams that aren't the answer to this query.
                        if len(reply) >= 2 and int.from_bytes(reply[:2], "big") == query_id:
                            return reply
                except OSError as e:
                    log.warning("Upstream %s:%d failed: %r", *upstream, e)
        return None

    @staticmethod
    def _reply(query: DNSRecord, rcode: int) -> bytes:
        reply = query.reply()
        reply.header.rcode = rcode
        return reply.pack()

    def _send(self, sock: socket.socket, payload: bytes, client: str) -> None:
        try:
            sock.sendto(payload, self.client_address)
        except OSError as e:
            log.warning("[%s] Could not send reply: %r", client, e)


class PS2DnsServer(socketserver.ThreadingUDPServer):
    # Note: One thread per query, so a slow upstream never blocks the DNAS answers.
    daemon_threads = True
    max_packet_size = MAX_PACKET

    def __init__(self, cfg: DnsConfig, host_map: HostMap):
        self.cfg = cfg
        self.host_map = host_map
        super().__init__((cfg.host, cfg.port), DnsHandler)


def main() -> None:
    parser = argparse.ArgumentParser(description="DNS server that points PS2 DNAS hostnames at your server.")
    parser.add_argument("--config", default=str(Path(__file__).with_name("ps2_dns.ini")),
                        help="Path to the ini file (created with defaults if missing).")
    parser.add_argument("--debug", action="store_true", help="Also log every forwarded query.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s")

    cfg = DnsConfig(Path(args.config))
    host_map = HostMap(cfg.map_path)

    with PS2DnsServer(cfg, host_map) as server:
        log.info("DNS server on %s:%d, %d mapped name(s), upstream: %s", cfg.host, cfg.port, len(host_map),
                 ", ".join(f"{h}:{p}" for h, p in cfg.upstream_servers) if cfg.upstream_enabled else "disabled")
        for name, ip in sorted(host_map.exact.items()) + sorted(("*." + k, v) for k, v in host_map.wildcards.items()):
            log.info("  %s -> %s", name, ip)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            log.info("Stopping DNS server")


if __name__ == "__main__":
    main()

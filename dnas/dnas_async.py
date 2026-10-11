"""
DNAS backend: asyncio HTTP/1.0 server replacing DNASrep's Apache + PHP.

Based on DNASrep - DNAS replacement server, Copyright (C) 2016 the_fog@1337.rip
Licensed under the GNU Affero General Public License v3 or later, same as DNASrep (see LICENSE).

Sits behind the SSL reverse proxy, which forwards the PS2's decrypted HTTP requests here. Routes like
DNASrep's DocumentRoot, where the region is part of the URL path:
    /<region>-gw/v2.5_i-connect   (or connect.php)  -> connect_reply
    /<region>-gw/v2.5_others      (or others.php)   -> others_reply
<region>-gw is any gateway folder under packet_root (us-gw, eu-gw, gai-gw), each with packets/ and error.raw.
The bundled gateways/ folder holds DNASrep's packet captures.

Requires: pip install -r requirements.txt
Usage:    python dnas_async.py [--config dnas_server.ini] [--debug]
"""

import argparse
import asyncio
import ipaddress
import logging
from configparser import ConfigParser
from pathlib import Path

from dnas_encryption import connect_reply, others_reply

log = logging.getLogger("dnas")

ROUTES = {
    "v2.5_i-connect": connect_reply,
    "connect.php": connect_reply,
    "v2.5_others": others_reply,
    "others.php": others_reply,
}

MAX_HEADER_SIZE = 8192
MAX_BODY_SIZE = 64 * 1024

DEFAULT_CONFIG = {
    "SERVER": {
        "host": "127.0.0.1",
        "port": "8000",
        "request_timeout": "15",
    },
    "DNAS": {
        # Note: Folder holding the <region>-gw gateway folders. Relative to this ini file.
        "packet_root": "gateways",
    },
}


class HttpError(Exception):
    def __init__(self, status: str, reason: str):
        super().__init__(reason)
        self.status = status
        self.reason = reason


class DnasConfig:
    def __init__(self, ini_path: Path):
        config = ConfigParser()
        config.read_dict(DEFAULT_CONFIG)

        if not ini_path.exists():
            with open(ini_path, "w") as cfg_file:
                config.write(cfg_file)
            log.info("Created default config: %s", ini_path)

        config.read(ini_path)
        base_dir = ini_path.resolve().parent

        server_sec = config["SERVER"]
        self.host = valid_ipv4(server_sec.get("host").strip())
        self.port = valid_port(server_sec.getint("port"))
        self.request_timeout = server_sec.getfloat("request_timeout")

        self.packet_root = (base_dir / config["DNAS"].get("packet_root").strip()).resolve()
        if not self.packet_root.is_dir():
            raise FileNotFoundError(f"packet_root not found: {self.packet_root}")


def valid_ipv4(ip: str) -> str:
    try:
        ipaddress.IPv4Address(ip)
    except ValueError:
        raise ValueError(f"Invalid IPv4 address: {ip}")
    return ip


def valid_port(port: int) -> int:
    if not 0 < port <= 65535:
        raise ValueError(f"Invalid port: {port}")
    return port


class DnasServer:
    def __init__(self, cfg: DnasConfig):
        self.cfg = cfg
        self.gateways = {p.name for p in cfg.packet_root.iterdir() if p.is_dir() and p.name.endswith("-gw")}
        if not self.gateways:
            raise FileNotFoundError(f"No <region>-gw folders in {cfg.packet_root}")

    async def serve_forever(self) -> None:
        server = await asyncio.start_server(self.handle_connection, host=self.cfg.host, port=self.cfg.port)
        log.info("DNAS server on %s:%d, gateways: %s (%s)", self.cfg.host, self.cfg.port,
                 ", ".join(sorted(self.gateways)), self.cfg.packet_root)
        async with server:
            await server.serve_forever()

    async def handle_connection(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        tag = f"{peer[0]}:{peer[1]}" if peer else "?"
        try:
            try:
                method, path, headers, body = await asyncio.wait_for(read_request(reader),
                                                                     self.cfg.request_timeout)
                log.info("[%s] %s %s (%d byte body)", tag, method, path, len(body))
                log.debug("[%s] Headers: %s", tag, headers)
                status, reply = await self.dispatch(tag, path, body)
            except HttpError as e:
                log.warning("[%s] %s: %s", tag, e.status, e.reason)
                status, reply = e.status, b""
            except (asyncio.TimeoutError, asyncio.IncompleteReadError, ConnectionError) as e:
                log.warning("[%s] Incomplete request: %r", tag, e)
                return

            writer.write(build_response(status, reply))
            await writer.drain()
        except ConnectionError as e:
            log.warning("[%s] Client went away: %r", tag, e)
        finally:
            # Note: HTTP/1.0, one request per connection. Closing tells the proxy to send close_notify.
            writer.close()
            try:
                await writer.wait_closed()
            except ConnectionError:
                pass

    async def dispatch(self, tag: str, path: str, body: bytes) -> tuple:
        parts = path.split("?", 1)[0].strip("/").split("/")
        if len(parts) != 2 or parts[0] not in self.gateways or parts[1] not in ROUTES:
            raise HttpError("404 Not Found", f"No route for {path}")

        gateway, endpoint = parts
        handler = ROUTES[endpoint]
        try:
            # Note: Pure Python 3DES is CPU bound; keep it off the event loop.
            reply = await asyncio.to_thread(handler, body, self.cfg.packet_root / gateway)
        except Exception:
            log.exception("[%s] Failed to build reply for %s", tag, path)
            raise HttpError("500 Internal Server Error", "Reply generation failed")

        if reply.found:
            log.info("[%s] %s %s -> %d bytes", tag, gateway, reply.packet_name, len(reply.body))
        else:
            # Note: Missing packets are the games DNASrep has no capture for. Worth collecting.
            log.warning("[%s] MISSING %s/packets/%s -> error.raw", tag, gateway, reply.packet_name)
        return "200 OK", reply.body


async def read_request(reader: asyncio.StreamReader) -> tuple:
    try:
        head = await reader.readuntil(b"\r\n\r\n")
    except asyncio.LimitOverrunError:
        raise HttpError("431 Request Header Fields Too Large", "Header too large")
    if len(head) > MAX_HEADER_SIZE:
        raise HttpError("431 Request Header Fields Too Large", "Header too large")

    lines = head.decode("latin-1").split("\r\n")
    try:
        method, path, _version = lines[0].split(" ", 2)
    except ValueError:
        raise HttpError("400 Bad Request", f"Bad request line: {lines[0]!r}")

    headers = {}
    for line in lines[1:]:
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.strip().lower()] = value.strip()

    try:
        length = int(headers.get("content-length", "0"))
    except ValueError:
        raise HttpError("400 Bad Request", "Bad Content-Length")
    if not 0 <= length <= MAX_BODY_SIZE:
        raise HttpError("413 Payload Too Large", f"Content-Length {length}")

    body = await reader.readexactly(length)
    return method, path, headers, body


def build_response(status: str, body: bytes) -> bytes:
    # Note: Same headers connect.php/others.php set.
    head = (f"HTTP/1.0 {status}\r\n"
            f"Content-Type: image/gif\r\n"
            f"Content-Length: {len(body)}\r\n"
            f"Connection: close\r\n\r\n")
    return head.encode("ascii") + body


def main() -> None:
    parser = argparse.ArgumentParser(description="DNAS backend (DNASrep replacement) for the SSL reverse proxy.")
    parser.add_argument("--config", default=str(Path(__file__).with_name("dnas_server.ini")),
                        help="Path to the ini file (created with defaults if missing).")
    parser.add_argument("--debug", action="store_true", help="Verbose logging, including request headers.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s")
    # Note: asyncio's debug logging is noisy and unrelated to DNAS.
    logging.getLogger("asyncio").setLevel(logging.WARNING)

    server = DnasServer(DnasConfig(Path(args.config)))
    try:
        asyncio.run(server.serve_forever())
    except KeyboardInterrupt:
        log.info("Stopping DNAS server")


if __name__ == "__main__":
    main()

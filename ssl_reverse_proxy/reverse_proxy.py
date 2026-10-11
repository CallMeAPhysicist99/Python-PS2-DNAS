"""
Pure Python SSL/TLS terminating reverse proxy for PS2 DNAS clients.

Accepts the PS2's legacy handshake (SSLv2-format ClientHello, TLS 1.0, 3DES/RC4 ciphers) using tlslite-ng,
then relays the decrypted byte stream to a plain TCP backend (e.g. the DNAS server). No OpenSSL required.

Handshake matches the original DNAS replacement server as seen in Wireshark:
    - TLS_DHE_RSA_WITH_3DES_EDE_CBC_SHA (0x0016), RSA key exchange and RC4 as fallbacks
    - 1024-bit DH, RFC 2409 Oakley group 2, g = 2
    - leaf certificate + CA certificate chain
    - application data records are not split (no 1/n-1 BEAST countermeasure)

Requires: pip install -r requirements.txt
Usage:    python reverse_proxy.py [--config ssl_reverse_proxy.ini] [--debug]
"""

import argparse
import logging
import socket
import threading
import time
from configparser import ConfigParser
from pathlib import Path

from tlslite.api import (TLSConnection, HandshakeSettings, SessionCache, X509, X509CertChain, parsePEMKey)
from tlslite.constants import CipherSuite, AlertDescription, AlertLevel
from tlslite.errors import TLSError, TLSClosedConnectionError
from tlslite.messages import ApplicationData, Alert
from tlslite.utils.pem import dePemList

log = logging.getLogger("ssl_proxy")

# Note: RFC 2409 Oakley group 2 (1024-bit). Same prime the original DNAS server sent in its ServerKeyExchange.
DH_GROUP_1024 = (2, int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF", 16))

TLS_VERSIONS = {"SSLv3": (3, 0), "TLSv1.0": (3, 1), "TLSv1.1": (3, 2), "TLSv1.2": (3, 3)}

BUFFER_SIZE = 16384

DEFAULT_CONFIG = {
    "SERVER": {
        "host": "0.0.0.0",
        "port": "443",
    },
    "BACKEND": {
        "host": "127.0.0.1",
        "port": "8000",
    },
    "SSL": {
        "certificate_path": "cert-us.pem",
        "private_key_path": "cert-us-key.pem",
        # Note: Optional. Extra certificates sent after the leaf (the DNASrep CA). Leave empty to send the leaf only.
        "chain_path": "ca-cert.pem",
    },
    "TLS": {
        "min_version": "SSLv3",
        "max_version": "TLSv1.0",
        # Note: Server preference order. tlslite names: 3des, rc4, aes128, aes256, ...
        "ciphers": "3des, rc4",
        # Note: tlslite names: dhe_rsa, rsa
        "key_exchange": "dhe_rsa, rsa",
        "macs": "sha, md5",
        # Note: tlslite splits TLS 1.0 CBC records as 1 byte + rest by default. The original server did not.
        "split_first_record": "no",
    },
    "TIMEOUTS": {
        "handshake": "15",
        "idle": "60",
        "backend_connect": "10",
        "close_linger": "5",
    },
}


class ProxyConfig:
    def __init__(self, ini_path: Path):
        config = ConfigParser()
        config.read_dict(DEFAULT_CONFIG)

        if not ini_path.exists():
            with open(ini_path, "w") as cfg_file:
                config.write(cfg_file)
            log.info("Created default config: %s", ini_path)

        config.read(ini_path)
        base_dir = ini_path.resolve().parent

        self.host = config["SERVER"].get("host").strip()
        self.port = config["SERVER"].getint("port")
        self.backend_host = config["BACKEND"].get("host").strip()
        self.backend_port = config["BACKEND"].getint("port")

        # Note: Paths are relative to the ini file, not the working directory.
        ssl_sec = config["SSL"]
        self.cert_path = base_dir / ssl_sec.get("certificate_path").strip()
        self.key_path = base_dir / ssl_sec.get("private_key_path").strip()
        chain = ssl_sec.get("chain_path", "").strip()
        self.chain_path = base_dir / chain if chain else None

        tls_sec = config["TLS"]
        self.min_version = _parse_version(tls_sec.get("min_version"))
        self.max_version = _parse_version(tls_sec.get("max_version"))
        self.ciphers = _parse_list(tls_sec.get("ciphers"))
        self.key_exchange = _parse_list(tls_sec.get("key_exchange"))
        self.macs = _parse_list(tls_sec.get("macs"))
        self.split_first_record = tls_sec.getboolean("split_first_record")

        timeout_sec = config["TIMEOUTS"]
        self.handshake_timeout = timeout_sec.getfloat("handshake")
        self.idle_timeout = timeout_sec.getfloat("idle")
        self.backend_connect_timeout = timeout_sec.getfloat("backend_connect")
        self.close_linger = timeout_sec.getfloat("close_linger")


def _parse_version(name: str) -> tuple:
    name = name.strip()
    if name not in TLS_VERSIONS:
        raise ValueError(f"Unknown TLS version '{name}'. Use one of: {', '.join(TLS_VERSIONS)}")
    return TLS_VERSIONS[name]


def _parse_list(value: str) -> list:
    return [item.strip() for item in value.split(",") if item.strip()]


class ProxyTLSConnection(TLSConnection):
    """TLSConnection with record splitting made optional and a non-blocking close_notify."""

    split_first_record = False

    def writeAsync(self, s):
        if self.split_first_record:
            yield from super().writeAsync(s)
            return

        # Note: Same as TLSRecordLayer.writeAsync, minus the forced 1/n-1 split of CBC records.
        try:
            if self.closed:
                raise TLSClosedConnectionError("attempt to write to closed connection")
            for result in self._sendMsg(ApplicationData().create(bytearray(s)), randomizeFirstBlock=False):
                yield result
        except GeneratorExit:
            raise
        except Exception:
            self._shutdown(self.ignoreAbruptClose)
            raise

    def send_close_notify(self) -> None:
        """Send close_notify without waiting for the peer's reply (the reader thread consumes that)."""
        if self.closed:
            return
        alert = Alert().create(AlertDescription.close_notify, AlertLevel.warning)
        for _ in self._sendMsg(alert):
            pass


class _RawX509(X509):
    """Certificate tlslite cannot parse (e.g. the DNASrep CA's 1.3.14.3.2.15 signature OID), sent as-is."""

    def __init__(self, der: bytes):
        super().__init__()
        self.bytes = bytearray(der)


def load_credentials(cfg: ProxyConfig) -> tuple:
    leaf = X509()
    leaf.parse(cfg.cert_path.read_text())
    certs = [leaf]

    if cfg.chain_path:
        for der in dePemList(cfg.chain_path.read_text(), "CERTIFICATE"):
            cert = X509()
            try:
                cert.parseBinary(der)
            except (KeyError, SyntaxError, ValueError):
                cert = _RawX509(der)
            certs.append(cert)

    key = parsePEMKey(cfg.key_path.read_text(), private=True)
    if key.n != leaf.publicKey.n:
        raise ValueError(f"Private key {cfg.key_path.name} does not match certificate {cfg.cert_path.name}")

    return X509CertChain(certs), key


def build_settings(cfg: ProxyConfig) -> HandshakeSettings:
    settings = HandshakeSettings()
    settings.minVersion = cfg.min_version
    settings.maxVersion = cfg.max_version
    settings.cipherNames = cfg.ciphers
    settings.keyExchangeNames = cfg.key_exchange
    settings.macNames = cfg.macs
    settings.dhParams = DH_GROUP_1024
    # Note: Validates names/versions now, so a typo in the ini fails at startup instead of on the first client.
    return settings.validate()


class ProxySession:
    """One client connection: TLS handshake, then a bidirectional relay to the backend."""

    def __init__(self, server: "SSLReverseProxy", client_sock: socket.socket, addr: tuple):
        self.server = server
        self.cfg = server.cfg
        self.client_sock = client_sock
        self.tag = f"{addr[0]}:{addr[1]}"
        self.tls = ProxyTLSConnection(client_sock)
        self.tls.split_first_record = self.cfg.split_first_record
        self.backend = None
        self.closing = threading.Event()
        self.bytes_up = 0
        self.bytes_down = 0

    def run(self) -> None:
        start = time.monotonic()
        try:
            if self._handshake() and self._connect_backend():
                self._relay()
        finally:
            self._close_all()
            log.info("[%s] Closed (client->backend %d bytes, backend->client %d bytes, %.2fs)",
                     self.tag, self.bytes_up, self.bytes_down, time.monotonic() - start)

    def _handshake(self) -> bool:
        self.client_sock.settimeout(self.cfg.handshake_timeout)
        try:
            self.tls.handshakeServer(certChain=self.server.cert_chain,
                                     privateKey=self.server.private_key,
                                     settings=self.server.settings,
                                     sessionCache=self.server.session_cache)
        except (TLSError, OSError) as e:
            log.warning("[%s] Handshake failed: %r", self.tag, e)
            return False

        suite = CipherSuite.ietfNames.get(self.tls.session.cipherSuite, hex(self.tls.session.cipherSuite))
        log.info("[%s] Handshake OK: %s %s%s", self.tag, self.tls.getVersionName(), suite,
                 " (resumed)" if self.tls.resumed else "")
        self.client_sock.settimeout(self.cfg.idle_timeout)
        return True

    def _connect_backend(self) -> bool:
        try:
            self.backend = socket.create_connection((self.cfg.backend_host, self.cfg.backend_port),
                                                    timeout=self.cfg.backend_connect_timeout)
        except OSError as e:
            log.error("[%s] Backend %s:%d unreachable: %r", self.tag, self.cfg.backend_host,
                      self.cfg.backend_port, e)
            return False
        self.backend.settimeout(None)
        return True

    def _relay(self) -> None:
        upstream = threading.Thread(target=self._client_to_backend, name=f"up-{self.tag}", daemon=True)
        upstream.start()
        self._backend_to_client()
        upstream.join(self.cfg.close_linger)

    def _client_to_backend(self) -> None:
        try:
            while True:
                data = self.tls.read()
                if not data:
                    break
                self.bytes_up += len(data)
                self.backend.sendall(data)
            # Note: Client sent close_notify. Half-close so the backend sees EOF but can still answer.
            self.backend.shutdown(socket.SHUT_WR)
        except (TLSError, OSError) as e:
            if not self.closing.is_set():
                log.warning("[%s] Client read ended: %r", self.tag, e)
            self._abort()

    def _backend_to_client(self) -> None:
        try:
            while True:
                data = self.backend.recv(BUFFER_SIZE)
                if not data:
                    break
                self.tls.write(data)
                self.bytes_down += len(data)
            # Note: Backend finished. Tell the client; its close_notify reply ends the upstream thread.
            self.tls.send_close_notify()
        except (TLSError, OSError) as e:
            if not self.closing.is_set():
                log.warning("[%s] Backend relay ended: %r", self.tag, e)
            self._abort()

    def _abort(self) -> None:
        """Unblock both relay directions."""
        self.closing.set()
        for sock in (self.backend, self.client_sock):
            if sock is not None:
                try:
                    sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass

    def _close_all(self) -> None:
        self.closing.set()
        for sock in (self.backend, self.client_sock):
            if sock is not None:
                try:
                    sock.close()
                except OSError:
                    pass


class SSLReverseProxy:
    def __init__(self, cfg: ProxyConfig):
        self.cfg = cfg
        self.cert_chain, self.private_key = load_credentials(cfg)
        self.settings = build_settings(cfg)
        self.session_cache = SessionCache()

    def serve_forever(self) -> None:
        # Note: TCP only. Wireshark showed no UDP traffic from the PS2.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
            listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            listener.bind((self.cfg.host, self.cfg.port))
            listener.listen(16)
            # Note: Timeout keeps the accept loop responsive to Ctrl+C on Windows.
            listener.settimeout(1.0)

            log.info("Listening (SSL/TLS) on %s:%d -> backend %s:%d", self.cfg.host, self.cfg.port,
                     self.cfg.backend_host, self.cfg.backend_port)
            log.info("Certificate chain: %d certificate(s), %s", self.cert_chain.getNumCerts(),
                     "split records" if self.cfg.split_first_record else "unsplit records")

            while True:
                try:
                    client_sock, addr = listener.accept()
                except socket.timeout:
                    continue
                log.info("[%s:%d] Client connected", *addr)
                session = ProxySession(self, client_sock, addr)
                threading.Thread(target=session.run, name=f"conn-{addr[0]}:{addr[1]}", daemon=True).start()


def main() -> None:
    parser = argparse.ArgumentParser(description="Pure Python SSL/TLS reverse proxy for PS2 DNAS clients.")
    parser.add_argument("--config", default=str(Path(__file__).with_name("ssl_reverse_proxy.ini")),
                        help="Path to the ini file (created with defaults if missing).")
    parser.add_argument("--debug", action="store_true", help="Verbose logging.")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO,
                        format="%(asctime)s %(levelname)-7s %(message)s")

    proxy = SSLReverseProxy(ProxyConfig(Path(args.config)))
    try:
        proxy.serve_forever()
    except KeyboardInterrupt:
        log.info("Stopping SSL reverse proxy")


if __name__ == "__main__":
    main()

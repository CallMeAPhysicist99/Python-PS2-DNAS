"""
DNAS reply generation, ported from DNASrep's connect.php and others.php.

DNASrep - DNAS replacement server, Copyright (C) 2016 the_fog@1337.rip
Python port licensed under the GNU Affero General Public License v3 or later, same as DNASrep (see LICENSE).

connect.php's encrypt3() (XOR with previous block, DES encrypt k1, decrypt k2, encrypt k3) is exactly
3DES-EDE in CBC mode with key k1||k2||k3 and IV = xor_seed, so a standard 3DES-CBC is used here.
tlslite-ng supplies the cipher: pycryptodome/M2Crypto if installed, otherwise its pure Python 3DES.
"""

import hashlib
from dataclasses import dataclass
from pathlib import Path

from tlslite.utils.cipherfactory import createTripleDES

# Note: Fixed "envelope" keyset from connect.php: des_key1, des_key2, des_key3, xor_seed.
_ENVELOPE_KEYS = (bytes.fromhex("eb711416cb0ab016"),
                  bytes.fromhex("ae190174b5ce6339"),
                  bytes.fromhex("7b01b91880145e34"),
                  bytes.fromhex("c510a6400a9b022f"))

_CONNECT_GAME_ID_OFFSET = 0x2C
_OTHERS_GAME_ID_OFFSET = 0x1B

_ERROR_FILE = "error.raw"
_PACKETS_DIR = "packets"


@dataclass
class DnasReply:
    body: bytes
    packet_name: str
    found: bool


def encrypt3(data: bytes, offset: int, length: int, des_key1: bytes, des_key2: bytes, des_key3: bytes,
             xor_seed: bytes) -> bytes:
    """encrypt3() from connect.php: 3DES-EDE-CBC over data[offset:offset + length], rest untouched."""
    cipher = createTripleDES(des_key1 + des_key2 + des_key3, xor_seed)
    encrypted = cipher.encrypt(bytes(data[offset:offset + length]))
    return data[:offset] + bytes(encrypted) + data[offset + length:]


def _query_keys(query: bytes) -> tuple:
    """Step 0 of connect.php: DES keys and XOR seed from SHA-1 checksums of the query packet."""
    chk_sum1 = hashlib.sha1(query[0x34:0x34 + 0x100]).digest()
    chk_sum2 = hashlib.sha1(query[0x48:0x48 + 0xEC]).digest()
    full_key = chk_sum2[:0x14] + chk_sum1[:0x0C]
    return full_key[0:8], full_key[8:16], full_key[16:24], full_key[24:32]


def _packet_name(query: bytes, game_id_offset: int) -> str:
    game_id = query[game_id_offset:game_id_offset + 8]
    qry_type = query[:4]
    return f"{game_id.hex()}_{qry_type.hex()}"


def _read_packet(gateway_dir: Path, name: str):
    # Note: Like PHP's file_get_contents() in an if(), a missing or empty file counts as a miss.
    path = gateway_dir / _PACKETS_DIR / name
    try:
        data = path.read_bytes()
    except OSError:
        return None
    return data or None


def _error_reply(gateway_dir: Path, name: str) -> DnasReply:
    try:
        body = (gateway_dir / _ERROR_FILE).read_bytes()
    except OSError:
        body = b""
    return DnasReply(body=body, packet_name=name, found=False)


def connect_reply(query: bytes, gateway_dir: Path) -> DnasReply:
    """connect.php (v2.5_i-connect): replay the stored packet, encrypted with query keys then envelope keys."""
    name = _packet_name(query, _CONNECT_GAME_ID_OFFSET)
    packet = _read_packet(gateway_dir, name)
    if packet is None:
        return _error_reply(gateway_dir, name)

    # Step 2 - encrypt with keyset from query packet
    packet = encrypt3(packet, 0xC8, 0x20, *_query_keys(query))
    # Step 3 - encrypt with envelope keyset
    packet = encrypt3(packet, 0x28, 0x120, *_ENVELOPE_KEYS)
    return DnasReply(body=packet, packet_name=name, found=True)


def others_reply(query: bytes, gateway_dir: Path) -> DnasReply:
    """others.php (v2.5_others): replay the stored packet as-is."""
    name = _packet_name(query, _OTHERS_GAME_ID_OFFSET)
    packet = _read_packet(gateway_dir, name)
    if packet is None:
        return _error_reply(gateway_dir, name)
    return DnasReply(body=packet, packet_name=name, found=True)

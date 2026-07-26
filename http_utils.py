"""Shared ASGI header, cookie, and host helpers used by the app and the terminal gateway."""

from __future__ import annotations

import secrets
from ipaddress import ip_address
from typing import TYPE_CHECKING
from urllib.parse import parse_qsl

if TYPE_CHECKING:
    from collections.abc import Iterable, Mapping

# ASGI scope key carrying the originating client IP once a trusted proxy has been consulted.
CLIENT_IP_SCOPE_KEY = 'wake.client_ip'


def decode_headers(raw_headers: Iterable[tuple[bytes, bytes]]) -> dict[str, str]:
    """Decode raw ASGI headers into a lower-cased latin-1 mapping."""
    return {key.decode('latin-1').lower(): value.decode('latin-1') for key, value in raw_headers}


def tokens_match(left: str | None, right: str | None) -> bool:
    """Compare two tokens in constant time without raising on non-ASCII input."""
    if not left or not right:
        return False
    return secrets.compare_digest(left.encode('utf-8', 'surrogateescape'), right.encode('utf-8', 'surrogateescape'))


def count_header(raw_headers: Iterable[tuple[bytes, bytes]], header_name: str) -> int:
    """Count how often a header occurs, so security-sensitive duplicates can be rejected."""
    wanted = header_name.lower().encode('latin-1')
    return sum(1 for key, _ in raw_headers if key.lower() == wanted)


def parse_cookie_header(cookie_header: str | None) -> dict[str, str]:
    """Parse a Cookie header into a mapping, ignoring malformed pairs."""
    if not cookie_header:
        return {}

    cookies: dict[str, str] = {}
    for chunk in cookie_header.split(';'):
        item = chunk.strip()
        if not item or '=' not in item:
            continue
        key, value = item.split('=', 1)
        cookies[key.strip()] = value.strip()
    return cookies


def etag_matches(if_none_match: str | None, etag: str) -> bool:
    """Match an If-None-Match header against an entity tag, accepting weak and unquoted forms."""
    if not if_none_match:
        return False

    expected = etag.strip().strip('"')
    for raw_candidate in if_none_match.split(','):
        candidate = raw_candidate.strip()
        if candidate == '*':
            return True
        if candidate[:2].lower() == 'w/':
            candidate = candidate[2:]
        if candidate.strip('"') == expected:
            return True
    return False


def replace_header(
    raw_headers: Iterable[tuple[bytes, bytes]], header_name: bytes, header_value: bytes
) -> list[tuple[bytes, bytes]]:
    """Return raw ASGI headers with exactly one occurrence of the named header."""
    updated: list[tuple[bytes, bytes]] = []
    replaced = False
    for key, value in raw_headers:
        if key.lower() == header_name:
            if not replaced:
                updated.append((header_name, header_value))
                replaced = True
            continue
        updated.append((key, value))

    if not replaced:
        updated.append((header_name, header_value))

    return updated


def first_forwarded_value(value: str | None) -> str | None:
    """Return the first entry of a comma-separated proxy header, or None."""
    if not value:
        return None
    first = value.split(',', 1)[0].strip()
    return first or None


def parse_forwarded_header(value: str | None) -> dict[str, str]:
    """Parse the first element of an RFC 7239 Forwarded header into its parameters."""
    first = first_forwarded_value(value)
    if not first:
        return {}

    forwarded: dict[str, str] = {}
    for key, raw_value in parse_qsl(first.replace(';', '&'), keep_blank_values=True):
        normalized_key = key.strip().lower()
        normalized_value = raw_value.strip().strip('"')
        if normalized_key and normalized_value:
            forwarded[normalized_key] = normalized_value
    return forwarded


def forwarded_client_ip(headers: Mapping[str, str]) -> str | None:
    """Return the originating client IP advertised by a trusted proxy, or None."""
    forwarded = parse_forwarded_header(headers.get('forwarded'))
    candidate = forwarded.get('for') or first_forwarded_value(headers.get('x-forwarded-for'))
    if not candidate:
        return None

    host = candidate.strip().strip('"')
    if host.startswith('['):
        host = host[1:].partition(']')[0]
    elif host.count(':') == 1:
        host = host.partition(':')[0]

    try:
        return str(ip_address(host))
    except ValueError:
        return None


def is_safe_host_header(value: str) -> bool:
    """Reject Host values that could inject headers or break authority parsing."""
    if not value or len(value) > 255:
        return False
    # Printable ASCII only: no whitespace, CTL, or non-ASCII (IDN must be punycode).
    return all(0x21 <= ord(character) <= 0x7E for character in value)


def header_safe_token_bytes(value: str) -> bytes | None:
    """Encode a CSRF token for an HTTP header, or None if it is not header-safe."""
    try:
        encoded = value.encode('latin-1')
    except UnicodeEncodeError:
        return None
    if not encoded or any(byte < 0x20 or byte == 0x7F for byte in encoded):
        return None
    return encoded

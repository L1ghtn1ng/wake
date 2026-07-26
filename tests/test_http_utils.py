import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from http_utils import (
    count_header,
    etag_matches,
    forwarded_client_ip,
    tokens_match,
)


def test_count_header_finds_smuggled_duplicates() -> None:
    raw_headers = [(b'Host', b'localhost'), (b'X-Wake-User', b'proxy'), (b'x-wake-user', b'attacker')]

    assert count_header(raw_headers, 'x-wake-user') == 2
    assert count_header(raw_headers, 'X-Wake-User') == 2
    assert count_header(raw_headers, 'host') == 1
    assert count_header(raw_headers, 'origin') == 0


def test_tokens_match_is_total_and_rejects_missing_values() -> None:
    assert tokens_match('token', 'token')
    assert not tokens_match('token', 'other')
    assert not tokens_match('token', None)
    assert not tokens_match(None, 'token')
    assert not tokens_match('', '')
    # Non-ASCII tokens must return False instead of raising, unlike secrets.compare_digest on str.
    assert not tokens_match('töken', 'token')
    assert tokens_match('töken', 'töken')


def test_etag_matches_accepts_weak_quoted_and_list_forms() -> None:
    assert etag_matches('"abc"', '"abc"')
    assert etag_matches('W/"abc"', '"abc"')
    assert etag_matches('w/"abc"', '"abc"')
    assert etag_matches('"other", W/"abc"', '"abc"')
    assert etag_matches('*', '"abc"')
    # Legacy clients that echo the unquoted digest still revalidate.
    assert etag_matches('abc', '"abc"')
    assert not etag_matches('"abcd"', '"abc"')
    assert not etag_matches(None, '"abc"')
    assert not etag_matches('', '"abc"')


def test_forwarded_client_ip_reads_only_valid_addresses() -> None:
    assert forwarded_client_ip({'forwarded': 'for=192.0.2.10;proto=https'}) == '192.0.2.10'
    assert forwarded_client_ip({'forwarded': 'for="192.0.2.10:44321"'}) == '192.0.2.10'
    assert forwarded_client_ip({'forwarded': 'for="[2001:db8::1]:44321"'}) == '2001:db8::1'
    assert forwarded_client_ip({'x-forwarded-for': '192.0.2.10, 10.0.0.1'}) == '192.0.2.10'
    assert forwarded_client_ip({'forwarded': 'for=unknown'}) is None
    assert forwarded_client_ip({'x-forwarded-for': 'not-an-ip'}) is None
    assert forwarded_client_ip({}) is None

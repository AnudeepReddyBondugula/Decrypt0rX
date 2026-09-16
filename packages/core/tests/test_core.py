"""Unit tests for the shared crypto, redaction and HTTP framing helpers."""

from __future__ import annotations

import asyncio
import base64

import pytest
from decrypt0rx_core.crypto import CryptoError, SecretBox, load_master_key
from decrypt0rx_core.pki import generate_root_ca, parse_ca_bundle
from decrypt0rx_core.redaction import redact_body, redact_headers, redact_url


class TestSecretBox:
    def test_round_trip(self):
        box = SecretBox(b"k" * 32)
        assert box.decrypt(box.encrypt(b"secret")) == b"secret"

    def test_ciphertext_differs_each_time(self):
        box = SecretBox(b"k" * 32)
        assert box.encrypt(b"same") != box.encrypt(b"same")

    def test_wrong_key_fails_loudly(self):
        payload = SecretBox(b"a" * 32).encrypt(b"secret")
        with pytest.raises(CryptoError):
            SecretBox(b"b" * 32).decrypt(payload)

    def test_aad_is_bound_to_the_ciphertext(self):
        box = SecretBox(b"k" * 32)
        payload = box.encrypt(b"secret", aad=b"fingerprint-1")
        with pytest.raises(CryptoError):
            box.decrypt(payload, aad=b"fingerprint-2")

    def test_tampering_is_detected(self):
        box = SecretBox(b"k" * 32)
        version, nonce, blob = box.encrypt(b"secret").split(":")
        corrupted = bytearray(base64.b64decode(blob))
        corrupted[0] ^= 0xFF
        with pytest.raises(CryptoError):
            box.decrypt(f"{version}:{nonce}:{base64.b64encode(corrupted).decode()}")

    @pytest.mark.parametrize(
        "value", ["", "too-short", base64.b64encode(b"x" * 16).decode()]
    )
    def test_bad_master_keys_are_rejected(self, value):
        with pytest.raises(CryptoError):
            load_master_key(value)

    def test_hex_and_base64_master_keys_both_work(self):
        raw = b"z" * 32
        assert load_master_key(base64.b64encode(raw).decode()) == raw
        assert load_master_key(raw.hex()) == raw


class TestRedaction:
    def test_credential_headers_are_masked(self):
        cleaned, changed = redact_headers(
            {"Authorization": "Bearer abc", "Cookie": "s=1", "Accept": "*/*"}
        )
        assert changed is True
        assert cleaned["Authorization"] == "***REDACTED***"
        assert cleaned["Cookie"] == "***REDACTED***"
        assert cleaned["Accept"] == "*/*"  # untouched

    def test_ordinary_headers_report_no_change(self):
        _, changed = redact_headers({"Accept": "*/*", "Host": "example.com"})
        assert changed is False

    def test_nested_json_secrets(self):
        body = b'{"user":{"name":"amy","password":"hunter2"},"items":[{"token":"t"}]}'
        cleaned, changed = redact_body(body, "application/json")
        assert changed
        assert b"hunter2" not in cleaned
        assert b"amy" in cleaned  # only the sensitive keys go
        assert b'"t"' not in cleaned

    def test_form_encoded_secrets(self):
        cleaned, changed = redact_body(
            b"user=amy&password=hunter2", "application/x-www-form-urlencoded"
        )
        assert changed and b"hunter2" not in cleaned and b"amy" in cleaned

    def test_jwts_in_opaque_bodies(self):
        token = b"eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.abcdefghijk"
        cleaned, changed = redact_body(b"prefix " + token, "text/plain")
        assert changed and token not in cleaned

    def test_malformed_json_is_left_alone(self):
        body = b"{not valid json"
        assert redact_body(body, "application/json") == (body, False)

    def test_query_string_secrets(self):
        assert "sk-live" not in redact_url("/cb?code=xyz&api_key=sk-live-1&page=2")
        assert "page=2" in redact_url("/cb?code=xyz&api_key=sk-live-1&page=2")


class TestPKI:
    def test_generated_ca_is_a_usable_signing_ca(self):
        root = generate_root_ca(common_name="Unit Test CA", organization="Tests")
        parsed = parse_ca_bundle(root.cert_pem, root.key_pem)
        assert parsed.fingerprint_sha256 == root.fingerprint_sha256
        assert "Unit Test CA" in parsed.subject

    def test_leaf_covers_the_requested_host(self):
        from cryptography import x509

        from decrypt0rx_core.pki import CertificateForge

        root = generate_root_ca()
        chain = CertificateForge(root.cert_pem, root.key_pem).forge("api.example.com")
        leaf = x509.load_pem_x509_certificate(chain.encode())
        names = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.DNSName)
        assert "api.example.com" in names
        assert "*.example.com" in names  # so sibling subdomains reuse the cert

    def test_leaf_for_an_ip_literal(self):
        from cryptography import x509

        from decrypt0rx_core.pki import CertificateForge

        root = generate_root_ca()
        chain = CertificateForge(root.cert_pem, root.key_pem).forge("10.1.2.3")
        leaf = x509.load_pem_x509_certificate(chain.encode())
        ips = leaf.extensions.get_extension_for_class(
            x509.SubjectAlternativeName
        ).value.get_values_for_type(x509.IPAddress)
        assert str(ips[0]) == "10.1.2.3"

    def test_a_leaf_certificate_is_not_accepted_as_a_ca(self):
        from decrypt0rx_core.pki import CertificateForge

        root = generate_root_ca()
        forge = CertificateForge(root.cert_pem, root.key_pem)
        leaf_pem = forge.forge("example.com").split("-----BEGIN CERTIFICATE-----")[1]
        with pytest.raises(ValueError, match="not a CA"):
            parse_ca_bundle(
                "-----BEGIN CERTIFICATE-----" + leaf_pem, forge.leaf_key_pem
            )


class TestHTTPFraming:
    """The framing decisions are what keep the proxy byte-transparent."""

    def _headers(self, **kwargs):
        from decrypt0rx_proxy.http1 import Headers

        return Headers([(k.replace("_", "-"), v) for k, v in kwargs.items()])

    def test_content_length_framing(self):
        from decrypt0rx_proxy.http1 import body_framing

        assert body_framing(self._headers(Content_Length="42"), is_response=False) == (
            "length",
            42,
        )

    def test_chunked_wins_over_content_length(self):
        from decrypt0rx_proxy.http1 import body_framing

        headers = self._headers(Transfer_Encoding="chunked", Content_Length="42")
        assert body_framing(headers, is_response=False)[0] == "chunked"

    def test_204_and_304_have_no_body(self):
        from decrypt0rx_proxy.http1 import body_framing

        for status in (204, 304):
            assert body_framing(
                self._headers(Content_Length="10"), is_response=True, status=status
            ) == ("none", 0)

    def test_head_response_has_no_body(self):
        from decrypt0rx_proxy.http1 import body_framing

        assert body_framing(
            self._headers(Content_Length="500"),
            is_response=True,
            status=200,
            method="HEAD",
        ) == ("none", 0)

    def test_response_without_length_reads_to_eof(self):
        from decrypt0rx_proxy.http1 import body_framing

        assert body_framing(self._headers(), is_response=True, status=200) == ("eof", 0)

    def test_hop_by_hop_headers_are_stripped(self):
        from decrypt0rx_proxy.http1 import Headers

        headers = Headers(
            [
                ("Connection", "keep-alive, X-Custom"),
                ("X-Custom", "drop me"),
                ("Proxy-Connection", "keep-alive"),
                ("Accept", "*/*"),
            ]
        )
        headers.strip_hop_by_hop()
        names = {k.lower() for k, _ in headers.items}
        assert "x-custom" not in names
        assert "proxy-connection" not in names
        assert "accept" in names

    def test_chunked_body_is_forwarded_verbatim_and_captured_decoded(self):
        from decrypt0rx_proxy.http1 import pump_body

        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data(b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n")
            reader.feed_eof()

            written = bytearray()

            class Sink:
                def write(self, data):
                    written.extend(data)

                async def drain(self):
                    return None

            result = await pump_body(reader, Sink(), "chunked", 0, 1024)
            return result, bytes(written)

        result, forwarded = asyncio.run(run())
        assert result.captured == b"hello world"
        assert result.total == 11
        assert forwarded == b"5\r\nhello\r\n6\r\n world\r\n0\r\n\r\n"

    def test_capture_stops_at_the_limit_but_forwarding_does_not(self):
        from decrypt0rx_proxy.http1 import pump_body

        async def run():
            reader = asyncio.StreamReader()
            reader.feed_data(b"x" * 5000)
            reader.feed_eof()

            written = bytearray()

            class Sink:
                def write(self, data):
                    written.extend(data)

                async def drain(self):
                    return None

            result = await pump_body(reader, Sink(), "length", 5000, 100)
            return result, bytes(written)

        result, forwarded = asyncio.run(run())
        assert len(result.captured) == 100
        assert result.truncated is True
        assert result.total == 5000
        assert len(forwarded) == 5000  # the client still got everything

    def test_gzip_bodies_are_decoded_for_display(self):
        import gzip

        from decrypt0rx_proxy.http1 import decode_content

        assert decode_content(gzip.compress(b"readable"), "gzip") == b"readable"

    def test_truncated_gzip_falls_back_to_raw_bytes(self):
        import gzip

        from decrypt0rx_proxy.http1 import decode_content

        full = gzip.compress(bytes(range(256)) * 200)
        truncated = full[: len(full) // 2]
        assert decode_content(truncated, "gzip") == truncated

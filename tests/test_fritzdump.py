"""Unit tests for fritzdump.

Run from the project root with:

    python3 -m unittest discover -s tests

These cover the pure logic only (config, validation, the login challenge math,
interface parsing and the pcap redactor) — nothing here talks to a real box.
"""

from __future__ import annotations

import hashlib
import struct
import sys
import unittest
from pathlib import Path

# Import the script as a module without running its main().
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
import fritzdump as f  # noqa: E402


class SettingsTest(unittest.TestCase):
    def test_env_overrides_dotenv(self):
        settings = f.Settings({"FRITZ_HOST": "from-env-file"})
        self.assertEqual(settings.get("FRITZ_HOST"), "from-env-file")

    def test_missing_key_returns_default(self):
        settings = f.Settings({})
        self.assertIsNone(settings.get("NOPE"))
        self.assertEqual(settings.get("NOPE", "fallback"), "fallback")

    def test_bool_parsing(self):
        settings = f.Settings({"A": "true", "B": "0", "C": "YES", "D": "off"})
        self.assertTrue(settings.get_bool("A"))
        self.assertFalse(settings.get_bool("B"))
        self.assertTrue(settings.get_bool("C"))
        self.assertFalse(settings.get_bool("D"))
        self.assertTrue(settings.get_bool("MISSING", default=True))


class LoadDotenvTest(unittest.TestCase):
    def test_parses_comments_and_quotes(self):
        import tempfile
        with tempfile.NamedTemporaryFile("w", suffix=".env", delete=False) as fh:
            fh.write("# a comment\n")
            fh.write("FRITZ_USER = alice \n")
            fh.write('FRITZ_PW="se cret"\n')
            fh.write("BLANK\n")  # no '=', ignored
            path = fh.name
        values = f.load_dotenv(path)
        Path(path).unlink()
        self.assertEqual(values["FRITZ_USER"], "alice")
        self.assertEqual(values["FRITZ_PW"], "se cret")
        self.assertNotIn("BLANK", values)


class ValidationTest(unittest.TestCase):
    def test_valid_hosts(self):
        for host in ("192.168.178.1", "fritz.box", "fd00::1"):
            f.validate_host(host)  # must not raise

    def test_invalid_hosts(self):
        for host in ("a/b", "x@y", "host?q", "with#hash", "back\\slash"):
            with self.assertRaises(ValueError):
                f.validate_host(host)

    def _args(self, iface="1-lan", snaplen="", filt=""):
        import argparse
        return argparse.Namespace(iface=iface, snaplen=snaplen, filter=filt)

    def test_snaplen_bounds(self):
        f.validate_capture_args(self._args(snaplen="64"))
        f.validate_capture_args(self._args(snaplen="262144"))
        for bad in ("63", "262145", "abc"):
            with self.assertRaises(ValueError):
                f.validate_capture_args(self._args(snaplen=bad))

    def test_filter_whitelist(self):
        f.validate_capture_args(self._args(filt="host 1.2.3.4 and tcp port 443"))
        for bad in ("host `whoami`", "a; rm -rf /", "x$y", 'q"uote'):
            with self.assertRaises(ValueError):
                f.validate_capture_args(self._args(filt=bad))

    def test_bad_iface(self):
        with self.assertRaises(ValueError):
            f.validate_capture_args(self._args(iface="bad iface!"))


class ChallengeTest(unittest.TestCase):
    def test_pbkdf2_matches_reference(self):
        salt1, salt2 = b"\xab" * 8, b"\xcd" * 8
        challenge = f"2$1000${salt1.hex()}$2000${salt2.hex()}"
        hash1 = hashlib.pbkdf2_hmac("sha256", b"secret", salt1, 1000)
        hash2 = hashlib.pbkdf2_hmac("sha256", hash1, salt2, 2000)
        self.assertEqual(
            f.solve_challenge(challenge, "secret"),
            f"{salt2.hex()}${hash2.hex()}",
        )

    def test_pbkdf2_rejects_excessive_iterations(self):
        challenge = f"2$9999999${'ab' * 8}$9999999${'cd' * 8}"
        with self.assertRaises(RuntimeError):
            f.solve_challenge(challenge, "pw")

    def test_legacy_refused_by_default(self):
        with self.assertRaises(RuntimeError) as ctx:
            f.solve_challenge("abc123", "pw")
        self.assertIn("legacy", str(ctx.exception).lower())

    def test_legacy_md5_when_allowed(self):
        raw = "abc123-pw".encode("utf-16-le")
        self.assertEqual(
            f.solve_challenge("abc123", "pw", allow_legacy=True),
            "abc123-" + hashlib.md5(raw).hexdigest(),
        )

    def test_bad_formats_rejected(self):
        with self.assertRaises(RuntimeError):
            f.solve_challenge("2$bad", "pw")
        with self.assertRaises(RuntimeError):
            f.solve_challenge("has space", "pw", allow_legacy=True)


class InterfaceParsingTest(unittest.TestCase):
    def test_json_snapshot(self):
        raw = (
            '{"data":{"snapshot":{"interfaces":['
            '{"name":"1-lan","kind":"LAN","displayname":"LAN Bridge"},'
            '{"id":"2-1","description":"WAN"},'
            '"junk",'
            '{"ifaceorminor":"4-133"}]}}}'
        )
        self.assertEqual(
            list(f._interfaces_from_json(raw)),
            [("1-lan", "LAN LAN Bridge"), ("2-1", "WAN"), ("4-133", "")],
        )

    def test_json_invalid_yields_nothing(self):
        self.assertEqual(list(f._interfaces_from_json("not json")), [])

    def test_html_buttons(self):
        raw = (
            "<table><tr><th>Wi-Fi 5 GHz</th>"
            '<td><button name="start" value="4-133">go</button></td></tr></table>'
        )
        self.assertEqual(list(f._interfaces_from_buttons(raw)), [("4-133", "Wi-Fi 5 GHz")])

    def test_url_fallback(self):
        raw = "some label ifaceorminor=4-135&more"
        ids = [iid for iid, _ in f._interfaces_from_urls(raw)]
        self.assertEqual(ids, ["4-135"])

    def test_clean_label_strips_html(self):
        self.assertEqual(f._clean_label("<b>Hello   world</b> &amp; more"), "Hello world & more")


class SafeCapturePathTest(unittest.TestCase):
    def test_allows_path_in_dumps(self):
        resolved = f.safe_capture_path("dumps/test.pcap")
        self.assertTrue(str(resolved).endswith("/dumps/test.pcap"))

    def test_rejects_outside_project(self):
        with self.assertRaises(ValueError):
            f.safe_capture_path("/etc/passwd")

    def test_rejects_bad_extension(self):
        with self.assertRaises(ValueError):
            f.safe_capture_path("dumps/test.txt")

    def test_rejects_hidden_file(self):
        with self.assertRaises(ValueError):
            f.safe_capture_path("dumps/.secret.pcap")


class PcapRedactorTest(unittest.TestCase):
    def _modified_pcap_with_tcp_payload(self):
        """A single Ethernet/IPv4/TCP frame in the box's 'modified' pcap format."""
        magic = b"\xa1\xb2\xcd\x34"
        # version(2.4), thiszone, sigfigs, snaplen, linktype=1 (Ethernet)
        global_hdr = magic + struct.pack(">HHiIII", 2, 4, 0, 0, 65535, 1)
        eth = bytes.fromhex("aabbccddeeff112233445566") + b"\x08\x00"
        ip = bytes([0x45, 0, 0, 0, 0, 0, 0, 0, 64, 6, 0, 0]) + bytes([192, 168, 0, 1]) + bytes([8, 8, 8, 8])
        tcp = bytes([0, 80, 0, 80, 0, 0, 0, 0, 0, 0, 0, 0, 0x50, 0x02, 0, 0, 0, 0, 0, 0])
        payload = b"SECRET-PASSWORD-DATA"
        frame = eth + ip + tcp + payload
        # modified record header = standard 16 bytes + 8 extra (ifindex/pkttype/pad)
        rec_hdr = struct.pack(">IIII", 111, 222, len(frame), len(frame)) + b"\x00" * 8
        return global_hdr + rec_hdr + frame, len(frame), len(eth) + len(ip) + len(tcp)

    def test_redacts_payload_across_chunks(self):
        stream, orig_len, header_len = self._modified_pcap_with_tcp_payload()
        out = bytearray()
        redactor = f.PcapRedactor(out.extend)
        # feed in deliberately misaligned 7-byte chunks
        for i in range(0, len(stream), 7):
            redactor.feed(stream[i:i + 7])

        # modified magic normalized to standard us magic
        self.assertEqual(bytes(out[:4]), b"\xa1\xb2\xc3\xd4")
        incl, orig = struct.unpack(">II", out[24 + 8:24 + 16])
        self.assertEqual(orig, orig_len)        # original length preserved
        self.assertEqual(incl, header_len)      # only L2-L4 headers kept
        self.assertNotIn(b"SECRET", bytes(out))  # payload dropped

    def test_standard_magic_passes_through(self):
        global_hdr = b"\xa1\xb2\xc3\xd4" + struct.pack(">HHiIII", 2, 4, 0, 0, 65535, 1)
        out = bytearray()
        f.PcapRedactor(out.extend).feed(global_hdr)
        self.assertEqual(bytes(out[:4]), b"\xa1\xb2\xc3\xd4")

    def test_bad_magic_raises(self):
        out = bytearray()
        with self.assertRaises(RuntimeError):
            f.PcapRedactor(out.extend).feed(b"\x00\x00\x00\x00" + b"\x00" * 20)

    def test_oversized_record_raises(self):
        global_hdr = b"\xa1\xb2\xc3\xd4" + struct.pack(">HHiIII", 2, 4, 0, 0, 65535, 1)
        huge = f.MAX_CAPTURE_RECORD + 1
        rec_hdr = struct.pack(">IIII", 0, 0, huge, huge)
        out = bytearray()
        with self.assertRaises(RuntimeError):
            f.PcapRedactor(out.extend).feed(global_hdr + rec_hdr)


if __name__ == "__main__":
    unittest.main()
